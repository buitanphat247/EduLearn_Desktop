"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

// P47-03: prime an electron stub in the require cache BEFORE loading the launcher
// (it transitively requires electron's `app`/`session`). The launcher functions
// under test — buildExamShellLaunchSpec + fetchSignedAllowlist — do not exercise
// the real Electron APIs, so a minimal stub is enough.
const electronPath = require.resolve("electron");
require.cache[electronPath] = {
  id: electronPath,
  filename: electronPath,
  loaded: true,
  exports: {
    app: {
      getPath: () => "C:\\tmp\\edulearn-userdata",
      getAppPath: () => "C:\\tmp\\edulearn-app",
    },
    session: {},
  },
};

const {
  resolveSignedAllowlistFromEnv,
} = require("../src/protection/signed-allowlist-source");
const {
  buildExamShellLaunchSpec,
  fetchSignedAllowlist,
} = require("../src/exam-desktop-launcher");
const { canonicalize } = require("../src/ipc-auth");
const { installUrlFilter } = require("../src/protection/url-filter");

// --- helpers ---------------------------------------------------------------

function makeSignedBlob(payload, keyId = "policy-k1") {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" });
  const rawB64 = spki.subarray(spki.length - 32).toString("base64");
  const signature = crypto
    .sign(null, Buffer.from(canonicalize(payload), "utf8"), privateKey)
    .toString("base64");
  return { blob: { payload, keyId, signature }, trusted: { [keyId]: rawB64 } };
}

function mockWin() {
  const h = {};
  const win = {
    webContents: {
      session: {
        webRequest: {
          onBeforeRequest: (fn) => (h.onBeforeRequest = fn),
          onHeadersReceived: (fn) => (h.onHeadersReceived = fn),
        },
      },
      setWindowOpenHandler: (fn) => (h.windowOpen = fn),
      on: (ev, fn) => (h[ev] = fn),
    },
  };
  return { win, h };
}

// --- resolveSignedAllowlistFromEnv (window.js's source) --------------------

test("P47-03 resolver: parses a valid blob, rejects missing/malformed ones", () => {
  const blob = { payload: { hosts: ["cdn.exam.edu"] }, keyId: "k", signature: "s" };
  assert.deepEqual(
    resolveSignedAllowlistFromEnv({ EDULEARN_SIGNED_ALLOWLIST_JSON: JSON.stringify(blob) }),
    blob,
  );
  assert.equal(resolveSignedAllowlistFromEnv({}), null); // absent
  assert.equal(resolveSignedAllowlistFromEnv({ EDULEARN_SIGNED_ALLOWLIST_JSON: "{not json" }), null);
  // A well-formed JSON that is not a signed-blob shape is refused.
  assert.equal(
    resolveSignedAllowlistFromEnv({ EDULEARN_SIGNED_ALLOWLIST_JSON: JSON.stringify({ hosts: ["x"] }) }),
    null,
  );
});

// --- buildExamShellLaunchSpec (launcher bakes the blob into shell env) ------

test("P47-03 launcher: bakes the signed blob into EDULEARN_SIGNED_ALLOWLIST_JSON", () => {
  const blob = { payload: { hosts: ["cdn.exam.edu"] }, keyId: "k", signature: "s" };
  const spec = buildExamShellLaunchSpec({
    roomUrl: "https://exam.edu/room",
    sessionId: "sess-1",
    examCode: "exam-1",
    signedAllowlist: blob,
  });
  assert.equal(spec.env.EDULEARN_SIGNED_ALLOWLIST_JSON, JSON.stringify(blob));
  // A pre-serialized string is passed through unchanged.
  const spec2 = buildExamShellLaunchSpec({
    roomUrl: "https://exam.edu/room",
    signedAllowlist: JSON.stringify(blob),
  });
  assert.equal(spec2.env.EDULEARN_SIGNED_ALLOWLIST_JSON, JSON.stringify(blob));
  // No blob -> the env var is absent (shell falls back to env-derived hosts).
  const spec3 = buildExamShellLaunchSpec({ roomUrl: "https://exam.edu/room" });
  assert.equal("EDULEARN_SIGNED_ALLOWLIST_JSON" in spec3.env, false);
});

// --- fetchSignedAllowlist (main-side, best-effort) --------------------------

test("P47-03 fetch: returns the blob on 200, null on error/missing config", async () => {
  const blob = { payload: { hosts: ["cdn.exam.edu"] }, keyId: "k", signature: "s" };
  const okFetch = async (url) => {
    assert.match(url, /\/exam-security\/policies\/exam-1\/url-allowlist$/);
    return { ok: true, json: async () => blob };
  };
  assert.deepEqual(
    await fetchSignedAllowlist({ examCode: "exam-1", apiBase: "https://api.exam.edu/", fetchImpl: okFetch }),
    blob,
  );
  // Non-2xx -> null.
  assert.equal(
    await fetchSignedAllowlist({
      examCode: "exam-1",
      apiBase: "https://api.exam.edu",
      fetchImpl: async () => ({ ok: false }),
    }),
    null,
  );
  // Thrown error -> null (never blocks entry).
  assert.equal(
    await fetchSignedAllowlist({
      examCode: "exam-1",
      apiBase: "https://api.exam.edu",
      fetchImpl: async () => {
        throw new Error("network down");
      },
    }),
    null,
  );
  // Missing examCode or apiBase -> null without calling fetch.
  assert.equal(await fetchSignedAllowlist({ apiBase: "https://api.exam.edu", fetchImpl: okFetch }), null);
  assert.equal(await fetchSignedAllowlist({ examCode: "exam-1", apiBase: "", fetchImpl: okFetch }), null);
});

// --- full chain: env -> resolver -> installUrlFilter (window.js's exact path) -

test("P47-03 end-to-end: a server-signed blob widens the host set; a tampered one is refused", () => {
  const payload = { examId: "exam-1", hosts: ["extra-cdn.net"], expiresAtMs: Date.now() + 60_000 };
  const { blob, trusted } = makeSignedBlob(payload);

  // Valid: env -> resolver -> installUrlFilter -> the signed host is reachable.
  const env = { EDULEARN_SIGNED_ALLOWLIST_JSON: JSON.stringify(blob) };
  const { win, h } = mockWin();
  const result = installUrlFilter(win, {
    startUrl: "https://exam.edu/room",
    extraHosts: [],
    mode: "enforce",
    signedAllowlist: resolveSignedAllowlistFromEnv(env),
    trustedKeys: trusted,
  });
  assert.equal(result.signedAllowlistStatus, "verified");
  let cb = null;
  h.onBeforeRequest({ url: "https://extra-cdn.net/lib.js" }, (x) => (cb = x));
  assert.deepEqual(cb, {}, "signed host allowed");

  // Tampered: flip a host in the signed payload -> refused, host stays blocked.
  const tamperedBlob = { ...blob, payload: { ...payload, hosts: ["extra-cdn.net", "evil.com"] } };
  const tamperedEnv = { EDULEARN_SIGNED_ALLOWLIST_JSON: JSON.stringify(tamperedBlob) };
  const { win: win2, h: h2 } = mockWin();
  const result2 = installUrlFilter(win2, {
    startUrl: "https://exam.edu/room",
    extraHosts: [],
    mode: "enforce",
    signedAllowlist: resolveSignedAllowlistFromEnv(tamperedEnv),
    trustedKeys: trusted,
  });
  assert.match(result2.signedAllowlistStatus, /^rejected:/);
  let cb2 = null;
  h2.onBeforeRequest({ url: "https://evil.com/x" }, (x) => (cb2 = x));
  assert.deepEqual(cb2, { cancel: true }, "tampered host blocked");
});
