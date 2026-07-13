"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const { canonicalize } = require("../src/ipc-auth");
const { verifySignedAllowlist, installUrlFilter } = require("../src/protection/url-filter");

function makeSigned(payload, keyId = "policy-k1") {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" });
  const rawB64 = spki.subarray(spki.length - 32).toString("base64"); // raw 32-byte pubkey
  const signature = crypto
    .sign(null, Buffer.from(canonicalize(payload), "utf8"), privateKey)
    .toString("base64");
  return { signed: { payload, keyId, signature }, trusted: { [keyId]: rawB64 } };
}

test("F-006 signed allowlist: a genuinely signed blob verifies and yields its hosts", () => {
  const payload = { hosts: ["exam.edu", "cdn.exam.edu"], version: "v1", expiresAtMs: Date.now() + 60_000 };
  const { signed, trusted } = makeSigned(payload);
  const v = verifySignedAllowlist(signed, trusted);
  assert.equal(v.ok, true);
  assert.deepEqual(v.hosts, ["exam.edu", "cdn.exam.edu"]);
});

test("F-006 signed allowlist: tampered / wrong-key / expired / unknown-key all rejected", () => {
  const payload = { hosts: ["exam.edu"], expiresAtMs: Date.now() + 60_000 };
  const { signed, trusted } = makeSigned(payload);

  const tampered = { ...signed, payload: { ...payload, hosts: ["exam.edu", "evil.com"] } };
  assert.equal(verifySignedAllowlist(tampered, trusted).ok, false);

  const other = makeSigned(payload);
  assert.equal(verifySignedAllowlist(signed, other.trusted).ok, false); // wrong key

  const exp = makeSigned({ hosts: ["exam.edu"], expiresAtMs: Date.now() - 1 });
  assert.equal(verifySignedAllowlist(exp.signed, exp.trusted).reason, "expired");

  assert.equal(verifySignedAllowlist(signed, {}).reason, "unknown keyId");
  assert.equal(verifySignedAllowlist(null, trusted).reason, "malformed");
});

// --- installUrlFilter enforcement + telemetry (mock BrowserWindow) ----------
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

test("F-006 enforce: allowed loads, external request cancelled, popup denied, nav prevented + telemetry", () => {
  const { win, h } = mockWin();
  const result = installUrlFilter(win, {
    startUrl: "https://exam.edu/room",
    extraHosts: [],
    mode: "enforce",
  });

  // Allowed request -> not cancelled.
  let cb = null;
  h.onBeforeRequest({ url: "https://exam.edu/app.js" }, (x) => (cb = x));
  assert.deepEqual(cb, {});
  // Disallowed request -> cancelled.
  h.onBeforeRequest({ url: "https://evil.com/x" }, (x) => (cb = x));
  assert.deepEqual(cb, { cancel: true });

  // Disallowed popup -> denied.
  assert.deepEqual(h.windowOpen({ url: "https://evil.com" }), { action: "deny" });

  // External navigation -> preventDefault called.
  let prevented = false;
  h["will-navigate"]({ preventDefault: () => (prevented = true) }, "https://evil.com/x");
  assert.equal(prevented, true);

  // Non-http protocol navigation -> also blocked.
  prevented = false;
  h["will-navigate"]({ preventDefault: () => (prevented = true) }, "file:///etc/passwd");
  assert.equal(prevented, true);

  assert.equal(result.enforcing, true);
  assert.ok(result.telemetry.blocked >= 3);
  assert.equal(result.telemetry.byKind["window-open"], 1);
  assert.equal(result.telemetry.byKind["navigate"], 2);
});

test("F-006 report mode: nothing is cancelled/prevented but everything is counted", () => {
  const { win, h } = mockWin();
  const result = installUrlFilter(win, { startUrl: "https://exam.edu/room", extraHosts: [], mode: "report" });
  let cb = null;
  h.onBeforeRequest({ url: "https://evil.com/x" }, (x) => (cb = x));
  assert.deepEqual(cb, {}); // NOT cancelled in report mode
  assert.deepEqual(h.windowOpen({ url: "https://evil.com" }), { action: "allow" });
  let prevented = false;
  h["will-navigate"]({ preventDefault: () => (prevented = true) }, "https://evil.com/x");
  assert.equal(prevented, false); // NOT prevented in report mode
  assert.equal(result.telemetry.flagged, 3);
  assert.equal(result.telemetry.blocked, 0);
});

test("F-006 installUrlFilter folds in a verified signed allowlist", () => {
  const payload = { hosts: ["extra-cdn.net"], expiresAtMs: Date.now() + 60_000 };
  const { signed, trusted } = makeSigned(payload);
  const { win, h } = mockWin();
  const result = installUrlFilter(win, {
    startUrl: "https://exam.edu/room",
    extraHosts: [],
    mode: "enforce",
    signedAllowlist: signed,
    trustedKeys: trusted,
  });
  assert.equal(result.signedAllowlistStatus, "verified");
  // A request to the signed host is now allowed.
  let cb = null;
  h.onBeforeRequest({ url: "https://extra-cdn.net/lib.js" }, (x) => (cb = x));
  assert.deepEqual(cb, {});
});

test("F-006 installUrlFilter refuses an invalid signed allowlist (does not widen hosts)", () => {
  const payload = { hosts: ["extra-cdn.net"], expiresAtMs: Date.now() + 60_000 };
  const { signed } = makeSigned(payload);
  const { win, h } = mockWin();
  const result = installUrlFilter(win, {
    startUrl: "https://exam.edu/room",
    extraHosts: [],
    mode: "enforce",
    signedAllowlist: signed,
    trustedKeys: {}, // no trusted key -> rejected
  });
  assert.match(result.signedAllowlistStatus, /^rejected:/);
  let cb = null;
  h.onBeforeRequest({ url: "https://extra-cdn.net/lib.js" }, (x) => (cb = x));
  assert.deepEqual(cb, { cancel: true }); // still blocked
});
