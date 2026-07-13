const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const {
  resolveLoggerBaseDir,
  redactSensitive,
  isSensitiveKey,
} = require("../src/logger");

test("resolveLoggerBaseDir prefers Electron userData", () => {
  const fakeApp = {
    getPath(name) {
      return name === "userData"
        ? "C:\\Users\\Admin\\AppData\\Roaming\\Edulearn"
        : "";
    },
    isDestroyed() {
      return false;
    },
  };

  assert.equal(
    resolveLoggerBaseDir(fakeApp),
    "C:\\Users\\Admin\\AppData\\Roaming\\Edulearn",
  );
});

test("resolveLoggerBaseDir falls back to the desktop app root", () => {
  const fakeApp = {
    getPath() {
      throw new Error("userData unavailable");
    },
    isDestroyed() {
      return false;
    },
  };

  assert.equal(resolveLoggerBaseDir(fakeApp), path.resolve(__dirname, ".."));
});

test("isSensitiveKey flags auth/secret/token/cookie keys, not benign ones", () => {
  for (const k of ["password", "exitPassword", "authToken", "_at", "_rt", "_csrf", "IPC_SECRET", "clipboardText", "Authorization", "apiKey"]) {
    assert.equal(isSensitiveKey(k), true, `${k} should be sensitive`);
  }
  for (const k of ["createdAt", "updatedAt", "lastAccessAt", "username", "sessionId", "eventId"]) {
    assert.equal(isSensitiveKey(k), false, `${k} should NOT be sensitive`);
  }
});

test("redactSensitive removes secrets recursively but keeps structure", () => {
  const input = {
    user: "alice",
    // non-sensitive parent key → nested cookie-name keys redacted individually
    handoff: { _at: "eyJhbGciOi...", _rt: "refresh...", _csrf: "csrf..." },
    // sensitive parent key ("cookie") → whole subtree redacted wholesale
    cookies: { _at: "eyJhbGciOi...", other: "x" },
    ipc: { EDULEARN_CORE_IPC_SECRET: "abc123", parentPid: 42 },
    events: [{ type: "copy", clipboard: "leaked answer text" }],
    exitPassword: "hunter2",
    nested: { deep: { token: "bearer xyz", ok: "keep-me" } },
    createdAt: "2026-07-11T00:00:00Z",
  };
  const out = redactSensitive(input);

  assert.equal(out.user, "alice");
  assert.equal(out.handoff._at, "[REDACTED]");
  assert.equal(out.handoff._rt, "[REDACTED]");
  assert.equal(out.handoff._csrf, "[REDACTED]");
  assert.equal(out.cookies, "[REDACTED]"); // whole subtree gone
  assert.equal(out.ipc.EDULEARN_CORE_IPC_SECRET, "[REDACTED]");
  assert.equal(out.ipc.parentPid, 42);
  assert.equal(out.events[0].clipboard, "[REDACTED]");
  assert.equal(out.events[0].type, "copy");
  assert.equal(out.exitPassword, "[REDACTED]");
  assert.equal(out.nested.deep.token, "[REDACTED]");
  assert.equal(out.nested.deep.ok, "keep-me");
  assert.equal(out.createdAt, "2026-07-11T00:00:00Z");

  // no secret value survives anywhere in the serialized form
  const serialized = JSON.stringify(out);
  assert.ok(!serialized.includes("eyJhbGciOi"));
  assert.ok(!serialized.includes("leaked answer text"));
  assert.ok(!serialized.includes("hunter2"));
});

test("redactSensitive tolerates cycles and primitives", () => {
  const a = { name: "x" };
  a.self = a;
  const out = redactSensitive(a);
  assert.equal(out.name, "x");
  assert.equal(out.self, "[Circular]");
  assert.equal(redactSensitive(null), null);
  assert.equal(redactSensitive(5), 5);
  assert.equal(redactSensitive("s"), "s");
});
