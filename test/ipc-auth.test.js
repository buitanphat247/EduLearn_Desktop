const test = require("node:test");
const assert = require("node:assert/strict");

const {
  canonicalize,
  createAuthenticatedFrame,
  createFrameVerifier,
} = require("../src/ipc-auth");

test("IPC canonical JSON sorts nested object keys deterministically", () => {
  assert.equal(
    canonicalize({ z: 1, a: { y: true, b: "value" } }),
    '{"a":{"b":"value","y":true},"z":1}',
  );
});

test("authenticated IPC accepts a valid frame and rejects replay", () => {
  const secret = Buffer.alloc(32, 7);
  const frame = createAuthenticatedFrame({
    kind: "response",
    payload: { requestId: "req-1", ok: true },
    secret,
    now: () => 10_000,
    nonce: "nonce-1234567890",
  });
  const verify = createFrameVerifier({
    expectedKind: "response",
    secret,
    now: () => 10_001,
  });

  assert.deepEqual(verify(frame), { requestId: "req-1", ok: true });
  assert.throws(() => verify(frame), /replayed/);
});

test("authenticated IPC rejects payload tampering and stale frames", () => {
  const secret = Buffer.alloc(32, 9);
  const frame = createAuthenticatedFrame({
    kind: "response",
    payload: { ok: true },
    secret,
    now: () => 10_000,
    nonce: "nonce-1234567890",
  });
  const verify = createFrameVerifier({
    expectedKind: "response",
    secret,
    now: () => 50_001,
  });
  assert.throws(() => verify(frame), /timestamp/);

  const freshVerify = createFrameVerifier({
    expectedKind: "response",
    secret,
    now: () => 10_001,
  });
  frame.payload.ok = false;
  assert.throws(() => freshVerify(frame), /MAC/);
});
