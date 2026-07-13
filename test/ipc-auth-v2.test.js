"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  IPC_FRAME_VERSION_V2,
  computeMac,
  createSequencedFrameFactory,
  createFrameVerifier,
} = require("../src/ipc-auth");

const SECRET = Buffer.alloc(32, 9);

function v2Frame({ kind = "request", payload = {}, nonce, timestampMs = Date.now(), sequence }) {
  const frame = { version: IPC_FRAME_VERSION_V2, kind, nonce, timestampMs, sequence, payload, mac: "" };
  frame.mac = computeMac(frame, SECRET);
  return frame;
}

test("F-015 v2: sequenced factory emits monotonically increasing frames", () => {
  const factory = createSequencedFrameFactory({ secret: SECRET });
  const a = factory.create({ kind: "request", payload: { cmd: "heartbeat" } });
  const b = factory.create({ kind: "request", payload: { cmd: "heartbeat" } });
  assert.equal(a.version, IPC_FRAME_VERSION_V2);
  assert.ok(Number.isInteger(a.sequence) && b.sequence > a.sequence);
});

test("F-015 v2: verifier accepts increasing sequence, rejects non-increasing (fresh nonce)", () => {
  const verify = createFrameVerifier({ expectedKind: "request", secret: SECRET });
  const a = v2Frame({ nonce: "nonce-aaaaaaaaaaaa", sequence: 5 });
  const b = v2Frame({ nonce: "nonce-bbbbbbbbbbbb", sequence: 6 });
  assert.doesNotThrow(() => verify(a));
  assert.doesNotThrow(() => verify(b));
  // Same sequence but a FRESH nonce (so not a replay) must still be rejected.
  const stale = v2Frame({ nonce: "nonce-cccccccccccc", sequence: 6 });
  assert.throws(() => verify(stale), /sequence did not increase/);
});

test("F-015 v2: replayed nonce rejected", () => {
  const verify = createFrameVerifier({ expectedKind: "request", secret: SECRET });
  const a = v2Frame({ nonce: "nonce-dddddddddddd", sequence: 1 });
  assert.doesNotThrow(() => verify(a));
  assert.throws(() => verify(a), /replayed/);
});

test("F-015 v2: missing sequence rejected; v1 carrying a sequence rejected", () => {
  const verify = createFrameVerifier({ expectedKind: "request", secret: SECRET });
  // v2 with no sequence: rejected at the version/sequence check, BEFORE the MAC
  // step (so a dummy mac is fine — a real client never builds such a frame).
  const noSeq = { version: IPC_FRAME_VERSION_V2, kind: "request", nonce: "nonce-eeeeeeeeeeee", timestampMs: Date.now(), payload: {}, mac: "AAAA" };
  assert.throws(() => verify(noSeq), /missing its sequence/);
  // v1 with a sequence
  const v1seq = { version: 1, kind: "request", nonce: "nonce-ffffffffffff", timestampMs: Date.now(), sequence: 3, payload: {}, mac: "" };
  v1seq.mac = computeMac(v1seq, SECRET);
  assert.throws(() => verify(v1seq), /must not carry a sequence/);
});

test("F-015 v2: tampered payload fails the MAC", () => {
  const verify = createFrameVerifier({ expectedKind: "request", secret: SECRET });
  const f = v2Frame({ nonce: "nonce-gggggggggggg", sequence: 1, payload: { cmd: "ping" } });
  f.payload = { cmd: "shutdown" }; // change after signing
  assert.throws(() => verify(f), /MAC verification failed/);
});

// P47-01 activation: what rust-sidecar now emits (a sequenced v2 frame from
// createSequencedFrameFactory) is accepted by the verifier, and a
// reordered/rolled-back/duplicate frame is rejected — end-to-end at the wire level.
test("P47-01: factory-emitted v2 frames round-trip; reorder / rollback / duplicate rejected", () => {
  const factory = createSequencedFrameFactory({ secret: SECRET });
  const verify = createFrameVerifier({ expectedKind: "request", secret: SECRET });

  const toRequest = (frame) => {
    const req = { ...frame, kind: "request" };
    req.mac = computeMac(req, SECRET);
    return req;
  };

  const r1 = toRequest(factory.create({ kind: "request", payload: { cmd: "ping" } }));
  const r2 = toRequest(factory.create({ kind: "request", payload: { cmd: "heartbeat" } }));
  assert.ok(r2.sequence > r1.sequence); // monotonic on the wire
  assert.doesNotThrow(() => verify(r1));
  assert.doesNotThrow(() => verify(r2));

  // Duplicate (replay the exact frame) -> rejected.
  assert.throws(() => verify(r2), /replayed|did not increase/);

  // Rollback (a validly-MAC'd frame with an OLD sequence + fresh nonce) -> rejected.
  const rollback = v2Frame({ nonce: "nonce-rollback-1234", sequence: r1.sequence });
  assert.throws(() => verify(rollback), /did not increase/);
});
