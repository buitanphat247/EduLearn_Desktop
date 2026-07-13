"use strict";

const crypto = require("crypto");

const IPC_FRAME_VERSION = 1;
// F-015: v2 adds a REQUIRED monotonic `sequence` bound into the MAC. The Rust
// core (ipc_auth.rs `MacContentV2`) verifies it; v1 stays accepted for compat.
const IPC_FRAME_VERSION_V2 = 2;
const IPC_MAX_CLOCK_SKEW_MS = 30_000;
const IPC_MAX_REPLAY_ENTRIES = 4096;

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("IPC canonical JSON does not support non-finite numbers.");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  throw new TypeError(`IPC canonical JSON does not support ${typeof value}.`);
}

function macContent(frame) {
  const content = {
    version: frame.version,
    kind: frame.kind,
    nonce: frame.nonce,
    timestampMs: frame.timestampMs,
    payload: frame.payload,
  };
  // v2 binds the monotonic sequence into the MAC (matches Rust MacContentV2).
  if (frame.version === IPC_FRAME_VERSION_V2) {
    content.sequence = frame.sequence;
  }
  return content;
}

function computeMac(frame, secret) {
  return crypto
    .createHmac("sha256", secret)
    .update(canonicalize(macContent(frame)))
    .digest("base64url");
}

function createAuthenticatedFrame({
  kind,
  payload,
  secret,
  now = Date.now,
  nonce = crypto.randomBytes(18).toString("base64url"),
}) {
  if (!Buffer.isBuffer(secret) || secret.length < 32) {
    throw new TypeError("IPC authentication secret must contain at least 32 bytes.");
  }
  const frame = {
    version: IPC_FRAME_VERSION,
    kind,
    nonce,
    timestampMs: now(),
    payload,
    mac: "",
  };
  frame.mac = computeMac(frame, secret);
  return frame;
}

/**
 * F-015: a factory that emits v2 frames carrying a per-connection MONOTONIC
 * sequence (each `create` increments it). The Rust core rejects a v2 frame whose
 * sequence does not strictly increase, defeating reordering/replay-with-new-nonce.
 */
function createSequencedFrameFactory({
  secret,
  now = Date.now,
  startSequence = 0,
} = {}) {
  if (!Buffer.isBuffer(secret) || secret.length < 32) {
    throw new TypeError("IPC authentication secret must contain at least 32 bytes.");
  }
  let sequence = startSequence;
  return {
    create({ kind, payload, nonce = crypto.randomBytes(18).toString("base64url") }) {
      sequence += 1;
      const frame = {
        version: IPC_FRAME_VERSION_V2,
        kind,
        nonce,
        timestampMs: now(),
        sequence,
        payload,
        mac: "",
      };
      frame.mac = computeMac(frame, secret);
      return frame;
    },
    get sequence() {
      return sequence;
    },
  };
}

function createFrameVerifier({
  expectedKind,
  secret,
  now = Date.now,
  maxClockSkewMs = IPC_MAX_CLOCK_SKEW_MS,
} = {}) {
  const seenNonces = new Map();
  let lastSequence = null;

  function prune(currentTime) {
    for (const [nonce, timestamp] of seenNonces) {
      if (currentTime - timestamp > maxClockSkewMs) {
        seenNonces.delete(nonce);
      }
    }
    while (seenNonces.size > IPC_MAX_REPLAY_ENTRIES) {
      const oldest = [...seenNonces.entries()].sort((left, right) => left[1] - right[1])[0];
      seenNonces.delete(oldest[0]);
    }
  }

  return function verifyFrame(frame) {
    if (!frame || typeof frame !== "object") {
      throw new Error("IPC frame must be an object.");
    }
    const isV2 = frame.version === IPC_FRAME_VERSION_V2;
    if (
      (frame.version !== IPC_FRAME_VERSION && frame.version !== IPC_FRAME_VERSION_V2) ||
      frame.kind !== expectedKind
    ) {
      throw new Error("IPC frame version or kind is invalid.");
    }
    if (isV2 && (typeof frame.sequence !== "number" || !Number.isInteger(frame.sequence))) {
      throw new Error("IPC v2 frame is missing its sequence.");
    }
    if (!isV2 && frame.sequence !== undefined) {
      throw new Error("IPC v1 frame must not carry a sequence.");
    }
    if (typeof frame.nonce !== "string" || frame.nonce.length < 16 || frame.nonce.length > 128) {
      throw new Error("IPC frame nonce length is invalid.");
    }
    const currentTime = now();
    if (
      typeof frame.timestampMs !== "number" ||
      frame.timestampMs > currentTime + maxClockSkewMs ||
      currentTime - frame.timestampMs > maxClockSkewMs
    ) {
      throw new Error("IPC frame timestamp is outside the accepted window.");
    }
    if (seenNonces.has(frame.nonce)) {
      throw new Error("IPC frame nonce was replayed.");
    }
    if (typeof frame.mac !== "string") {
      throw new Error("IPC frame MAC is missing.");
    }
    const expected = Buffer.from(computeMac(frame, secret), "base64url");
    const supplied = Buffer.from(frame.mac, "base64url");
    if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) {
      throw new Error("IPC frame MAC verification failed.");
    }
    // v2: enforce strictly-increasing sequence AFTER authenticating the frame.
    if (isV2) {
      if (lastSequence !== null && frame.sequence <= lastSequence) {
        throw new Error("IPC v2 sequence did not increase.");
      }
      lastSequence = frame.sequence;
    }
    seenNonces.set(frame.nonce, frame.timestampMs);
    prune(currentTime);
    return frame.payload;
  };
}

module.exports = {
  IPC_FRAME_VERSION,
  IPC_FRAME_VERSION_V2,
  canonicalize,
  computeMac,
  createAuthenticatedFrame,
  createSequencedFrameFactory,
  createFrameVerifier,
};
