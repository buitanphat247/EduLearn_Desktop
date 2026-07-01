"use strict";

const crypto = require("crypto");

const IPC_FRAME_VERSION = 1;
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
  return {
    version: frame.version,
    kind: frame.kind,
    nonce: frame.nonce,
    timestampMs: frame.timestampMs,
    payload: frame.payload,
  };
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

function createFrameVerifier({
  expectedKind,
  secret,
  now = Date.now,
  maxClockSkewMs = IPC_MAX_CLOCK_SKEW_MS,
} = {}) {
  const seenNonces = new Map();

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
    if (frame.version !== IPC_FRAME_VERSION || frame.kind !== expectedKind) {
      throw new Error("IPC frame version or kind is invalid.");
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
    seenNonces.set(frame.nonce, frame.timestampMs);
    prune(currentTime);
    return frame.payload;
  };
}

module.exports = {
  IPC_FRAME_VERSION,
  canonicalize,
  computeMac,
  createAuthenticatedFrame,
  createFrameVerifier,
};
