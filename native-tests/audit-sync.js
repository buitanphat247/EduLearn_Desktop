"use strict";

function validateHashChain(records) {
  if (!Array.isArray(records) || records.length === 0) {
    return { valid: false, reason: "audit-records-empty" };
  }
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (!record.currentHash || typeof record.currentHash !== "string") {
      return { valid: false, reason: `missing-current-hash:${index}` };
    }
    const expectedPrevious = index === 0 ? null : records[index - 1].currentHash;
    if ((record.previousHash ?? null) !== expectedPrevious) {
      return { valid: false, reason: `broken-previous-hash:${index}` };
    }
  }
  return { valid: true, reason: "ok" };
}

function buildAuditSyncBundle({
  records,
  deviceIdHash,
  sessionId,
  policyVersion,
  generatedAt,
} = {}) {
  const chain = validateHashChain(records);
  if (!chain.valid) {
    return {
      ready: false,
      reason: chain.reason,
    };
  }
  if (!deviceIdHash || !sessionId || !generatedAt) {
    return {
      ready: false,
      reason: "missing-sync-identity",
    };
  }
  return {
    ready: true,
    schemaVersion: 1,
    generatedAt,
    deviceIdHash,
    sessionId,
    policyVersion: policyVersion ?? null,
    recordCount: records.length,
    firstHash: records[0].currentHash,
    headHash: records[records.length - 1].currentHash,
    records,
  };
}

module.exports = {
  buildAuditSyncBundle,
  validateHashChain,
};
