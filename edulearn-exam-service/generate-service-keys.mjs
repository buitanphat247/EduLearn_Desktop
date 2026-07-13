#!/usr/bin/env node
// Generate the Ed25519 signing keypair that ties the three parts of "Option B"
// (elevated remediation via the SYSTEM service) together:
//
//   • BACKEND (NestJS) signs the exam policy + the `elevated-remediation`
//     receipt with the PRIVATE key  → env `EXAM_POLICY_PRIVATE_KEY_PEM`
//     (+ `EXAM_POLICY_KEY_ID`). See exam-security.service.ts `signReceipt`.
//   • SERVICE (edulearn-exam-service) trusts the matching RAW PUBLIC key
//     (base64 of the 32 raw bytes) keyed by the same key id → the
//     `trustedServerKeys` map in service-config.json (written by
//     Install-ExamGuardService.ps1). See authorization.rs
//     `from_base64_keys` / `VerifyingKey::from_bytes`.
//
// The two MUST come from the same keypair or every elevated kill is rejected as
// "Signature verification failed". This script emits both sides in the exact
// shapes each consumer expects, and self-tests the round-trip before printing.
//
// Usage:  node generate-service-keys.mjs [--key-id exam-policy-primary]

import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const keyId = arg('--key-id', 'exam-policy-primary');

// Ed25519 keypair — same algorithm the backend and the Rust service use.
const { publicKey, privateKey } = generateKeyPairSync('ed25519');

// Backend side: PKCS#8 PEM (what `createPrivateKey(config.policyPrivateKeyPem)`
// expects). For a single-line .env value, newlines are escaped as `\n`.
const pkcs8Pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).trim();
const pemEnvValue = pkcs8Pem.replace(/\n/g, '\\n');

// Service side: the RAW 32-byte Ed25519 public key, base64. An SPKI DER for
// Ed25519 is a fixed 12-byte header followed by the 32-byte key.
const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
const rawPublic = spkiDer.subarray(spkiDer.length - 32);
const rawPublicB64 = rawPublic.toString('base64');
const trustedServerKeysJson = JSON.stringify({ [keyId]: rawPublicB64 });

// Self-test: sign like the backend, verify with a key reconstructed from the
// RAW bytes exactly the way the Rust service does (base64 → 32 bytes → key).
const message = Buffer.from('edulearn-exam-guard-keypair-selftest');
const signature = sign(null, message, createPrivateKey(pkcs8Pem));
const reconstructedSpki = Buffer.concat([spkiDer.subarray(0, 12), rawPublic]);
const reconstructedPublic = createPublicKey({
  key: reconstructedSpki,
  format: 'der',
  type: 'spki',
});
const ok = verify(null, message, reconstructedPublic, signature);
if (!ok) {
  console.error(
    'FATAL: keypair self-test failed (private PEM ↔ raw public key mismatch). Aborting.',
  );
  process.exit(1);
}

console.log(`
============================================================
 EduLearn Exam Guard — Option B signing keypair
 key id: ${keyId}   (self-test: PASSED ✅)
============================================================

STEP 1 — BACKEND (.env of server/server-nest), then restart the server:
------------------------------------------------------------
EXAM_POLICY_KEY_ID=${keyId}
EXAM_POLICY_PRIVATE_KEY_PEM=${pemEnvValue}
------------------------------------------------------------

STEP 2 — SERVICE install: pass this as -TrustedServerKeysJson to
         Setup-ExamGuardService.ps1 / Install-ExamGuardService.ps1
         (raw 32-byte Ed25519 public key, base64):
------------------------------------------------------------
${trustedServerKeysJson}
------------------------------------------------------------

⚠  Keep the PRIVATE key secret (it authorizes elevated process kills).
   Generate a SEPARATE keypair for production and store the private PEM
   in your secrets manager, never in git.
`);
