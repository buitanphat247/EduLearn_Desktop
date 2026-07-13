#!/usr/bin/env node
// DEV provisioning: generate ONE Ed25519 keypair, persist it, and wire the
// backend .env — so Option B works locally without hand-copying secrets.
//   • writes exam-guard-keys.local.json  (private PEM + trustedServerKeys)  [gitignored]
//   • appends EXAM_POLICY_* to server/server-nest/.env  (only if not already set)
//   • prints the -TrustedServerKeysJson value for Setup-ExamGuardService.ps1
// Idempotent: if the keys file already exists it is REUSED (so the backend key
// and the installed service stay in sync across re-runs). Never overwrites an
// existing EXAM_POLICY_PRIVATE_KEY_PEM in .env.

import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const keysFile = join(here, 'exam-guard-keys.local.json');
const envFile = resolve(here, '..', '..', 'server', 'server-nest', '.env');
const keyId = 'exam-policy-primary';

let record;
if (existsSync(keysFile)) {
  record = JSON.parse(readFileSync(keysFile, 'utf8'));
  console.log(`[provision] Reusing existing keypair: ${keysFile}`);
} else {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pkcs8Pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).trim();
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const rawPublicB64 = spkiDer.subarray(spkiDer.length - 32).toString('base64');
  record = {
    keyId,
    privateKeyPemEscaped: pkcs8Pem.replace(/\n/g, '\\n'),
    publicKeyRawBase64: rawPublicB64,
    trustedServerKeysJson: JSON.stringify({ [keyId]: rawPublicB64 }),
  };
  writeFileSync(keysFile, JSON.stringify(record, null, 2) + '\n', { mode: 0o600 });
  console.log(`[provision] Generated new keypair -> ${keysFile}`);
}

// self-test: sign like the backend, verify like the Rust service (raw 32 bytes).
const pem = record.privateKeyPemEscaped.replace(/\\n/g, '\n');
const raw = Buffer.from(record.publicKeyRawBase64, 'base64');
const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex'); // Ed25519 SPKI prefix
const pub = createPublicKey({
  key: Buffer.concat([spkiHeader, raw]),
  format: 'der',
  type: 'spki',
});
const msg = Buffer.from('provision-selftest');
if (!verify(null, msg, pub, sign(null, msg, createPrivateKey(pem)))) {
  console.error('[provision] FATAL: keypair self-test failed. Aborting.');
  process.exit(1);
}
console.log('[provision] keypair self-test: PASSED');

// wire the backend .env (idempotent).
let envStatus;
try {
  const existing = existsSync(envFile) ? readFileSync(envFile, 'utf8') : '';
  if (/^\s*EXAM_POLICY_PRIVATE_KEY_PEM=/m.test(existing)) {
    envStatus =
      'EXAM_POLICY_PRIVATE_KEY_PEM already set in .env — left untouched. ' +
      'Ensure it matches exam-guard-keys.local.json or re-install the service with the matching key.';
  } else {
    const block =
      `${existing.endsWith('\n') || existing === '' ? '' : '\n'}` +
      `\n# EduLearn Exam Guard (Option B) elevated-remediation signing key (DEV)\n` +
      `EXAM_POLICY_KEY_ID=${record.keyId}\n` +
      `EXAM_POLICY_PRIVATE_KEY_PEM=${record.privateKeyPemEscaped}\n`;
    appendFileSync(envFile, block);
    envStatus = `Appended EXAM_POLICY_KEY_ID + EXAM_POLICY_PRIVATE_KEY_PEM to ${envFile} — RESTART the backend.`;
  }
} catch (error) {
  envStatus =
    `Could not write ${envFile} (${error.message}). Add these lines manually:\n` +
    `  EXAM_POLICY_KEY_ID=${record.keyId}\n` +
    `  EXAM_POLICY_PRIVATE_KEY_PEM=${record.privateKeyPemEscaped}`;
}

console.log(`
[provision] Backend .env: ${envStatus}

[provision] Service install (elevated PowerShell):
  .\\Setup-ExamGuardService.ps1 -TrustedServerKeysJson '${record.trustedServerKeysJson}'
`);
