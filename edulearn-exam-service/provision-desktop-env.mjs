#!/usr/bin/env node
// Wire the DESKTOP .env (loaded by scripts/open-electron.js, inherited by the
// rust-core sidecar) so the signed-policy + elevated-remediation handshake runs:
//   EDULEARN_REQUIRE_SIGNED_EXAM_POLICY=1    → get_status.signedPolicyRequired=true
//        so the client runs prepareDesktopExamSecurity and obtains a signed
//        serviceAuthorization receipt for the elevated kill.
//   EDULEARN_EXAM_POLICY_PUBLIC_KEYS_JSON    → the trusted policy PUBLIC key so
//        rust-core can verify the backend's signed exam policy (same keypair as
//        the backend private key + the service's trustedServerKeys).
// Idempotent: never overwrites a var that is already set.

import { readFileSync, existsSync, appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const keysFile = join(here, 'exam-guard-keys.local.json');
const desktopEnv = resolve(here, '..', '.env');

if (!existsSync(keysFile)) {
  console.error(`[desktop-env] missing ${keysFile}. Run provision-dev-keys.mjs first.`);
  process.exit(1);
}
const keys = JSON.parse(readFileSync(keysFile, 'utf8'));

const existing = existsSync(desktopEnv) ? readFileSync(desktopEnv, 'utf8') : '';
const want = [
  ['EDULEARN_REQUIRE_SIGNED_EXAM_POLICY', '1'],
  ['EDULEARN_EXAM_POLICY_PUBLIC_KEYS_JSON', keys.trustedServerKeysJson],
];

const toAdd = want.filter(
  ([name]) => !new RegExp(`^\\s*${name}=`, 'm').test(existing),
);

if (toAdd.length === 0) {
  console.log('[desktop-env] both vars already present in desktop/.env — nothing to do.');
} else {
  const block =
    `${existing.endsWith('\n') || existing === '' ? '' : '\n'}` +
    `\n# EduLearn Exam Guard (Option B) — signed policy + elevated remediation\n` +
    toAdd.map(([name, value]) => `${name}=${value}`).join('\n') +
    '\n';
  appendFileSync(desktopEnv, block);
  console.log(
    `[desktop-env] added to ${desktopEnv}:\n` +
      toAdd.map(([name]) => `  ${name}`).join('\n') +
      `\n\nRESTART desktop:stable to load them.`,
  );
}
