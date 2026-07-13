"use strict";

// P47-03: source the SIGNED URL allowlist blob for the exam window.
//
// The exam-shell is spawned by the trusted main process (exam-desktop-launcher),
// which fetches the server-signed blob and hands it to the shell through the
// EDULEARN_SIGNED_ALLOWLIST_JSON environment variable. window.js reads it here
// and passes it to installUrlFilter, which VERIFIES the Ed25519 signature before
// widening the reachable-host set — so even though the value rides through the
// environment, a tampered/forged blob is refused (it carries no valid signature).
//
// This helper is deliberately pure and Electron-free so the env -> filter wiring
// is unit-testable without booting a BrowserWindow. A missing or malformed value
// yields null, and installUrlFilter then falls back to the env-derived host list.

/**
 * Parse the signed allowlist blob the launcher injected, or null.
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {{payload: object, keyId?: string, signature?: string} | null}
 */
function resolveSignedAllowlistFromEnv(env = process.env) {
  const raw = env && env.EDULEARN_SIGNED_ALLOWLIST_JSON;
  if (!raw || typeof raw !== "string") {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (
    parsed &&
    typeof parsed === "object" &&
    parsed.payload &&
    typeof parsed.payload === "object"
  ) {
    return parsed;
  }
  return null;
}

module.exports = { resolveSignedAllowlistFromEnv };
