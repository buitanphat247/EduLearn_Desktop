"use strict";

const crypto = require("crypto");

// C3 fix — per-launch renderer→main capability token.
//
// The exam room UI is loaded over an untrusted origin (plain http). With
// contextIsolation the page can only reach what the preload exposes, but the
// preload historically forwarded any `desktop-core:*` command straight to the
// native core. `isTrustedSender` proves the message came from the exam window's
// webContents, but not that it came through *our* bundled preload.
//
// This module mints a cryptographically random secret at main-process startup
// and hands it to the preload via a Chromium `additionalArguments` entry — a
// channel readable by the preload (isolated world / process.argv) but NOT by the
// untrusted page. The preload attaches the token to every privileged IPC call
// and main verifies it (constant-time) before dispatching. A rogue webContents,
// an external browser pointed at the http origin, or a replay from another
// process cannot present the token, so it cannot drive the core.
//
// The token lives only in memory for the life of the process; each launch (and
// each Electron process, including the isolated exam-shell) gets its own.

const CAPABILITY_TOKEN_ARG_PREFIX = "--edulearn-cap-token=";

// Robust exam-shell identity marker. Delivered to the shell window's preload via
// the same `additionalArguments`/argv channel as the capability token, so the
// room's disconnect-safety + exit UI never mis-read a genuine isolated shell as
// the trapping in-window mode just because an env var failed to propagate.
const EXAM_SHELL_LAUNCH_ARG = "--edulearn-exam-shell=1";

let cachedToken = null;

function getCapabilityToken() {
  if (!cachedToken) {
    cachedToken = crypto.randomBytes(32).toString("hex");
  }
  return cachedToken;
}

// The `additionalArguments` entry to pass into a BrowserWindow's webPreferences
// so the preload of that window can read the current process's token.
function capabilityTokenLaunchArg() {
  return `${CAPABILITY_TOKEN_ARG_PREFIX}${getCapabilityToken()}`;
}

// Preload-side: pull the token out of process.argv (Chromium appends
// additionalArguments there). Returns null when absent.
function readCapabilityTokenFromArgv(argv) {
  const args = Array.isArray(argv) ? argv : [];
  for (const entry of args) {
    if (typeof entry === "string" && entry.startsWith(CAPABILITY_TOKEN_ARG_PREFIX)) {
      return entry.slice(CAPABILITY_TOKEN_ARG_PREFIX.length);
    }
  }
  return null;
}

// Preload-side: true when this launch's argv marks the process as the isolated
// exam-shell. Combined (OR) with the env flag as defense-in-depth.
function isExamShellFromArgv(argv) {
  const args = Array.isArray(argv) ? argv : [];
  return args.includes(EXAM_SHELL_LAUNCH_ARG);
}

// Constant-time comparison of a candidate token against this process's token.
// Never throws on malformed input — just returns false.
function verifyCapabilityToken(candidate) {
  if (typeof candidate !== "string" || candidate.length === 0) {
    return false;
  }
  const expected = getCapabilityToken();
  const a = Buffer.from(candidate, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) {
    return false;
  }
  try {
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

module.exports = {
  CAPABILITY_TOKEN_ARG_PREFIX,
  EXAM_SHELL_LAUNCH_ARG,
  getCapabilityToken,
  capabilityTokenLaunchArg,
  readCapabilityTokenFromArgv,
  isExamShellFromArgv,
  verifyCapabilityToken,
};
