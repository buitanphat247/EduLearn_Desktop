"use strict";

const fs = require("fs");
const path = require("path");
const { app, net, session } = require("electron");
const { EXAM_PARTITION } = require("./exam-session-handoff");

// VS-02: offline exit-password cache file path. One file per session, stored in
// userData (owner-only mode). Layout:
// {
//   "exitPasswordHash": "$2b$12$...",   // bcrypt hash from server
//   "cachedAt": 1234567890              // ms timestamp
// }
const EXIT_CACHE_PREFIX = "exam-exit-";
const EXIT_CACHE_SUFFIX = ".json";

function roomOrigin() {
  const url = process.env.ELECTRON_START_URL || "http://localhost:3000";
  try {
    return new URL(url).origin;
  } catch {
    return "http://localhost:3000";
  }
}

function requestJson({ method, url, examSession, headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const request = net.request({
      method,
      url,
      session: examSession,
      useSessionCookies: true,
    });
    for (const [key, value] of Object.entries(headers)) {
      request.setHeader(key, value);
    }
    let data = "";
    request.on("response", (response) => {
      response.on("data", (chunk) => {
        data += chunk.toString();
      });
      response.on("end", () => resolve({ status: response.statusCode, body: data }));
    });
    request.on("error", reject);
    if (body != null) {
      request.write(body);
    }
    request.end();
  });
}

// ─── Offline exit-password cache ──────────────────────────────────────────────

/** Returns the path to the offline cache file for a session, or null on error. */
function exitCachePath(sessionId) {
  try {
    const safe = String(sessionId || "").replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 64);
    return path.join(app.getPath("userData"), `${EXIT_CACHE_PREFIX}${safe}${EXIT_CACHE_SUFFIX}`);
  } catch {
    return null;
  }
}

/**
 * Cache the exit-password bcrypt hash for a session. Called from the main
 * process when `start_exam_session` succeeds and the response carries the hash.
 * Writes owner-only (0o600) so the auth token file is not world-readable.
 *
 * @param {string} sessionId
 * @param {string|null} exitPasswordHash  bcrypt hash from the server, or null
 *                                        when no exit password is configured.
 */
function cacheExitPasswordHash(sessionId, exitPasswordHash) {
  const filePath = exitCachePath(sessionId);
  if (!filePath) return;
  try {
    if (exitPasswordHash) {
      fs.writeFileSync(filePath, JSON.stringify({
        exitPasswordHash,
        cachedAt: Date.now(),
      }), { encoding: "utf8", mode: 0o600 });
    } else {
      // No exit password configured — remove any stale cache entry.
      try { fs.unlinkSync(filePath); } catch { /* already gone */ }
    }
  } catch (error) {
    console.error("[desktop] Failed to cache exit-password hash:", error?.message ?? error);
  }
}

/** Load the cached exit-password hash for a session. Returns null if not cached. */
function loadExitPasswordHash(sessionId) {
  const filePath = exitCachePath(sessionId);
  if (!filePath) return null;
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    return typeof parsed.exitPasswordHash === "string" ? parsed.exitPasswordHash : null;
  } catch {
    return null;
  }
}

/**
 * Invalidate the offline exit-password cache for a session. Called when the
 * exam session ends so stale material is never reused.
 */
function invalidateExitPasswordCache(sessionId) {
  const filePath = exitCachePath(sessionId);
  if (!filePath) return;
  try { fs.unlinkSync(filePath); } catch { /* already gone */ }
}

// ─── Offline verification ──────────────────────────────────────────────────────

// Lazy-load bcryptjs so the desktop module load does not fail when the package
// is not yet installed. Only used on packaged builds.
// VS-02 test override: BCryptJsCompareFn env-var names a global function
// (e.g. "bcryptjs.compare") that is resolved and used instead of the real bcryptjs.
// This lets tests inject a real bcryptjs.compare without fighting Node's module cache.
// The function must be set as a property on globalThis before calling this module.
function requireBcryptjs() {
  const mockFnName = process.env.BCryptJsCompareFn;
  if (mockFnName && typeof globalThis[mockFnName] === "function") {
    return { compare: globalThis[mockFnName] };
  }
  try {
    return require("bcryptjs");
  } catch (error) {
    console.error("[desktop] bcryptjs not available for offline exit verify:", error?.message ?? error);
    return null;
  }
}

/**
 * VS-02: Offline-safe exit-password verification using the locally cached bcrypt
 * hash. Returns:
 *  - "ok":        password matches the cached hash  → allow exit
 *  - "denied":    password does NOT match           → BLOCK (fail-closed)
 *  - "no_cache":  no cached material available       → caller must fall through
 *
 * This runs in the main process so a compromised renderer cannot interfere.
 */
async function verifyOfflineExitPassword(sessionId, password) {
  if (!sessionId || !password) {
    return "denied";
  }

  const cachedHash = loadExitPasswordHash(sessionId);
  if (!cachedHash) {
    return "no_cache"; // no local material — caller must use the server path
  }

  // Verify using bcrypt.compare (constant-time by design).
  const bcrypt = requireBcryptjs();
  if (!bcrypt) {
    console.warn("[desktop] bcryptjs unavailable, cannot verify offline — falling through to server");
    return "no_cache";
  }

  try {
    const ok = await bcrypt.compare(password, cachedHash);
    return ok ? "ok" : "denied";
  } catch (error) {
    console.error("[desktop] Offline exit-password verify failed:", error?.message ?? error);
    // Corrupt cache → fall through to server; do NOT grant exit.
    return "no_cache";
  }
}

// ─── Server-side verification ─────────────────────────────────────────────────

/**
 * Re-verify the invigilator exit password from the MAIN process (independent of
 * the renderer), so an injected/compromised exam page cannot bypass the exit
 * gate by calling the exit IPC directly.
 *
 * VS-02 CHANGE: We now check the offline cache FIRST (fail-closed), and only
 * fall through to the server API when no local material is cached. This closes
 * the network-error fail-open gap — a candidate who firewalls the API can no
 * longer exit with any wrong password.
 *
 * Returns:
 *  - "denied": password rejected (offline mismatch OR server 403) → BLOCK
 *  - "ok":     password accepted (offline match OR server 2xx)     → allow
 *  - "error":  network/technical failure AND no local cache       → FAIL-OPEN
 *              (genuine exit never trapped; no local material to verify against)
 */
async function verifyExitPasswordInMain(sessionId, password) {
  if (!sessionId || !password) {
    return "denied";
  }

  // Step 1: Offline verification (fail-closed — wrong password is BLOCKED).
  const offlineResult = await verifyOfflineExitPassword(sessionId, password);
  if (offlineResult === "ok") {
    return "ok";
  }
  if (offlineResult === "denied") {
    return "denied";
  }
  // offlineResult === "no_cache" → fall through to server below.

  // Step 2: Server API verification (fallback when no cached material exists).
  try {
    const examSession = session.fromPartition(EXAM_PARTITION);
    const origin = roomOrigin();

    let csrfToken = "";
    try {
      const csrf = await requestJson({
        method: "GET",
        url: `${origin}/api/api-proxy/auth/csrf-token`,
        examSession,
      });
      csrfToken = JSON.parse(csrf.body)?.data?.csrfToken || "";
    } catch {
      // csrf fetch failed — fall through; the POST will 4xx and we fail-open.
    }

    const verify = await requestJson({
      method: "POST",
      url: `${origin}/api/api-proxy/exams/virtual-room/${encodeURIComponent(sessionId)}/verify-exit`,
      examSession,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
      },
      body: JSON.stringify({ exitPassword: password }),
    });

    if (verify.status >= 200 && verify.status < 300) {
      return "ok";
    }
    if (verify.status === 403) {
      return "denied";
    }
    return "error";
  } catch {
    return "error";
  }
}

module.exports = {
  verifyExitPasswordInMain,
  cacheExitPasswordHash,
  loadExitPasswordHash,
  invalidateExitPasswordCache,
  verifyOfflineExitPassword,
};
