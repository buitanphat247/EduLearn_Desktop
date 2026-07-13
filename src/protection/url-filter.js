"use strict";

const crypto = require("crypto");
const { canonicalize } = require("../ipc-auth");

// URL allow-list / navigation filter for the exam window.
//
// Safe Exam Browser restricts the candidate to an approved set of resources.
// This module is the equivalent for the EduLearn shell: only the exam origin
// (and any explicitly configured hosts) may be requested or navigated to. New
// windows / popups are always denied.
//
// The pure helpers (`buildAllowlist`, `isAllowedUrl`) are exported for unit
// testing; `installUrlFilter` wires them into an Electron BrowserWindow.

// Non-network schemes the renderer legitimately uses internally.
const ALWAYS_ALLOWED_SCHEMES = new Set([
  "data",
  "blob",
  "about",
  "devtools",
  "chrome-devtools",
]);

const NETWORK_SCHEMES = new Set(["http", "https", "ws", "wss"]);

function parseEnvHosts(raw) {
  if (!raw) {
    return [];
  }
  return raw
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

function hostFromUrl(raw) {
  try {
    return new URL(raw).hostname.toLowerCase();
  } catch {
    return null;
  }
}

// Hosts that should be allowed in addition to the exam origin. Combines the
// explicit EDULEARN_ALLOWED_HOSTS override with the API origins the renderer
// legitimately calls (NEXT_PUBLIC_API_URL / NEXT_PUBLIC_FLASK_API_URL), so the
// filter does not accidentally block the backend in production.
function defaultExtraHosts(env = process.env) {
  const hosts = new Set(parseEnvHosts(env.EDULEARN_ALLOWED_HOSTS));
  for (const name of ["NEXT_PUBLIC_API_URL", "NEXT_PUBLIC_FLASK_API_URL"]) {
    const host = hostFromUrl(env[name]);
    if (host) {
      hosts.add(host);
    }
  }
  return [...hosts];
}

// H1: the isolated exam-shell is a high-stakes, locked environment that only
// ever legitimately loads the room URL (its startUrl, allow-listed) plus the API
// host (auto-allowed), so the filter ENFORCES there by default — matching SEB's
// URL allow-list. The lobby / dev stay in "report" (log-only) so a dry-run can
// still validate real traffic before enforcement. Explicit EDULEARN_URL_FILTER
// (enforce|report) always overrides. Popups are denied whenever enforcing.
function resolveMode(env = process.env) {
  if (env.EDULEARN_URL_FILTER === "enforce") {
    return "enforce";
  }
  if (env.EDULEARN_URL_FILTER === "report") {
    return "report";
  }
  return env.EDULEARN_EXAM_SHELL === "1" ? "enforce" : "report";
}

/**
 * Build the set of allowed hostnames from the exam start URL plus any extra
 * hosts (e.g. a separate API domain configured via env). localhost/127.0.0.1
 * are only whitelisted when the exam itself is served locally (dev), so a
 * production kiosk cannot be redirected to a local rogue server.
 */
function buildAllowlist({ startUrl, extraHosts = [] } = {}) {
  const hosts = new Set();
  const add = (host) => {
    if (host) {
      hosts.add(String(host).toLowerCase());
    }
  };

  let startHost = null;
  try {
    startHost = new URL(startUrl).hostname;
  } catch {
    startHost = null;
  }
  add(startHost);

  if (startHost === "localhost" || startHost === "127.0.0.1") {
    add("localhost");
    add("127.0.0.1");
  }

  for (const host of extraHosts) {
    add(host);
  }

  return hosts;
}

/**
 * Whether a hostname is covered by the allow-list: an exact match, or a
 * subdomain of an allowed host (so `cdn.exam.edu` is allowed when `exam.edu` is
 * listed). This avoids blocking the exam's own CDN/asset subdomains, a common
 * cause of a broken page under enforcement.
 */
function hostAllowed(hostname, allowlist) {
  const host = String(hostname).toLowerCase();
  if (allowlist.has(host)) {
    return true;
  }
  for (const allowed of allowlist) {
    if (host.endsWith(`.${allowed}`)) {
      return true;
    }
  }
  return false;
}

/**
 * Decide whether a URL may be requested/navigated to. Internal schemes are
 * always allowed; network schemes must target an allow-listed host (or a
 * subdomain of one); everything else (file:, ftp:, custom protocol handlers, …)
 * is denied.
 */
function isAllowedUrl(rawUrl, allowlist) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return false;
  }

  const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();
  if (ALWAYS_ALLOWED_SCHEMES.has(scheme)) {
    return true;
  }
  if (NETWORK_SCHEMES.has(scheme)) {
    return hostAllowed(parsed.hostname, allowlist);
  }
  return false;
}

// --- F-006: signed allowlist -----------------------------------------------
// The authoritative allowlist should come from a POLICY SIGNED by the exam-policy
// Ed25519 key (server side, `EXAM_POLICY_PRIVATE_KEY_PEM`), verified here against
// the trusted public keys (`EDULEARN_EXAM_POLICY_PUBLIC_KEYS_JSON`). A tampered or
// unsigned allowlist is refused, so the candidate machine cannot widen the set of
// reachable hosts. The canonicalization matches the server (`canonical.ts`) and
// the IPC layer (JCS: recursive, sorted keys).

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function ed25519PublicKeyFromRaw(rawBase64) {
  let raw;
  try {
    raw = Buffer.from(String(rawBase64), "base64");
  } catch {
    return null;
  }
  if (raw.length !== 32) {
    return null;
  }
  try {
    return crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
      format: "der",
      type: "spki",
    });
  } catch {
    return null;
  }
}

/** Parse EDULEARN_EXAM_POLICY_PUBLIC_KEYS_JSON ({ keyId: base64-raw-pubkey }). */
function parseTrustedKeys(raw) {
  if (!raw) {
    return {};
  }
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

/**
 * Verify a signed allowlist blob and return { ok, hosts, reason }.
 * @param {{payload:{hosts:string[],version?:string,expiresAtMs?:number}, keyId:string, signature:string}} signed
 * @param {Record<string,string>} trustedKeysB64  keyId -> base64 raw Ed25519 public key
 */
function verifySignedAllowlist(signed, trustedKeysB64, now = Date.now()) {
  if (!signed || typeof signed !== "object" || !signed.payload || typeof signed.payload !== "object") {
    return { ok: false, hosts: [], reason: "malformed" };
  }
  const publicKeyB64 = trustedKeysB64 && trustedKeysB64[signed.keyId];
  if (!publicKeyB64) {
    return { ok: false, hosts: [], reason: "unknown keyId" };
  }
  const key = ed25519PublicKeyFromRaw(publicKeyB64);
  if (!key) {
    return { ok: false, hosts: [], reason: "bad public key" };
  }
  if (typeof signed.payload.expiresAtMs === "number" && signed.payload.expiresAtMs <= now) {
    return { ok: false, hosts: [], reason: "expired" };
  }
  let valid = false;
  try {
    valid = crypto.verify(
      null,
      Buffer.from(canonicalize(signed.payload), "utf8"),
      key,
      Buffer.from(String(signed.signature), "base64"),
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    return { ok: false, hosts: [], reason: "bad signature" };
  }
  const hosts = Array.isArray(signed.payload.hosts)
    ? signed.payload.hosts.filter((host) => typeof host === "string" && host.trim())
    : [];
  return { ok: true, hosts, reason: null };
}

/**
 * Install the request/navigation filter on an exam BrowserWindow.
 *
 * @param {import('electron').BrowserWindow} win
 * @param {object} options
 * @param {string} options.startUrl        The exam URL the window loads.
 * @param {string[]} [options.extraHosts]   Additional allowed hosts (defaults to EDULEARN_ALLOWED_HOSTS).
 * @param {(info: {kind: string, url: string}) => void} [options.onBlocked]
 * @returns {Set<string>} the resolved allow-list (useful for logging/tests)
 */
function installUrlFilter(win, options = {}) {
  const {
    startUrl,
    extraHosts = defaultExtraHosts(),
    mode = resolveMode(),
    onBlocked = () => {},
    signedAllowlist = null,
    trustedKeys = parseTrustedKeys(process.env.EDULEARN_EXAM_POLICY_PUBLIC_KEYS_JSON),
  } = options;

  const enforcing = mode === "enforce";

  // F-006: fold in a SIGNED allowlist when present AND valid; refuse it otherwise
  // (a tampered/unsigned/expired blob never widens the reachable host set).
  let signedHosts = [];
  let signedAllowlistStatus = "none";
  if (signedAllowlist) {
    const verdict = verifySignedAllowlist(signedAllowlist, trustedKeys);
    if (verdict.ok) {
      signedHosts = verdict.hosts;
      signedAllowlistStatus = "verified";
    } else {
      signedAllowlistStatus = `rejected:${verdict.reason}`;
      safeInvoke(onBlocked, {
        kind: "signed-allowlist-rejected",
        url: verdict.reason,
        blocked: enforcing,
      });
    }
  }

  const allowlist = buildAllowlist({ startUrl, extraHosts: [...extraHosts, ...signedHosts] });

  // F-006 telemetry: structured counts of every block/flag decision.
  const telemetry = { blocked: 0, flagged: 0, byKind: Object.create(null) };
  const report = (kind, url) => {
    telemetry.byKind[kind] = (telemetry.byKind[kind] || 0) + 1;
    if (enforcing) {
      telemetry.blocked += 1;
    } else {
      telemetry.flagged += 1;
    }
    safeInvoke(onBlocked, { kind, url, blocked: enforcing });
  };

  const contents = win.webContents;
  const ses = contents.session;

  ses.webRequest.onBeforeRequest((details, callback) => {
    if (isAllowedUrl(details.url, allowlist)) {
      callback({});
      return;
    }
    report("request", details.url);
    callback(enforcing ? { cancel: true } : {});
  });

  // Deny popups only when enforcing; in report mode we log but allow so the
  // dry-run stays truly passive and surfaces (rather than breaks) any legitimate
  // window.open flow before enforcement is turned on.
  contents.setWindowOpenHandler(({ url }) => {
    report("window-open", url);
    return { action: enforcing ? "deny" : "allow" };
  });

  const blockNavigation = (event, url) => {
    if (!isAllowedUrl(url, allowlist)) {
      if (enforcing) {
        event.preventDefault();
      }
      report("navigate", url);
    }
  };
  contents.on("will-navigate", blockNavigation);
  contents.on("will-redirect", blockNavigation);

  return { allowlist, mode, enforcing, telemetry, signedAllowlistStatus };
}

function safeInvoke(fn, arg) {
  try {
    fn(arg);
  } catch (error) {
    console.error("[desktop] url-filter onBlocked handler threw", error);
  }
}

module.exports = {
  ALWAYS_ALLOWED_SCHEMES,
  NETWORK_SCHEMES,
  parseEnvHosts,
  hostFromUrl,
  defaultExtraHosts,
  resolveMode,
  buildAllowlist,
  hostAllowed,
  isAllowedUrl,
  installUrlFilter,
  ed25519PublicKeyFromRaw,
  parseTrustedKeys,
  verifySignedAllowlist,
};
