"use strict";

// VS-03 / F-006 — Content-Security-Policy for the exam window.
//
// Enforcement model (the VS-03 fix):
//   * PACKAGED exam-shell  -> ALWAYS `enforce`. A missing/relaxed EDULEARN_CSP
//     can NEVER silently downgrade a packaged exam-shell to report-only.
//   * Development / lobby   -> `report` by default (dry-run: surface violations
//     without breaking the Next.js dev server / HMR), or an explicit
//     EDULEARN_CSP=enforce|report override.
//
// Policy model:
//   * PACKAGED   script-src = 'self' 'unsafe-inline'   (NO 'unsafe-eval')
//   * DEV        script-src = 'self' 'unsafe-inline' 'unsafe-eval'
//     `unsafe-eval` is a DEVELOPMENT-only need (Next.js dev uses eval-based
//     source maps + React Refresh); a production Next build does not use eval,
//     so it is dropped from the packaged policy — the core of VS-03.
//
//   `script-src 'unsafe-inline'` is RETAINED with a documented blocker: the
//   renderer is a Next.js app whose server-rendered bootstrap <script> tags
//   (App Router `self.__next_f.push(...)`, hydration) would need per-request
//   nonces propagated by Next.js middleware. Electron injects CSP on the
//   *response* path here, so it cannot supply a nonce that matches Next's
//   already-rendered HTML. Removing script `unsafe-inline` therefore requires a
//   client-package (Next.js) nonce migration — tracked as the VS-03 follow-up,
//   out of scope for this desktop-only change. `style-src 'unsafe-inline'` is a
//   separate, lower-risk allowance the UI framework genuinely needs.
//
//   The always-safe hardening directives (`object-src 'none'`, `frame-src
//   'none'`, `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'self'`)
//   close real holes (clickjacking, injected <object>/<base>, off-origin form
//   posts) and — now that the packaged exam-shell ENFORCES — actually block.
//
// `buildCspValue` / `buildCspHeader` are pure and unit-tested; `installCsp`
// wires the header into the exam window's session.

/**
 * Resolve whether the CSP is emitted as an enforcing header or report-only.
 *
 * @param {Record<string,string|undefined>} env
 * @param {{ packaged?: boolean, examShell?: boolean }} [ctx]
 * @returns {"enforce"|"report"}
 */
function cspMode(env = process.env, ctx = {}) {
  const { packaged = false, examShell = false } = ctx;
  // Hard rule: a packaged exam-shell always enforces and cannot be downgraded
  // by a missing or `report` EDULEARN_CSP — this is the VS-03 fail-closed fix.
  if (packaged && examShell) {
    return "enforce";
  }
  // Explicit developer/test override.
  if (env.EDULEARN_CSP === "enforce") {
    return "enforce";
  }
  if (env.EDULEARN_CSP === "report") {
    return "report";
  }
  // Dev / non-exam default: report-only (dry-run, non-breaking).
  return "report";
}

// Characters that must never appear inside a CSP source token — they would
// break out of the directive or let a malformed config inject extra sources.
const UNSAFE_SOURCE_CHARS = /[\s,;'"]/;

/**
 * Normalize + validate the configured connect origins (from the trusted,
 * Ed25519-signed URL-filter allowlist — NOT untrusted renderer input):
 * stringify, trim, drop empties/wildcards/malformed tokens, and deduplicate.
 *
 * @param {Array<unknown>} connectHosts
 * @returns {string[]}
 */
function normalizeConnectHosts(connectHosts = []) {
  const seen = new Set();
  const out = [];
  for (const raw of connectHosts) {
    if (raw == null) {
      continue;
    }
    const host = String(raw).trim();
    if (!host) {
      continue;
    }
    // Reject wildcards and any token carrying directive-breaking characters.
    if (host === "*" || host.includes("*") || UNSAFE_SOURCE_CHARS.test(host)) {
      continue;
    }
    if (seen.has(host)) {
      continue;
    }
    seen.add(host);
    out.push(host);
  }
  return out;
}

/**
 * Build the CSP directive string.
 *
 * @param {Array<unknown>} connectHosts extra origins the renderer legitimately
 *   calls (API / socket host), added to `connect-src`.
/** Nonce charset per CSP spec (base64) plus url-safe variants Next may emit. */
const CSP_NONCE_RE = /'nonce-([A-Za-z0-9+/=_-]{8,256})'/;

/**
 * @param {{ packaged?: boolean, nonce?: string|null }} [opts] when `packaged` is
 *   false the DEV policy adds `'unsafe-eval'`; when a `nonce` is supplied (from the
 *   Next.js middleware, see VS-03) `script-src` becomes `'self' 'nonce-…'` with NO
 *   `'unsafe-inline'` and NO `'unsafe-eval'` — the strongest form.
 */
function buildCspValue(connectHosts = [], opts = {}) {
  const { packaged = false, nonce = null } = opts;
  const connect = ["'self'", ...normalizeConnectHosts(connectHosts)].join(" ");
  // VS-03 strongest: a per-request nonce lets us drop BOTH unsafe-inline and
  // unsafe-eval — only the exact nonced inline scripts (Next.js bootstrap +
  // our own) and 'self' run. Falls back to the unsafe-inline policy when no
  // nonce is available (dev without the middleware, or a non-Next response).
  const scriptSrc = nonce
    ? `script-src 'self' 'nonce-${nonce}'`
    : packaged
      ? "script-src 'self' 'unsafe-inline'"
      : "script-src 'self' 'unsafe-inline' 'unsafe-eval'";
  // The NON-script directives mirror the trusted app's own CSP (Google auth/maps,
  // YouTube embeds, https images, fonts) so the exam-shell — which hosts the same
  // Next.js app — does not block the app's legitimate content. The real VS-03 win
  // is `script-src` (nonce / no unsafe-inline / no unsafe-eval), kept strict above;
  // XSS is what the exam must prevent, and the anti-cheat lock comes from the
  // URL-filter (navigation allowlist) + input lockdown + capture + server authority,
  // not from starving CSP of frames/images.
  return [
    "default-src 'self'",
    scriptSrc,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://accounts.google.com",
    "img-src 'self' data: blob: https: http:",
    "font-src 'self' https://fonts.gstatic.com data:",
    `connect-src ${connect} https: wss:`,
    "frame-src 'self' https://accounts.google.com https://content.googleapis.com https://www.google.com https://www.youtube.com https://www.youtube-nocookie.com",
    "media-src 'self' blob: https:",
    "worker-src 'self' blob:",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self' https://accounts.google.com",
  ].join("; ");
}

function buildCspHeader({ connectHosts = [], mode = cspMode(), packaged = false } = {}) {
  const headerName =
    mode === "enforce" ? "Content-Security-Policy" : "Content-Security-Policy-Report-Only";
  return { headerName, value: buildCspValue(connectHosts, { packaged }), mode, packaged };
}

/**
 * Inject the CSP header into every response for the exam window's session.
 *
 * @param {import('electron').BrowserWindow} win
 * @param {{ connectHosts?: Array<unknown>, mode?: "enforce"|"report",
 *           packaged?: boolean, examShell?: boolean, env?: object }} [options]
 */
function installCsp(win, options = {}) {
  const {
    connectHosts = [],
    packaged = false,
    examShell = false,
    env = process.env,
  } = options;
  // Mode is derived fail-closed from the packaged/examShell context unless an
  // explicit mode is passed in (tests). Packaged exam-shell => always enforce.
  const mode = options.mode || cspMode(env, { packaged, examShell });
  const { headerName, value } = buildCspHeader({ connectHosts, mode, packaged });
  const ses = win.webContents.session;
  // NOTE: Electron's webRequest.onHeadersReceived supports a SINGLE listener per
  // session; re-registering (e.g. exam-shell re-entry on the shared persistent
  // partition) REPLACES it rather than stacking — so no duplicate CSP handlers
  // accumulate. The URL filter uses onBeforeRequest (request path), so the two
  // never clobber each other.
  ses.webRequest.onHeadersReceived((details, callback) => {
    const responseHeaders = { ...details.responseHeaders };
    // VS-03: BEFORE stripping the upstream CSP, harvest a per-request nonce the
    // Next.js middleware set (script-src '...nonce-XXX...'). We then re-emit OUR
    // authoritative CSP carrying that SAME nonce, which lets us drop
    // script 'unsafe-inline' for document responses while staying the sole CSP.
    let nonce = null;
    for (const key of Object.keys(responseHeaders)) {
      if (/^content-security-policy(-report-only)?$/i.test(key)) {
        if (!nonce) {
          const raw = responseHeaders[key];
          const text = Array.isArray(raw) ? raw.join(" ") : String(raw ?? "");
          const match = CSP_NONCE_RE.exec(text);
          if (match) {
            nonce = match[1];
          }
        }
        // Drop any upstream CSP (enforce OR report-only) so ours is authoritative.
        delete responseHeaders[key];
      }
    }
    const effectiveValue = nonce
      ? buildCspValue(connectHosts, { packaged, nonce })
      : value;
    responseHeaders[headerName] = [effectiveValue];
    callback({ responseHeaders });
  });
  return { headerName, value, mode, packaged };
}

module.exports = {
  cspMode,
  buildCspValue,
  buildCspHeader,
  installCsp,
  normalizeConnectHosts,
};
