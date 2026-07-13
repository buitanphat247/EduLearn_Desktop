"use strict";

// F-006 / Electron hardening — Content-Security-Policy for the exam window.
//
// Report-only by DEFAULT (EDULEARN_CSP unset|report) so a dry-run surfaces
// violations without breaking the Next.js renderer; `EDULEARN_CSP=enforce` sends
// a blocking policy. The always-safe hardening directives (`object-src 'none'`,
// `frame-src 'none'`, `frame-ancestors 'none'`, `base-uri 'self'`,
// `form-action 'self'`) close real holes (clickjacking, injected <object>/<base>,
// off-origin form posts) without breaking the app.
//
// `buildCspValue` / `buildCspHeader` are pure and unit-tested; `installCsp` wires
// the header into the window session.

function cspMode(env = process.env) {
  return env.EDULEARN_CSP === "enforce" ? "enforce" : "report";
}

/**
 * Build the CSP directive string. `connectHosts` are the extra origins the
 * renderer legitimately calls (the API / socket host), added to `connect-src`.
 */
function buildCspValue(connectHosts = []) {
  const connect = ["'self'", ...connectHosts.map((host) => String(host))].join(" ");
  return [
    "default-src 'self'",
    // Next.js hydration currently needs inline/eval; tightened via nonces later.
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    `connect-src ${connect}`,
    "object-src 'none'",
    "frame-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ");
}

function buildCspHeader({ connectHosts = [], mode = cspMode() } = {}) {
  const headerName =
    mode === "enforce" ? "Content-Security-Policy" : "Content-Security-Policy-Report-Only";
  return { headerName, value: buildCspValue(connectHosts), mode };
}

/** Inject the CSP header into every response for the exam window's session. */
function installCsp(win, options = {}) {
  const { connectHosts = [], mode = cspMode() } = options;
  const { headerName, value } = buildCspHeader({ connectHosts, mode });
  const ses = win.webContents.session;
  ses.webRequest.onHeadersReceived((details, callback) => {
    const responseHeaders = { ...details.responseHeaders };
    // Drop any upstream CSP so ours is authoritative (a rogue origin can't relax it).
    for (const key of Object.keys(responseHeaders)) {
      if (/^content-security-policy(-report-only)?$/i.test(key)) {
        delete responseHeaders[key];
      }
    }
    responseHeaders[headerName] = [value];
    callback({ responseHeaders });
  });
  return { headerName, value, mode };
}

module.exports = { cspMode, buildCspValue, buildCspHeader, installCsp };
