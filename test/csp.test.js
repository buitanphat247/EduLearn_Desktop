"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  cspMode,
  buildCspValue,
  buildCspHeader,
  installCsp,
  normalizeConnectHosts,
} = require("../src/protection/csp");

// Extract the `script-src ...` directive from a full CSP value.
function scriptSrcOf(value) {
  const m = value.split(";").map((s) => s.trim()).find((d) => d.startsWith("script-src"));
  return m || "";
}

// ---------------------------------------------------------------------------
// Enforcement mode (VS-03 core: packaged exam-shell can never be report-only)
// ---------------------------------------------------------------------------

test("VS-03: packaged exam-shell ALWAYS enforces, even with EDULEARN_CSP unset/report", () => {
  assert.equal(cspMode({}, { packaged: true, examShell: true }), "enforce");
  assert.equal(
    cspMode({ EDULEARN_CSP: "report" }, { packaged: true, examShell: true }),
    "enforce",
    "a relaxed env var must NOT downgrade a packaged exam-shell",
  );
  assert.equal(
    cspMode({ EDULEARN_CSP: "enforce" }, { packaged: true, examShell: true }),
    "enforce",
  );
});

test("dev / lobby default is report; explicit EDULEARN_CSP is honored", () => {
  assert.equal(cspMode({}), "report");
  assert.equal(cspMode({}, { packaged: false, examShell: false }), "report");
  assert.equal(cspMode({ EDULEARN_CSP: "report" }), "report");
  assert.equal(cspMode({ EDULEARN_CSP: "enforce" }), "enforce");
  // Unpackaged exam-shell defaults report (dry-run safe) unless explicitly set.
  assert.equal(cspMode({}, { packaged: false, examShell: true }), "report");
  assert.equal(
    cspMode({ EDULEARN_CSP: "enforce" }, { packaged: false, examShell: true }),
    "enforce",
  );
});

test("header name reflects report-only vs enforce", () => {
  assert.equal(
    buildCspHeader({ mode: "report" }).headerName,
    "Content-Security-Policy-Report-Only",
  );
  assert.equal(buildCspHeader({ mode: "enforce" }).headerName, "Content-Security-Policy");
});

// ---------------------------------------------------------------------------
// Policy: no unsafe-eval in packaged; no wildcards anywhere
// ---------------------------------------------------------------------------

test("VS-03: packaged script-src has NO 'unsafe-eval'", () => {
  const value = buildCspValue(["api.exam.edu"], { packaged: true });
  const scriptSrc = scriptSrcOf(value);
  assert.ok(scriptSrc.length > 0, "script-src directive must exist");
  assert.ok(
    !scriptSrc.includes("'unsafe-eval'"),
    `packaged script-src must not contain 'unsafe-eval': ${scriptSrc}`,
  );
  // unsafe-inline is RETAINED (documented Next.js nonce blocker).
  assert.ok(scriptSrc.includes("'unsafe-inline'"), "documented blocker: script unsafe-inline kept");
});

test("dev script-src retains 'unsafe-eval' (Next.js dev source maps / HMR)", () => {
  const scriptSrc = scriptSrcOf(buildCspValue(["api.exam.edu"], { packaged: false }));
  assert.ok(scriptSrc.includes("'unsafe-eval'"), `dev needs unsafe-eval: ${scriptSrc}`);
});

test("no wildcard sources in default-src / script-src / connect-src (packaged or dev)", () => {
  for (const packaged of [true, false]) {
    const value = buildCspValue(["api.exam.edu", "wss://rt.exam.edu"], { packaged });
    for (const directive of ["default-src", "script-src", "connect-src"]) {
      const d = value.split(";").map((s) => s.trim()).find((x) => x.startsWith(directive));
      assert.ok(d, `${directive} must exist`);
      assert.ok(!/\s\*(\s|$)/.test(` ${d} `), `${directive} must not contain a bare wildcard: ${d}`);
    }
  }
});

test("safe hardening directives present (object/frame-ancestors/base) incl base-uri 'none'", () => {
  const value = buildCspValue(["api.exam.edu"], { packaged: true });
  for (const directive of [
    "default-src 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "worker-src 'self' blob:",
  ]) {
    assert.match(value, new RegExp(directive.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&")));
  }
  // connect-src keeps 'self' + the allowed API host (widened with https:/wss: so
  // the hosted app can reach its API / Google without the shell over-blocking).
  assert.match(value, /connect-src 'self' api\.exam\.edu/);
  // frame-src mirrors the app's legitimate embeds (Google Maps / YouTube) rather
  // than 'none', so the shell doesn't block the hosted app's own content.
  assert.match(value, /frame-src[^;]*https:\/\/www\.youtube\.com/);
  assert.match(value, /frame-src[^;]*https:\/\/www\.google\.com/);
});

// ---------------------------------------------------------------------------
// connect-src normalization / validation
// ---------------------------------------------------------------------------

test("connect hosts are deduped and directive-breaking / wildcard tokens dropped", () => {
  const hosts = normalizeConnectHosts([
    "api.exam.edu",
    "api.exam.edu", // dup
    "  wss://rt.exam.edu  ", // trimmed
    "", // empty
    null,
    "*", // wildcard
    "*.evil.com", // wildcard
    "bad host", // whitespace -> dropped
    "inject';script-src *", // directive-breaking -> dropped
  ]);
  assert.deepEqual(hosts, ["api.exam.edu", "wss://rt.exam.edu"]);
  // The full value must not be corrupted by a malicious host.
  const value = buildCspValue(["ok.exam.edu", "x';object-src *"], { packaged: true });
  assert.ok(value.includes("connect-src 'self' ok.exam.edu"));
  assert.ok(!value.includes("x';object-src"), "injection token must not survive");
});

// ---------------------------------------------------------------------------
// installCsp header wiring: enforce header emitted, upstream CSP stripped,
// only one header, packaged exam-shell cannot fall back to report-only.
// ---------------------------------------------------------------------------

function fakeWin() {
  let handler = null;
  let handlerRegistrations = 0;
  return {
    _invoke: (details) => {
      let captured;
      handler(details, (res) => {
        captured = res;
      });
      return captured;
    },
    _registrations: () => handlerRegistrations,
    webContents: {
      session: {
        webRequest: {
          onHeadersReceived: (fn) => {
            handler = fn; // single-listener semantics: last wins
            handlerRegistrations += 1;
          },
        },
      },
    },
  };
}

test("installCsp on a packaged exam-shell emits enforcing CSP and strips upstream CSP", () => {
  const win = fakeWin();
  const result = installCsp(win, {
    connectHosts: ["api.exam.edu", "wss://rt.exam.edu"],
    packaged: true,
    examShell: true,
    env: {}, // no EDULEARN_CSP — must still enforce
  });
  assert.equal(result.mode, "enforce");
  assert.equal(result.headerName, "Content-Security-Policy");

  const out = win._invoke({
    responseHeaders: {
      "content-type": ["text/html"],
      "Content-Security-Policy-Report-Only": ["script-src 'unsafe-eval' *"],
      "content-security-policy": ["default-src *"],
    },
  });
  const keys = Object.keys(out.responseHeaders);
  // Exactly one CSP header, and it is the ENFORCING one.
  const cspKeys = keys.filter((k) => /^content-security-policy(-report-only)?$/i.test(k));
  assert.deepEqual(cspKeys, ["Content-Security-Policy"]);
  const emitted = out.responseHeaders["Content-Security-Policy"][0];
  assert.ok(!emitted.includes("'unsafe-eval'"), "packaged emitted CSP must have no unsafe-eval");
  assert.ok(emitted.includes("connect-src 'self' api.exam.edu wss://rt.exam.edu"));
  // Unrelated headers preserved.
  assert.deepEqual(out.responseHeaders["content-type"], ["text/html"]);
});

test("installCsp: an explicit EDULEARN_CSP=report can NOT downgrade a packaged exam-shell", () => {
  const win = fakeWin();
  const result = installCsp(win, {
    connectHosts: ["api.exam.edu"],
    packaged: true,
    examShell: true,
    env: { EDULEARN_CSP: "report" },
  });
  assert.equal(result.mode, "enforce");
  assert.equal(result.headerName, "Content-Security-Policy");
});

test("installCsp: dev exam-shell stays report-only by default (dry-run, non-breaking)", () => {
  const win = fakeWin();
  const result = installCsp(win, {
    connectHosts: ["api.exam.edu"],
    packaged: false,
    examShell: true,
    env: {},
  });
  assert.equal(result.mode, "report");
  assert.equal(result.headerName, "Content-Security-Policy-Report-Only");
});

test("VS-03 nonce: buildCspValue with a nonce drops unsafe-inline AND unsafe-eval", () => {
  for (const packaged of [true, false]) {
    const scriptSrc = scriptSrcOf(buildCspValue([], { packaged, nonce: "ABC123nonce" }));
    assert.ok(scriptSrc.includes("'nonce-ABC123nonce'"), `nonce present: ${scriptSrc}`);
    assert.ok(!scriptSrc.includes("'unsafe-inline'"), `no unsafe-inline: ${scriptSrc}`);
    assert.ok(!scriptSrc.includes("'unsafe-eval'"), `no unsafe-eval: ${scriptSrc}`);
  }
});

test("VS-03 nonce: installCsp harvests the Next.js nonce from the upstream CSP and re-emits it", () => {
  const win = fakeWin();
  installCsp(win, { connectHosts: ["api.exam.edu"], packaged: true, examShell: true, env: {} });
  const out = win._invoke({
    responseHeaders: {
      "content-type": ["text/html"],
      // Simulate the Next.js middleware's nonce CSP on the upstream response.
      "Content-Security-Policy": ["script-src 'self' 'nonce-Nx9keyFromNext' https://x"],
    },
  });
  const emitted = out.responseHeaders["Content-Security-Policy"][0];
  assert.ok(emitted.includes("'nonce-Nx9keyFromNext'"), "must preserve the upstream nonce");
  const scriptSrc = scriptSrcOf(emitted);
  assert.ok(!scriptSrc.includes("'unsafe-inline'"), "nonce mode drops script unsafe-inline");
  assert.ok(!scriptSrc.includes("'unsafe-eval'"), "nonce mode drops unsafe-eval");
});

test("VS-03 nonce: no upstream nonce => falls back to the unsafe-inline policy (unchanged)", () => {
  const win = fakeWin();
  installCsp(win, { connectHosts: [], packaged: true, examShell: true, env: {} });
  const out = win._invoke({ responseHeaders: { "content-type": ["text/html"] } });
  const scriptSrc = scriptSrcOf(out.responseHeaders["Content-Security-Policy"][0]);
  assert.ok(scriptSrc.includes("'unsafe-inline'"), "fallback keeps unsafe-inline when no nonce");
});

test("installCsp: re-registration replaces (no duplicate handlers accumulate)", () => {
  const win = fakeWin();
  installCsp(win, { connectHosts: [], packaged: true, examShell: true, env: {} });
  installCsp(win, { connectHosts: [], packaged: true, examShell: true, env: {} });
  // Two installs (exam-shell re-entry) => two registrations, but Electron keeps
  // only the last listener; our fake models that (single active handler).
  assert.equal(win._registrations(), 2);
  const out = win._invoke({ responseHeaders: {} });
  const cspKeys = Object.keys(out.responseHeaders).filter((k) =>
    /^content-security-policy(-report-only)?$/i.test(k),
  );
  assert.deepEqual(cspKeys, ["Content-Security-Policy"], "exactly one CSP header after re-entry");
});
