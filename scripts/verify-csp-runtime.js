"use strict";

// VS-03 runtime verifier — GROUND TRUTH, no DevTools / console-bypass confounders.
//
// Boots a real Electron BrowserWindow on our exam partition, serves a tiny HTML
// page over http (so installCsp's onHeadersReceived fires), and runs the CSP
// probes FROM THE PAGE'S OWN inline script (page context = real CSP applies,
// unlike the DevTools console which bypasses CSP). Reports PASS/FAIL.
//
// Run:  node_modules/.bin/electron scripts/verify-csp-runtime.js

const http = require("http");
const fs = require("fs");
const path = require("path");
const { app, BrowserWindow } = require("electron");
const { installCsp } = require("../src/protection/csp");

// Electron is a Windows GUI subsystem app: its stdout is NOT attached to the
// parent terminal, so results are written to a file (path via CSP_VERIFY_OUT or
// a default next to this script) AND echoed to console for good measure.
const OUT_FILE = process.env.CSP_VERIFY_OUT || path.join(__dirname, "..", "csp-verify-result.txt");
const lines = [];
function out(line) {
  lines.push(line);
  console.log(line);
}
function flush() {
  try { fs.writeFileSync(OUT_FILE, lines.join("\n") + "\n"); } catch {}
}

app.disableHardwareAcceleration();
app.commandLine.appendSwitch("disable-gpu");
app.commandLine.appendSwitch("no-sandbox");
// Prevent the default auto-quit when the first probe window is destroyed
// (before the second run opens its window) — otherwise the app exits early.
app.on("window-all-closed", () => {});

const PAGE = `<!doctype html><html><head><title>boot</title></head><body>
<script>
(function () {
  var r = { inlineRan: true, evalBlocked: null, offOriginBlocked: false, dataBlocked: false, violations: [] };
  document.addEventListener('securitypolicyviolation', function (e) {
    var b = String(e.blockedURI || '');
    r.violations.push(e.effectiveDirective + '|' + b.slice(0, 24));
    if (b === 'eval') r.evalBlocked = true;
    if (b.indexOf('evil.example') > -1) r.offOriginBlocked = true;
    if (b.indexOf('data') === 0) r.dataBlocked = true;
  });
  try { eval('1+1'); if (r.evalBlocked === null) r.evalBlocked = false; } catch (e) { r.evalBlocked = true; }
  var s1 = document.createElement('script'); s1.src = 'https://evil.example/x.js'; document.body.appendChild(s1);
  var s2 = document.createElement('script'); s2.src = 'data:text/javascript,window.__D=1'; document.body.appendChild(s2);
  setTimeout(function () { document.title = 'CSPRESULT:' + JSON.stringify(r); }, 400);
})();
</script>
</body></html>`;

function run(packaged) {
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.end(PAGE);
    });
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      const win = new BrowserWindow({
        show: false,
        webPreferences: { partition: `temp:cspverify-${packaged}` },
      });
      const meta = installCsp(win, {
        connectHosts: ["api.edulearn.vn", "wss://api.edulearn.vn"],
        packaged,
        examShell: true,
        env: {},
      });
      let done = false;
      const finish = (title) => {
        if (done) return;
        done = true;
        try { server.close(); } catch {}
        try { if (!win.isDestroyed()) win.destroy(); } catch {}
        resolve({ mode: meta.mode, headerName: meta.headerName, title });
      };
      win.webContents.on("page-title-updated", (_e, t) => {
        if (t.startsWith("CSPRESULT:")) finish(t);
      });
      setTimeout(() => finish("(timeout)"), 6000);
      win.loadURL(`http://127.0.0.1:${port}/`);
    });
  });
}

app.whenReady().then(async () => {
  const parse = (x) => {
    try { return JSON.parse(x.title.replace("CSPRESULT:", "")); } catch { return { raw: x.title }; }
  };
  const dev = await run(false);
  const pkg = await run(true);
  const d = parse(dev);
  const p = parse(pkg);

  out("\n================ CSP RUNTIME VERIFY ================");
  out(`DEV      header: ${dev.headerName}`);
  out(`   inlineRan=${d.inlineRan} evalBlocked=${d.evalBlocked} offOriginBlocked=${d.offOriginBlocked} dataBlocked=${d.dataBlocked}`);
  out(`   violations: ${JSON.stringify(d.violations)}`);
  out(`PACKAGED header: ${pkg.headerName}`);
  out(`   inlineRan=${p.inlineRan} evalBlocked=${p.evalBlocked} offOriginBlocked=${p.offOriginBlocked} dataBlocked=${p.dataBlocked}`);
  out(`   violations: ${JSON.stringify(p.violations)}`);

  const checks = [
    ["PACKAGED header is enforcing (Content-Security-Policy)", pkg.headerName === "Content-Security-Policy"],
    ["PACKAGED blocks eval() (no 'unsafe-eval')", p.evalBlocked === true],
    ["PACKAGED blocks off-origin script (script-src 'self')", p.offOriginBlocked === true],
    ["PACKAGED blocks data: script", p.dataBlocked === true],
    ["PACKAGED allows inline script (documented 'unsafe-inline')", p.inlineRan === true],
    ["DEV allows eval() ('unsafe-eval' present by design)", d.evalBlocked === false],
    ["DEV still blocks off-origin script", d.offOriginBlocked === true],
  ];

  out("\n----------------- VERDICT -----------------");
  let all = true;
  for (const [name, ok] of checks) {
    out(`${ok ? "PASS" : "FAIL"}  ${name}`);
    if (!ok) all = false;
  }
  out(all ? "\n>>> ALL CHECKS PASSED — CSP is enforced at runtime.\n" : "\n>>> SOME CHECKS FAILED — see above.\n");
  flush();
  app.exit(all ? 0 : 1);
});
