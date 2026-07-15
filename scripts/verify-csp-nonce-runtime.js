"use strict";

// VS-03 (nonce) runtime verifier — proves the packaged exam-shell HARVESTS the
// Next.js per-request nonce from the upstream CSP and re-emits a policy that DROPS
// script 'unsafe-inline': a nonced inline script runs, a NON-nonced inline script
// is blocked, and eval is blocked — all under a real enforcing Electron CSP.
// Results are written to a file (Electron GUI stdout isn't attached on Windows).
//
// Run:  node_modules/.bin/electron scripts/verify-csp-nonce-runtime.js

const http = require("http");
const fs = require("fs");
const path = require("path");
const { app, BrowserWindow } = require("electron");
const { installCsp } = require("../src/protection/csp");

app.disableHardwareAcceleration();
app.commandLine.appendSwitch("disable-gpu");
app.commandLine.appendSwitch("no-sandbox");
app.on("window-all-closed", () => {});

const OUT_FILE = process.env.CSP_NONCE_OUT || path.join(__dirname, "..", "csp-nonce-result.txt");
const lines = [];
const out = (s) => { lines.push(s); console.log(s); };
const flush = () => { try { fs.writeFileSync(OUT_FILE, lines.join("\n") + "\n"); } catch {} };

const NONCE = "THENONCE12345678";
// The page: a NONCED probe script (should run) + a NON-nonced script (should be
// blocked when unsafe-inline is dropped). The probe reports via document.title.
const PAGE =
  "<!doctype html><html><body>" +
  `<script>window.__nonNoncedRan=true;</script>` +
  `<script nonce="${NONCE}">(function(){` +
  "var r={noncedRan:true,nonNoncedRan:!!window.__nonNoncedRan,evalBlocked:null,violations:[]};" +
  "document.addEventListener('securitypolicyviolation',function(e){r.violations.push(e.effectiveDirective+'|'+String(e.blockedURI).slice(0,10));if(e.blockedURI==='eval')r.evalBlocked=true;});" +
  "try{eval('1+1');if(r.evalBlocked===null)r.evalBlocked=false;}catch(e){r.evalBlocked=true;}" +
  "setTimeout(function(){document.title='NONCE:'+JSON.stringify(r);},400);" +
  "})();</script>" +
  "</body></html>";

app.whenReady().then(() => {
  const server = http.createServer((_req, res) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    // Simulate the Next.js middleware emitting a per-request nonce CSP upstream.
    res.setHeader(
      "Content-Security-Policy",
      `default-src 'self'; script-src 'self' 'nonce-${NONCE}'`,
    );
    res.end(PAGE);
  });
  server.listen(0, "127.0.0.1", () => {
    const port = server.address().port;
    const win = new BrowserWindow({ show: false, webPreferences: { partition: "temp:cspnonce" } });
    const meta = installCsp(win, {
      connectHosts: ["api.exam.edu"],
      packaged: true,
      examShell: true,
      env: {},
    });
    let done = false;
    const finish = (title) => {
      if (done) return;
      done = true;
      try { server.close(); } catch {}
      let r = {};
      try { r = JSON.parse(String(title).replace("NONCE:", "")); } catch { r = { raw: title }; }

      out("\n================ CSP NONCE RUNTIME VERIFY ================");
      out(`emitted header: ${meta.headerName}`);
      out(`noncedRan=${r.noncedRan} nonNoncedRan=${r.nonNoncedRan} evalBlocked=${r.evalBlocked}`);
      out(`violations: ${JSON.stringify(r.violations)}`);

      const checks = [
        ["exam-shell emits an ENFORCING CSP", meta.headerName === "Content-Security-Policy"],
        ["nonced inline script RUNS (nonce harvested + preserved)", r.noncedRan === true],
        ["NON-nonced inline script is BLOCKED (unsafe-inline dropped)", r.nonNoncedRan === false],
        ["eval() is blocked under the nonce policy", r.evalBlocked === true],
      ];
      out("\n----------------- VERDICT -----------------");
      let all = true;
      for (const [name, ok] of checks) {
        out(`${ok ? "PASS" : "FAIL"}  ${name}`);
        if (!ok) all = false;
      }
      out(all ? "\n>>> ALL CHECKS PASSED — nonce CSP drops script unsafe-inline at runtime.\n" : "\n>>> SOME CHECKS FAILED.\n");
      flush();
      try { win.destroy(); } catch {}
      app.exit(all ? 0 : 1);
    };
    win.webContents.on("page-title-updated", (_e, t) => {
      if (String(t).startsWith("NONCE:")) finish(t);
    });
    setTimeout(() => finish("(timeout)"), 6000);
    win.loadURL(`http://127.0.0.1:${port}/`);
  });
});
