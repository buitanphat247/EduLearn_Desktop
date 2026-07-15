"use strict";

// VS-04 runtime verifier — proves at REAL Electron runtime that:
//   1. webPreferences.devTools:false actually prevents openDevTools() (the
//      packaged exam-shell setting), and
//   2. the devtools-opened -> closeDevTools() guard slams it shut even if a
//      window somehow had DevTools enabled (defense-in-depth), and
//   3. a control window with devTools:true DOES open (so the test is meaningful).
//
// Electron on Windows is a GUI-subsystem app whose stdout is not attached to the
// parent terminal, so results are written to a file.
//
// Run:  node_modules/.bin/electron scripts/verify-devtools-runtime.js

const fs = require("fs");
const path = require("path");
const { app, BrowserWindow } = require("electron");

app.disableHardwareAcceleration();
app.commandLine.appendSwitch("disable-gpu");
app.commandLine.appendSwitch("no-sandbox");
app.on("window-all-closed", () => {});

const OUT_FILE = process.env.DEVTOOLS_VERIFY_OUT || path.join(__dirname, "..", "devtools-verify-result.txt");
const lines = [];
const out = (s) => { lines.push(s); console.log(s); };
const flush = () => { try { fs.writeFileSync(OUT_FILE, lines.join("\n") + "\n"); } catch {} };

const PAGE = "data:text/html,<title>t</title><body>probe</body>";
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

// Load the window, attach a devtools-opened watcher, call openDevTools(), then
// report whether the 'devtools-opened' EVENT fired (the reliable "DevTools was
// allowed to open" signal in headless) and the final isDevToolsOpened() state.
function probe(opts, { guard = false } = {}) {
  return new Promise((resolve) => {
    const win = new BrowserWindow({ show: false, webPreferences: opts });
    let openedEvent = false;
    win.webContents.on("devtools-opened", () => {
      openedEvent = true;
      if (guard) {
        try { win.webContents.closeDevTools(); } catch {}
      }
    });
    win.webContents.once("did-finish-load", async () => {
      try { win.webContents.openDevTools({ mode: "detach" }); } catch {}
      await delay(1500);
      const state = { openedEvent, isOpen: win.webContents.isDevToolsOpened() };
      try { win.destroy(); } catch {}
      resolve(state);
    });
    win.loadURL(PAGE);
  });
}

app.whenReady().then(async () => {
  // Case 1: devTools:false — openDevTools() must be a no-op (no event, not open).
  const c1 = await probe({ devTools: false, contextIsolation: true, nodeIntegration: false });
  // Case 2: control — devTools:true, the devtools-opened event MUST fire.
  const c2 = await probe({ devTools: true, contextIsolation: true, nodeIntegration: false });
  // Case 3: devTools:true BUT guard closes on open -> event fires, ends closed.
  const c3 = await probe({ devTools: true, contextIsolation: true, nodeIntegration: false }, { guard: true });

  out("\n================ DEVTOOLS RUNTIME VERIFY ================");
  out(`Case 1  devTools:false          -> openedEvent=${c1.openedEvent} isOpen=${c1.isOpen}  (expect false/false)`);
  out(`Case 2  devTools:true (control) -> openedEvent=${c2.openedEvent} isOpen=${c2.isOpen}  (expect event=true)`);
  out(`Case 3  guard closes on open    -> openedEvent=${c3.openedEvent} isOpen=${c3.isOpen}  (expect event=true, isOpen=false)`);

  const checks = [
    ["devTools:false blocks openDevTools() — no open event, never open", c1.openedEvent === false && c1.isOpen === false],
    ["control window with devTools:true DOES fire devtools-opened (test is meaningful)", c2.openedEvent === true],
    ["devtools-opened guard closes DevTools (defense-in-depth): opened then closed", c3.openedEvent === true && c3.isOpen === false],
  ];
  out("\n----------------- VERDICT -----------------");
  let all = true;
  for (const [name, ok] of checks) {
    out(`${ok ? "PASS" : "FAIL"}  ${name}`);
    if (!ok) all = false;
  }
  out(all ? "\n>>> ALL CHECKS PASSED — DevTools lockdown works at runtime.\n" : "\n>>> SOME CHECKS FAILED.\n");
  flush();
  app.exit(all ? 0 : 1);
});
