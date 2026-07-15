"use strict";

// VS-04 runtime verifier — proves the BUNDLED preload loads and works under
// webPreferences.sandbox:true: the contextBridge worlds are exposed (so the
// preload executed fully without a require/Node error), the exam-shell identity +
// session/code arrive via argv (not process.env), and an ipcRenderer.invoke
// round-trips to a main handler. Results are written to a file (Electron GUI
// stdout is not attached to the terminal on Windows).
//
// Run:  node_modules/.bin/electron scripts/verify-sandbox-preload.js

const fs = require("fs");
const path = require("path");
const { app, BrowserWindow, ipcMain } = require("electron");

app.disableHardwareAcceleration();
app.commandLine.appendSwitch("disable-gpu");
app.commandLine.appendSwitch("no-sandbox"); // OS-level test sandbox off; Electron sandbox:true still exercised
app.on("window-all-closed", () => {});

const OUT_FILE = process.env.SANDBOX_VERIFY_OUT || path.join(__dirname, "..", "sandbox-verify-result.txt");
const lines = [];
const out = (s) => { lines.push(s); console.log(s); };
const flush = () => { try { fs.writeFileSync(OUT_FILE, lines.join("\n") + "\n"); } catch {} };

// A channel the preload invokes directly (desktopOAuth.getPendingCallback).
ipcMain.handle("desktop-oauth:get-pending", () => ({ pong: true }));

const PAGE =
  "data:text/html," +
  encodeURIComponent(
    "<title>boot</title><body><script>(async function(){" +
      "var r={hasRuntime:!!window.desktopRuntime,hasCore:!!window.desktopCore," +
      "hasExam:!!window.desktopExam,hasOAuth:!!window.desktopOAuth," +
      "isExamShell:!!(window.desktopExam&&window.desktopExam.isExamShell)," +
      "sessionId:window.desktopExam&&window.desktopExam.sessionId," +
      "examCode:window.desktopExam&&window.desktopExam.examCode,ipcOk:false};" +
      "try{var res=await window.desktopOAuth.getPendingCallback();r.ipcOk=!!(res&&res.pong);}" +
      "catch(e){r.ipcErr=String(e);}" +
      "document.title='SBX:'+JSON.stringify(r);" +
      "})();</script></body>",
  );

app.whenReady().then(() => {
  const bundled = path.join(__dirname, "..", "dist", "preload.js");
  if (!fs.existsSync(bundled)) {
    out("FAIL  dist/preload.js not found — run `npm run build:preload` first");
    flush();
    app.exit(1);
    return;
  }
  const win = new BrowserWindow({
    show: false,
    webPreferences: {
      preload: bundled,
      sandbox: true, // <-- the VS-04 target
      contextIsolation: true,
      nodeIntegration: false,
      additionalArguments: [
        "--edulearn-cap-token=TESTTOKEN",
        "--edulearn-exam-shell=1",
        "--edulearn-exam-session=S123",
        "--edulearn-exam-code=EXAM9",
      ],
    },
  });

  let done = false;
  const finish = (title) => {
    if (done) return;
    done = true;
    let r = {};
    try { r = JSON.parse(title.replace("SBX:", "")); } catch { r = { raw: title }; }

    out("\n================ SANDBOX PRELOAD VERIFY (sandbox:true) ================");
    out(`bridges: runtime=${r.hasRuntime} core=${r.hasCore} exam=${r.hasExam} oauth=${r.hasOAuth}`);
    out(`argv identity: isExamShell=${r.isExamShell} sessionId=${r.sessionId} examCode=${r.examCode}`);
    out(`ipc round-trip: ipcOk=${r.ipcOk}${r.ipcErr ? " err=" + r.ipcErr : ""}`);

    const checks = [
      ["bundled preload exposed all contextBridge worlds under sandbox:true",
        r.hasRuntime && r.hasCore && r.hasExam && r.hasOAuth],
      ["exam-shell identity delivered via argv (isExamShell)", r.isExamShell === true],
      ["sessionId delivered via argv (not process.env)", r.sessionId === "S123"],
      ["examCode delivered via argv (not process.env)", r.examCode === "EXAM9"],
      ["ipcRenderer.invoke round-trips under sandbox", r.ipcOk === true],
    ];
    out("\n----------------- VERDICT -----------------");
    let all = true;
    for (const [name, ok] of checks) {
      out(`${ok ? "PASS" : "FAIL"}  ${name}`);
      if (!ok) all = false;
    }
    out(all ? "\n>>> ALL CHECKS PASSED — sandbox:true works with the bundled preload.\n" : "\n>>> SOME CHECKS FAILED.\n");
    flush();
    try { win.destroy(); } catch {}
    app.exit(all ? 0 : 1);
  };

  win.webContents.on("page-title-updated", (_e, t) => {
    if (t.startsWith("SBX:")) finish(t);
  });
  setTimeout(() => finish("(timeout)"), 8000);
  win.loadURL(PAGE);
});
