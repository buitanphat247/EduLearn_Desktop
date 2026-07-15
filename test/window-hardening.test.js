"use strict";

// Regression guard (VS-03 scope): assert the exam window keeps its existing
// Electron hardening and that CSP is wired to enforce for a packaged exam-shell.
// window.js needs a live Electron runtime to construct a BrowserWindow, so these
// checks are source-level — they fail loudly if a future edit weakens the flags.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const windowSrc = fs.readFileSync(
  path.join(__dirname, "..", "src", "window.js"),
  "utf8",
);
const overlaySrc = fs.readFileSync(
  path.join(__dirname, "..", "src", "protection", "overlay-manager.js"),
  "utf8",
);

test("VS-03/regression: exam window keeps its hardening flags unchanged", () => {
  assert.match(windowSrc, /contextIsolation:\s*true/, "contextIsolation must stay true");
  assert.match(windowSrc, /nodeIntegration:\s*false/, "nodeIntegration must stay false");
  assert.match(windowSrc, /webSecurity:\s*true/, "webSecurity must stay true");
  assert.match(windowSrc, /webviewTag:\s*false/, "webviewTag must stay false");
  // These must never be weakened.
  assert.doesNotMatch(windowSrc, /webSecurity:\s*false/);
  assert.doesNotMatch(windowSrc, /allowRunningInsecureContent:\s*true/);
  assert.doesNotMatch(windowSrc, /nodeIntegration:\s*true/);
  assert.doesNotMatch(windowSrc, /contextIsolation:\s*false/);
});

test("VS-03: CSP install passes packaged + examShell so a packaged shell enforces", () => {
  assert.match(
    windowSrc,
    /installCsp\(win,\s*\{[\s\S]*packaged:\s*app\.isPackaged[\s\S]*examShell:\s*isExamShell[\s\S]*\}\)/,
    "installCsp must receive packaged:app.isPackaged and examShell:isExamShell",
  );
});

test("VS-04: packaged exam-shell disables DevTools at the BrowserWindow level", () => {
  // devTools is false exactly when packaged AND exam-shell; dev + packaged lobby keep it.
  assert.match(
    windowSrc,
    /devTools:\s*!\(app\.isPackaged\s*&&\s*isExamShell\)/,
    "webPreferences must set devTools:!(app.isPackaged && isExamShell)",
  );
  // Must never hard-enable DevTools for the exam-shell.
  assert.doesNotMatch(windowSrc, /devTools:\s*true/);
});

test("VS-04: defense-in-depth guard closes DevTools if opened in packaged exam-shell", () => {
  assert.match(windowSrc, /devtools-opened/, "must listen for devtools-opened");
  assert.match(windowSrc, /closeDevTools\(\)/, "must call closeDevTools()");
  // The guard is gated to packaged exam-shell only (dev workflow untouched).
  assert.match(
    windowSrc,
    /if\s*\(app\.isPackaged\s*&&\s*isExamShell\)\s*\{[\s\S]*devtools-opened[\s\S]*closeDevTools/,
    "devtools-opened guard must be gated on app.isPackaged && isExamShell",
  );
});

test("VS-04: no DevTools programmatic entry points remain in window.js", () => {
  assert.doesNotMatch(windowSrc, /\.openDevTools\(/, "no openDevTools() call may exist");
  assert.doesNotMatch(windowSrc, /\.toggleDevTools\(/, "no toggleDevTools() call may exist");
});

test("VS-04: overlay covers are sandboxed with DevTools disabled", () => {
  assert.match(overlaySrc, /sandbox:\s*true/, "overlay windows (no preload) must be sandboxed");
  assert.match(overlaySrc, /devTools:\s*false/, "overlay windows must disable DevTools");
  assert.match(overlaySrc, /contextIsolation:\s*true/);
  assert.match(overlaySrc, /nodeIntegration:\s*false/);
});

test("VS-04: main window runs the BUNDLED preload with sandbox enabled when present", () => {
  // resolvePreload prefers dist/preload.js with sandbox:true, falling back to the
  // raw src preload with sandbox:false — never hard-coding sandbox:false again.
  assert.match(windowSrc, /"dist",\s*"preload\.js"/, "resolvePreload targets the bundled preload");
  assert.match(windowSrc, /return\s*\{\s*preloadPath:\s*bundled,\s*sandbox:\s*true\s*\}/);
  assert.match(windowSrc, /preload:\s*preloadPath/, "webPreferences.preload uses the resolved path");
  assert.match(windowSrc, /\bsandbox,\s*\r?\n/, "webPreferences.sandbox uses the resolved flag");
  // Must never statically re-disable the other hardening flags.
  assert.doesNotMatch(windowSrc, /nodeIntegration:\s*true/);
  assert.doesNotMatch(windowSrc, /contextIsolation:\s*false/);
});
