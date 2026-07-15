const { BrowserWindow, screen, app } = require("electron");
const path = require("path");
const fs = require("fs");
const { installUrlFilter } = require("./protection/url-filter");
const {
  resolveSignedAllowlistFromEnv,
} = require("./protection/signed-allowlist-source");
const { installCsp } = require("./protection/csp");
const { isExamShellCloseAllowed } = require("./exam-desktop-launcher");
const {
  capabilityTokenLaunchArg,
  EXAM_SHELL_LAUNCH_ARG,
  examShellIdentityLaunchArgs,
} = require("./capability-token");

function resolveStartUrl() {
  return process.env.ELECTRON_START_URL || "http://localhost:3000";
}

// VS-04: prefer the esbuild-BUNDLED preload (a single self-contained file with no
// local `require()`), which lets the window run with `sandbox:true`. Fall back to
// the raw src preload with `sandbox:false` when the bundle is absent (e.g. a plain
// dev run that skipped `npm run build:preload`) so development is never broken. The
// packaged build always bundles (see the `package` script), so shipped exam-shells
// are sandboxed.
function resolvePreload() {
  const bundled = path.join(__dirname, "..", "dist", "preload.js");
  try {
    if (fs.existsSync(bundled)) {
      return { preloadPath: bundled, sandbox: true };
    }
  } catch {
    /* fall through to the unbundled preload */
  }
  return { preloadPath: path.join(__dirname, "preload.js"), sandbox: false };
}

function createMainWindow() {
  // The isolated exam-shell fills its dedicated desktop as a frameless
  // fullscreen window (SEB-style) so there is no black strip / OS chrome; its
  // own bottom control bar (rendered by the room UI) provides reload/exit.
  const isExamShell = process.env.EDULEARN_EXAM_SHELL === "1";
  const { preloadPath, sandbox } = resolvePreload();

  const win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1200,
    minHeight: 760,
    show: false,
    autoHideMenuBar: true,
    fullscreen: isExamShell,
    frame: !isExamShell,
    backgroundColor: "#ffffff",
    webPreferences: {
      preload: preloadPath,
      contextIsolation: true,
      // VS-04 sandbox: enabled when running the BUNDLED preload (a single
      // self-contained esbuild output with no local require() and no load-time
      // Node built-ins — crypto/fs/logger were pruned/lazified, and exam-shell
      // identity + session/code are delivered via argv, not process.env). The raw
      // src preload can't be sandboxed (it require()s local files), so it falls
      // back to sandbox:false for a bundle-less dev run. Packaged builds always
      // bundle, so shipped exam-shells run sandboxed.
      sandbox,
      nodeIntegration: false,
      webSecurity: true,
      // Hardening: no <webview> embedding (an injected <webview> would bypass the
      // window's guards) and no in-page spellcheck network calls.
      webviewTag: false,
      spellcheck: false,
      // VS-04 DevTools lockdown: the packaged exam-shell can NEVER open DevTools
      // (an exam candidate must not inspect state/tokens/IPC or hide overlays).
      // Dev and the packaged lobby keep DevTools for debugging. A `devtools-opened`
      // guard below closes it as defense-in-depth if any path still tries.
      devTools: !(app.isPackaged && isExamShell),
      // C3: hand this launch's capability token to the preload only. It lands in
      // process.argv (readable by the isolated-world preload, NOT the untrusted
      // page), and the preload attaches it to every privileged desktop-core IPC
      // call so main can prove the call came through our bundled bridge.
      //
      // Defense-in-depth for the exam-shell identity: the room's disconnect
      // safety + exit UI hinge on `window.desktopExam.isExamShell`. Deliver it
      // through the same robust argv channel as the token (not only process.env)
      // so a stripped/unpropagated env var can never silently flip a genuine
      // isolated shell into the trapping in-window mode.
      // VS-04: also deliver session id + exam code via argv (read from env in the
      // main process, where env IS available) so the sandboxed preload — whose
      // process.env is unreliable — can still expose window.desktopExam.sessionId
      // / examCode.
      additionalArguments: isExamShell
        ? [
            capabilityTokenLaunchArg(),
            EXAM_SHELL_LAUNCH_ARG,
            ...examShellIdentityLaunchArgs(
              process.env.EDULEARN_EXAM_SHELL_SESSION_ID,
              process.env.EDULEARN_EXAM_SHELL_EXAM_CODE,
            ),
          ]
        : [capabilityTokenLaunchArg()],
      // Dedicated persistent partition so the exam window has its own session:
      // the URL-filter's webRequest hooks are isolated from the process-global
      // defaultSession (which any other component could otherwise clobber), while
      // storage/cookies still persist across an in-session relaunch.
      partition: "persist:edulearn-exam",
    },
  });

  // Capture protection: make this window's pixels appear BLACK in any screen
  // capture, recording or remote-desktop share (Windows WDA_EXCLUDEFROMCAPTURE via
  // Electron). Applied to EVERY mode — lobby, in-window kiosk AND the isolated
  // exam-shell — so if a remote-control / screen-share tool is running, the other
  // side only ever sees black where the exam is. This is why such tools no longer
  // need to be killed to enter: they are neutralised, not removed.
  if (typeof win.setContentProtection === "function") {
    win.setContentProtection(true);
  }

  // VS-04 defense-in-depth: even though `devTools:false` is set for the packaged
  // exam-shell, slam DevTools shut immediately if any future code path / bug
  // manages to open it. Dev and the packaged lobby are untouched.
  if (app.isPackaged && isExamShell) {
    win.webContents.on("devtools-opened", () => {
      try {
        win.webContents.closeDevTools();
      } catch {
        /* closing DevTools must never break the exam-shell */
      }
    });
  }

  // Remove the native menu completely so pressing Alt cannot surface the
  // Windows menu bar during the exam desktop flow.
  if (typeof win.removeMenu === "function") {
    win.removeMenu();
  } else {
    win.setMenuBarVisibility(false);
  }

  // Keep the exam-shell above stray floating OS chrome (e.g. the Windows TSF
  // language bar that appears on a taskbar-less isolated desktop). "screen-saver"
  // is a high always-on-top band so it sits over most topmost windows.
  if (isExamShell) {
    win.setAlwaysOnTop(true, "screen-saver");
  }

  const startUrl = resolveStartUrl();

  // Restrict the exam window to the approved origin (SEB-style URL allow-list):
  // block requests/navigation to non-allow-listed hosts and deny all popups.
  // Defaults to report-only mode; set EDULEARN_URL_FILTER=enforce to block.
  // P47-03: fold in the server-signed URL allowlist the launcher handed us (if
  // any). installUrlFilter verifies its Ed25519 signature and only then widens
  // the reachable-host set; a tampered/unsigned/expired blob is refused + logged.
  const { allowlist, mode, telemetry, signedAllowlistStatus } = installUrlFilter(win, {
    startUrl,
    signedAllowlist: resolveSignedAllowlistFromEnv(),
    onBlocked: ({ kind, url, blocked }) => {
      const action = blocked ? "blocked" : "flagged (report-only)";
      console.warn(`[desktop] url-filter ${action} ${kind}: ${url}`);
    },
  });
  console.log(
    `[desktop] url-filter mode=${mode} signed-allowlist=${signedAllowlistStatus} allow-list: ${[...allowlist].join(", ")}`,
  );

  // VS-03 / F-006: attach a Content-Security-Policy to the exam window's
  // responses. A PACKAGED exam-shell ALWAYS enforces (a missing/relaxed
  // EDULEARN_CSP can never downgrade it to report-only) and drops 'unsafe-eval';
  // dev/lobby stays report-only unless EDULEARN_CSP=enforce. connect-src is
  // widened to the same hosts the URL-filter allows so the API/WSS keeps working.
  const csp = installCsp(win, {
    connectHosts: [...allowlist],
    packaged: app.isPackaged,
    examShell: isExamShell,
  });
  console.log(
    `[desktop] CSP mode=${csp.mode} (${csp.headerName}) packaged=${csp.packaged} examShell=${isExamShell}`,
  );

  // Surface the URL-filter telemetry periodically so blocks are observable
  // (structured counts, not just per-event console lines).
  win.webContents.on("did-finish-load", () => {
    console.log(
      `[desktop] url-filter telemetry: blocked=${telemetry.blocked} flagged=${telemetry.flagged} byKind=${JSON.stringify(telemetry.byKind)}`,
    );
  });

  let hasShownWindow = false;

  // If the exam window opened on a SECONDARY monitor, move it onto the OS primary
  // display before showing. The exam must live on the main screen (secondary
  // monitors are blacked out with overlays), so a window stranded on a side
  // monitor is pulled back to the primary. Never allowed to throw / block show.
  const moveToPrimaryDisplay = () => {
    try {
      if (win.isDestroyed() || win.isFullScreen()) {
        return;
      }
      const primary = screen.getPrimaryDisplay();
      const current = screen.getDisplayMatching(win.getBounds());
      if (current && current.id !== primary.id) {
        const { x, y, width, height } = primary.workArea;
        win.setBounds({ x, y, width, height });
        console.log("[desktop] moved exam window from a secondary display to the primary");
      }
    } catch (error) {
      console.warn("[desktop] moveToPrimaryDisplay failed (continuing)", error);
    }
  };

  const showWindow = () => {
    if (hasShownWindow || win.isDestroyed()) {
      return;
    }

    hasShownWindow = true;
    // Pull the window onto the primary display first (in case it opened on a side
    // monitor), then present it.
    moveToPrimaryDisplay();
    // Fullscreen already fills the exam desktop; only maximize the framed lobby.
    if (process.platform === "win32" && !isExamShell) {
      win.maximize();
    }

    win.show();
  };

  // A display topology change (plug/unplug a monitor) can strand the window on a
  // now-secondary screen mid-exam — pull it back to the primary.
  const onDisplayChange = () => moveToPrimaryDisplay();
  screen.on("display-metrics-changed", onDisplayChange);
  screen.on("display-removed", onDisplayChange);
  screen.on("display-added", onDisplayChange);
  win.on("closed", () => {
    screen.removeListener("display-metrics-changed", onDisplayChange);
    screen.removeListener("display-removed", onDisplayChange);
    screen.removeListener("display-added", onDisplayChange);
  });

  win.once("ready-to-show", () => {
    showWindow();
  });

  win.webContents.on("did-fail-load", (_event, errorCode, errorDescription, validatedURL) => {
    console.error("[desktop] Failed to load renderer", {
      errorCode,
      errorDescription,
      validatedURL,
    });
    showWindow();
  });

  win.webContents.on("did-finish-load", () => {
    console.log(`[desktop] Renderer loaded: ${startUrl}`);
  });

  // If the renderer takes too long, still show the shell so it does not look stuck.
  setTimeout(() => {
    showWindow();
  }, 3000);

  // Deny EVERY web permission for the locked exam room. Screen proctoring was
  // removed, so the room needs no camera/mic/geolocation/display-capture at all —
  // default-deny is the safest posture (Chromium would otherwise auto-approve some
  // permissions). Applied to THIS window's own session, in every entry mode.
  //
  // CRITICAL: this MUST NOT be able to throw — it runs before `win.loadURL`, so any
  // exception here would abort createMainWindow. Wrap defensively so it can never
  // block the candidate from entering the exam.
  try {
    const examSession = win.webContents.session;
    if (typeof examSession.setPermissionRequestHandler === "function") {
      examSession.setPermissionRequestHandler((_wc, _permission, callback) => {
        callback(false);
      });
    }
    if (typeof examSession.setPermissionCheckHandler === "function") {
      examSession.setPermissionCheckHandler(() => false);
    }
  } catch (error) {
    console.error(
      "[desktop] permission handler setup failed (continuing to load the room)",
      error,
    );
  }

  if (isExamShell) {
    // Chromium-level keyboard lockdown (defense-in-depth over the preload
    // filter): suppress every Ctrl/Alt/Meta shortcut combo, F1–F12 and
    // PrintScreen before they reach the page. Plain keys and Shift+key (typing)
    // pass through so answers/passwords can still be entered.
    win.webContents.on("before-input-event", (event, input) => {
      if (input.type !== "keyDown") {
        return;
      }
      const key = input.key || "";
      const isCombo = input.control || input.alt || input.meta;
      const isFunctionKey = /^F\d{1,2}$/.test(key);
      const isBlockedSingle =
        key === "PrintScreen" || key === "ContextMenu" || key === "Meta";
      if (isCombo || isFunctionKey || isBlockedSingle) {
        event.preventDefault();
      }
    });

    // Block Alt+F4 / the window X so a student cannot bail out of the exam. A
    // real exit (password-verified) sets the allow flag before quitting.
    win.on("close", (event) => {
      if (!isExamShellCloseAllowed()) {
        event.preventDefault();
      }
    });
  }

  console.log(`[desktop] Loading renderer URL: ${startUrl}`);
  win.loadURL(startUrl);
  return win;
}

module.exports = {
  createMainWindow,
};
