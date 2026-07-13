const fs = require("fs");
const path = require("path");
const { app, BrowserWindow, globalShortcut } = require("electron");

// Earliest-possible SYNCHRONOUS crash capture. The exam-shell (a 2nd Electron
// process spawned onto the isolated desktop) has been dying before it logs
// anything — the async JSONL logger buffer is lost on a hard crash. Write, with
// fs.appendFileSync, a boot marker + any uncaught error to a dedicated file so a
// shell that never reaches the room still tells us exactly how far it got and
// why. Wrapped so this diagnostic can never itself break boot.
(function installEarlyCrashCapture() {
  const tag = process.env.EDULEARN_EXAM_SHELL === "1" ? "exam-shell" : "lobby";
  const crashFile = path.join(
    process.env.APPDATA || process.env.HOME || __dirname,
    "edulearn-desktop",
    "shell-crash.log",
  );
  const write = (kind, detail) => {
    try {
      fs.appendFileSync(
        crashFile,
        `${new Date().toISOString()} [${tag}] pid=${process.pid} ${kind}: ${detail}\n`,
      );
    } catch {
      /* diagnostics must never throw */
    }
  };
  write(
    "boot",
    `main.js started start=${process.env.ELECTRON_START_URL || "(default)"}`,
  );
  process.on("uncaughtException", (err) =>
    write("uncaughtException", err && err.stack ? err.stack : String(err)),
  );
  process.on("unhandledRejection", (reason) =>
    write(
      "unhandledRejection",
      reason && reason.stack ? reason.stack : String(reason),
    ),
  );
  global.__eduWriteCrash = write;
})();
const { createMainWindow } = require("./window");
const { handleDeepLink, registerProtocol } = require("./deeplink");
const { registerDesktopOAuthIpc, registerDesktopCoreIpc } = require("./ipc");
const { createDesktopCoreRuntime } = require("./core-runtime");
const { createDesktopProtectionController } = require("./protection-controller");
const { DESKTOP_CORE_CHANNELS } = require("./contracts/safe-exam");
const { createWatchdogHeartbeat } = require("./watchdog-heartbeat");
const { logger, resolveLoggerBaseDir } = require("./logger");
const { createExamGuardTracer } = require("./exam-guard-trace");
const { createAudioGuard } = require("./audio-guard");
const { verifyPackagedAppIntegrity } = require("./app-integrity");
const {
  isExamShellProcess,
  switchBackToDefaultDesktop,
  allowExamShellClose,
} = require("./exam-desktop-launcher");
const {
  importExamSessionCookies,
  cleanupStaleSessionFiles,
} = require("./exam-session-handoff");

// Bootstrap logger immediately
logger.bootstrap();

// Electron is usually DPI-aware on Windows, but this makes the intent explicit
// for the exam shell before any BrowserWindow is created.
if (process.platform === "win32") {
  app.commandLine.appendSwitch("high-dpi-support", "1");
}

let mainWindow = null;
let pendingDeepLink = null;
let isQuitCleanupInProgress = false;
let isQuitCleanupCompleted = false;
const protectionController = createDesktopProtectionController({
  getMainWindow: () => mainWindow,
  globalShortcut,
});
const examGuardTracer = createExamGuardTracer({
  baseDir: resolveLoggerBaseDir(),
});
const desktopCoreRuntime = createDesktopCoreRuntime({
  platform: process.platform,
  protectionController,
  examGuardTracer,
});
const watchdogHeartbeat = createWatchdogHeartbeat({
  getRuntimeSnapshot: () => desktopCoreRuntime.getSnapshot(),
});
const audioGuard = createAudioGuard({
  getMainWindow: () => mainWindow,
  examGuardTracer,
});
// Keep exactly one desktop shell alive so OAuth/deep-link callbacks always
// return to the existing app window instead of spawning a second shell.
//
// Exception: the isolated exam-shell is intentionally a second instance running
// on its own Windows desktop, so it must NOT take (or be blocked by) the
// single-instance lock — otherwise it would quit and forward to the lobby.
const isExamShell = isExamShellProcess();
const hasSingleInstanceLock = isExamShell || app.requestSingleInstanceLock();

if (!hasSingleInstanceLock) {
  app.quit();
}

function setPendingDeepLink(url) {
  pendingDeepLink = url;
}

function getPendingDeepLink() {
  return pendingDeepLink;
}

function clearPendingDeepLink() {
  pendingDeepLink = null;
}

function sendDeepLinkToRenderer(url) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    if (mainWindow.isMinimized()) {
      mainWindow.restore();
    }

    mainWindow.focus();
    // Forward the callback into the renderer where the auth hook completes the
    // login flow with the Google authorization code.
    mainWindow.webContents.send("desktop-oauth:callback", { url });
    return;
  }

  setPendingDeepLink(url);
}

function routeDeepLink(url) {
  handleDeepLink(url, ({ url: callbackUrl }) => {
    sendDeepLinkToRenderer(callbackUrl);
  });
}

function setupDeepLinkHandling() {
  registerProtocol();

  app.on("open-url", (event, url) => {
    event.preventDefault();
    routeDeepLink(url);
  });

  if (process.platform === "win32") {
    const deepLink = process.argv.slice(1).find((arg) => arg.startsWith("edulearn://"));
    if (deepLink) {
      setPendingDeepLink(deepLink);
    }
  }
}

function createAppWindow() {
  mainWindow = createMainWindow();
  mainWindow.webContents.on("did-start-loading", () => {
    examGuardTracer.recordLoop({
      action: "renderer_reload_triggered",
      decision: "accepted",
      state: desktopCoreRuntime.getSnapshot().sessionState,
      reason: "did-start-loading",
    });
  });
  mainWindow.webContents.on("did-fail-load", (_event, errorCode, errorDescription, validatedURL) => {
    examGuardTracer.recordLoop({
      action: "renderer_reload_failed",
      decision: "accepted",
      state: desktopCoreRuntime.getSnapshot().sessionState,
      reason: `${errorCode}:${errorDescription}`,
    });
    global.__eduWriteCrash?.(
      "did-fail-load",
      `${errorCode}:${errorDescription} url=${validatedURL || ""}`,
    );
  });
  mainWindow.webContents.on("render-process-gone", (_event, details) => {
    examGuardTracer.recordLoop({
      action: "renderer_process_gone",
      decision: details?.reason ?? "unknown",
      state: desktopCoreRuntime.getSnapshot().sessionState,
      reason: details?.exitCode != null ? String(details.exitCode) : "no_exit_code",
    });
    global.__eduWriteCrash?.(
      "render-process-gone",
      `reason=${details?.reason ?? "unknown"} exitCode=${details?.exitCode ?? "?"}`,
    );
  });
  mainWindow.webContents.on("did-finish-load", () => {
    if (!mainWindow || mainWindow.isDestroyed()) {
      return;
    }

    const snapshot = desktopCoreRuntime.getSnapshot();
    audioGuard.handleRuntimeChanged(
      snapshot,
      desktopCoreRuntime.getAudioState(),
    );
    mainWindow.webContents.send(DESKTOP_CORE_CHANNELS.RUNTIME_CHANGED, snapshot);
  });
  return mainWindow;
}

function registerDevRestoreShortcut() {
  if (!app.isPackaged) {
    const registered = globalShortcut.register("CommandOrControl+Shift+F12", async () => {
      try {
        const response = await desktopCoreRuntime.handleCommand({
          requestId: `desktop-dev-restore-${Date.now()}`,
          cmd: "force_restore_desktop",
          payload: {},
        });
        console.log("[desktop-core] Dev restore shortcut triggered", response);
      } catch (error) {
        console.error("[desktop-core] Failed to run dev restore shortcut", error);
      }
    });

    if (!registered) {
      console.warn("[desktop-core] Dev restore shortcut was not registered");
    }
  }
}

app.whenReady().then(() => {
  // C2: tamper self-check. On a packaged build carrying an integrity manifest,
  // refuse to run if any protected file was modified after signing. Fail-open in
  // dev / unsigned builds so a normal developer run is never bricked. Optional
  // Ed25519 signature enforcement via EDULEARN_INTEGRITY_PUBKEY.
  const integrity = verifyPackagedAppIntegrity({
    appDir: app.getAppPath(),
    isPackaged: app.isPackaged,
    publicKeyPem: process.env.EDULEARN_INTEGRITY_PUBKEY || null,
    requireSignature: process.env.EDULEARN_REQUIRE_SIGNED_INTEGRITY === "1",
  });
  if (integrity.enforced && !integrity.ok) {
    try {
      logger.error?.("App integrity check failed", integrity);
    } catch {
      // logging must never mask the refusal
    }
    console.error(
      "[desktop] App integrity check FAILED — refusing to launch:",
      integrity.reason,
      { missing: integrity.missing, mismatched: integrity.mismatched },
    );
    app.quit();
    return;
  }

  watchdogHeartbeat.start();
  registerDesktopOAuthIpc({
    getPendingDeepLink,
    clearPendingDeepLink,
  });
  registerDesktopCoreIpc({
    desktopCoreRuntime,
    examGuardTracer,
    getMainWindow: () => mainWindow,
  });
  setupDeepLinkHandling();
  registerDevRestoreShortcut();
  desktopCoreRuntime.start().finally(async () => {
    global.__eduWriteCrash?.("stage", "core.start settled, entering finally");
    if (isExamShell) {
      // Exam-shell adopts the lobby's login session before its room window
      // loads, so the isolated desktop does not force a re-login.
      try {
        await importExamSessionCookies();
        global.__eduWriteCrash?.("stage", "importExamSessionCookies ok");
      } catch (error) {
        console.error("[desktop] Failed to adopt exam session in shell", error);
        global.__eduWriteCrash?.(
          "importExamSessionCookies-threw",
          error && error.stack ? error.stack : String(error),
        );
      }
      // Activate the native OS-level keyboard lockdown (WH_KEYBOARD_LL): blocks
      // Alt+F4, Win, Alt+Tab, Alt+Esc, Ctrl+Esc, PrintScreen, Win+D/Shift+S,
      // ContextMenu and Ctrl+C/V/X system-wide while the exam-shell is up.
      try {
        await desktopCoreRuntime.handleCommand({
          requestId: `exam-shell-input-lockdown-${Date.now()}`,
          cmd: "activate_input_lockdown",
          payload: {},
        });
        global.__eduWriteCrash?.("stage", "activate_input_lockdown ok");
      } catch (error) {
        console.error("[desktop] Failed to activate input lockdown in shell", error);
        global.__eduWriteCrash?.(
          "activate_input_lockdown-threw",
          error && error.stack ? error.stack : String(error),
        );
      }
    } else {
      // Lobby: sweep any orphaned auth-token handoff files from a prior run.
      cleanupStaleSessionFiles();
    }
    try {
      global.__eduWriteCrash?.("stage", "calling createAppWindow");
      createAppWindow();
      global.__eduWriteCrash?.("stage", "createAppWindow returned");
    } catch (error) {
      global.__eduWriteCrash?.(
        "createAppWindow-threw",
        error && error.stack ? error.stack : String(error),
      );
      throw error;
    }
  });

  desktopCoreRuntime.onRuntimeChanged((snapshot) => {
    logger.setSessionContext(snapshot.sessionId, snapshot.sessionState);
    if (!mainWindow || mainWindow.isDestroyed()) {
      return;
    }

    audioGuard.handleRuntimeChanged(
      snapshot,
      desktopCoreRuntime.getAudioState(),
    );
    mainWindow.webContents.send(DESKTOP_CORE_CHANNELS.RUNTIME_CHANGED, snapshot);
  });

  const watchedRoots = [
    __dirname,
    path.resolve(__dirname, "..", "..", "client", "app", "(root)", "virtual-exam"),
    path.resolve(__dirname, "..", "..", "client", "lib", "runtime"),
  ];
  for (const watchedRoot of watchedRoots) {
    try {
      fs.watch(watchedRoot, { recursive: true }, (_eventType, filename) => {
        const changedPath = filename ? path.join(watchedRoot, filename) : watchedRoot;
        const accepted = !/node_modules|\.next|logs|demo|mock/i.test(changedPath);
        examGuardTracer.recordWatcher({
          path: changedPath,
          triggerAction: accepted ? "reload_possible" : "ignored",
          accepted,
        });
      });
    } catch (error) {
      examGuardTracer.recordWatcher({
        path: watchedRoot,
        triggerAction: "watch_failed",
        accepted: false,
        source: error instanceof Error ? error.message : "watch_error",
      });
    }
  }

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createAppWindow();
    }
  });

  app.on("before-quit", (event) => {
    if (isQuitCleanupCompleted) {
      return;
    }

    event.preventDefault();

    if (isQuitCleanupInProgress) {
      return;
    }

    isQuitCleanupInProgress = true;

    // Safety: never let a hung cleanup (e.g. a stuck sidecar stop) zombie the
    // process — force-exit after a short grace period. Unref so it never keeps
    // the app alive on its own.
    const forceExitTimer = setTimeout(() => {
      app.exit(0);
    }, 4000);
    forceExitTimer.unref?.();

    // Safety net: if the exam-shell is quitting for any reason (incl. the window
    // X button, without going through the password exit), make sure the visible
    // desktop returns to Default synchronously so the user isn't stranded on the
    // soon-to-be-destroyed exam desktop. Idempotent with the password exit path.
    if (isExamShell) {
      // Allow the guarded window close now that we are genuinely quitting.
      allowExamShellClose();
      try {
        switchBackToDefaultDesktop();
      } catch (error) {
        console.error("[desktop] Failed to restore Default desktop on exam-shell quit", error);
      }
    }

    Promise.resolve()
      .then(async () => {
        globalShortcut.unregisterAll();
        await desktopCoreRuntime.stop();
        watchdogHeartbeat.stop();
        audioGuard.dispose();
      })
      .catch((error) => {
        console.error("[desktop] Failed to stop Rust sidecar cleanly", error);
      })
      .finally(() => {
        clearTimeout(forceExitTimer);
        examGuardTracer.printSummary();
        isQuitCleanupCompleted = true;
        isQuitCleanupInProgress = false;
        app.quit();
      });
  });
});

app.on("second-instance", (_, argv) => {
  if (mainWindow && !mainWindow.isDestroyed()) {
    if (mainWindow.isMinimized()) {
      mainWindow.restore();
    }

    mainWindow.focus();
  }

  const deepLink = argv.find((arg) => arg.startsWith("edulearn://"));
  if (deepLink) {
    routeDeepLink(deepLink);
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
