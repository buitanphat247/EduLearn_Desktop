const fs = require("fs");
const path = require("path");
const { app, BrowserWindow, globalShortcut } = require("electron");
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
const hasSingleInstanceLock = app.requestSingleInstanceLock();

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
  mainWindow.webContents.on("did-fail-load", (_event, errorCode, errorDescription) => {
    examGuardTracer.recordLoop({
      action: "renderer_reload_failed",
      decision: "accepted",
      state: desktopCoreRuntime.getSnapshot().sessionState,
      reason: `${errorCode}:${errorDescription}`,
    });
  });
  mainWindow.webContents.on("render-process-gone", (_event, details) => {
    examGuardTracer.recordLoop({
      action: "renderer_process_gone",
      decision: details?.reason ?? "unknown",
      state: desktopCoreRuntime.getSnapshot().sessionState,
      reason: details?.exitCode != null ? String(details.exitCode) : "no_exit_code",
    });
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
  watchdogHeartbeat.start();
  registerDesktopOAuthIpc({
    getPendingDeepLink,
    clearPendingDeepLink,
  });
  registerDesktopCoreIpc({
    desktopCoreRuntime,
    examGuardTracer,
  });
  setupDeepLinkHandling();
  registerDevRestoreShortcut();
  desktopCoreRuntime.start().finally(() => {
    createAppWindow();
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
