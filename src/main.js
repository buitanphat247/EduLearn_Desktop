const { app, BrowserWindow, globalShortcut } = require("electron");
const { createMainWindow } = require("./window");
const { handleDeepLink, registerProtocol } = require("./deeplink");
const { registerDesktopOAuthIpc, registerDesktopCoreIpc } = require("./ipc");
const { createDesktopCoreRuntime } = require("./core-runtime");
const { createDesktopProtectionController } = require("./protection-controller");
const { DESKTOP_CORE_CHANNELS } = require("../../shared/contracts/safe-exam");

let mainWindow = null;
let pendingDeepLink = null;
let isQuitCleanupInProgress = false;
let isQuitCleanupCompleted = false;
const protectionController = createDesktopProtectionController({
  getMainWindow: () => mainWindow,
  globalShortcut,
});
const desktopCoreRuntime = createDesktopCoreRuntime({
  platform: process.platform,
  protectionController,
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
  mainWindow.webContents.on("did-finish-load", () => {
    if (!mainWindow || mainWindow.isDestroyed()) {
      return;
    }

    mainWindow.webContents.send(
      DESKTOP_CORE_CHANNELS.RUNTIME_CHANGED,
      desktopCoreRuntime.getSnapshot(),
    );
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
  registerDesktopOAuthIpc({
    getPendingDeepLink,
    clearPendingDeepLink,
  });
  registerDesktopCoreIpc({
    desktopCoreRuntime,
  });
  setupDeepLinkHandling();
  registerDevRestoreShortcut();
  desktopCoreRuntime.start().finally(() => {
    createAppWindow();
  });

  desktopCoreRuntime.onRuntimeChanged((snapshot) => {
    if (!mainWindow || mainWindow.isDestroyed()) {
      return;
    }

    mainWindow.webContents.send(DESKTOP_CORE_CHANNELS.RUNTIME_CHANGED, snapshot);
  });

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
      })
      .catch((error) => {
        console.error("[desktop] Failed to stop Rust sidecar cleanly", error);
      })
      .finally(() => {
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
