const { BrowserWindow } = require("electron");
const path = require("path");

function resolveStartUrl() {
  return process.env.ELECTRON_START_URL || "http://localhost:3000";
}

function createMainWindow() {
  const win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1200,
    minHeight: 760,
    show: false,
    autoHideMenuBar: true,
    backgroundColor: "#ffffff",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      // The preload bridge imports local shared contract files and needs the
      // standard preload environment. Keeping context isolation on is enough
      // for this stage; sandbox can be revisited after the bridge is bundled.
      sandbox: false,
      nodeIntegration: false,
      webSecurity: true,
    },
  });

  const startUrl = resolveStartUrl();
  let hasShownWindow = false;

  const showWindow = () => {
    if (hasShownWindow || win.isDestroyed()) {
      return;
    }

    hasShownWindow = true;
    if (process.platform === "win32") {
      win.maximize();
    }

    win.show();
  };

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

  console.log(`[desktop] Loading renderer URL: ${startUrl}`);
  win.loadURL(startUrl);
  return win;
}

module.exports = {
  createMainWindow,
};
