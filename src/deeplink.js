const { app, shell } = require("electron");

const PROTOCOL = "edulearn";
const CALLBACK_HOST = "auth";

function parseDeepLink(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== `${PROTOCOL}:`) return null;
    if (parsed.hostname !== CALLBACK_HOST) return null;
    return parsed;
  } catch {
    return null;
  }
}

function handleDeepLink(url, onCallback) {
  const parsed = parseDeepLink(url);
  if (!parsed) return false;

  const code = parsed.searchParams.get("code");
  const error = parsed.searchParams.get("error");

  if (typeof onCallback === "function") {
    onCallback({ code, error, url });
  }

  return true;
}

function openExternal(url) {
  return shell.openExternal(url);
}

function registerProtocol() {
  if (process.platform === "win32") {
    if (process.defaultApp && process.argv.length >= 2) {
      // In dev mode do not read process.argv[1] here: when Electron is started
      // through electronmon it may become an internal flag such as "--require".
      // That causes Windows deep-link relaunches to try opening a fake module
      // like "...\\desktop\\--require" and breaks OAuth return-to-app flow.
      // app.getAppPath() stays stable and points at the desktop app root.
      const appPath = app.getAppPath();
      app.setAsDefaultProtocolClient(PROTOCOL, process.execPath, [appPath]);
      return;
    }

    app.setAsDefaultProtocolClient(PROTOCOL);
    return;
  }

  if (process.platform === "darwin") {
    app.setAsDefaultProtocolClient(PROTOCOL);
  }
}

module.exports = {
  PROTOCOL,
  handleDeepLink,
  openExternal,
  parseDeepLink,
  registerProtocol,
};
