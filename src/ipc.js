const { ipcMain, shell } = require("electron");
const { DESKTOP_CORE_CHANNELS } = require("./contracts/safe-exam");

function registerDesktopOAuthIpc({ getPendingDeepLink, clearPendingDeepLink }) {
  if (ipcMain.listenerCount("desktop-oauth:get-pending") === 0) {
    ipcMain.handle("desktop-oauth:get-pending", () => {
      const value = getPendingDeepLink();
      clearPendingDeepLink();
      return value;
    });
  }

  if (ipcMain.listenerCount("desktop-oauth:open-external") === 0) {
    ipcMain.handle("desktop-oauth:open-external", async (_, url) => {
      await shell.openExternal(url);
      return true;
    });
  }
}

function registerDesktopCoreIpc({ desktopCoreRuntime }) {
  if (ipcMain.listenerCount(DESKTOP_CORE_CHANNELS.GET_RUNTIME_SNAPSHOT) === 0) {
    ipcMain.handle(DESKTOP_CORE_CHANNELS.GET_RUNTIME_SNAPSHOT, () => desktopCoreRuntime.getSnapshot());
  }

  if (ipcMain.listenerCount(DESKTOP_CORE_CHANNELS.REQUEST) === 0) {
    ipcMain.handle(DESKTOP_CORE_CHANNELS.REQUEST, async (_, request) => desktopCoreRuntime.handleCommand(request));
  }
}

module.exports = {
  registerDesktopOAuthIpc,
  registerDesktopCoreIpc,
};
