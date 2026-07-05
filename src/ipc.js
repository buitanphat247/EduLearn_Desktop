const { ipcMain, shell } = require("electron");
const { DESKTOP_CORE_CHANNELS } = require("./contracts/safe-exam");
const { TRACE_CHANNEL } = require("./exam-guard-trace");

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

function registerDesktopCoreIpc({ desktopCoreRuntime, examGuardTracer }) {
  if (ipcMain.listenerCount(DESKTOP_CORE_CHANNELS.GET_RUNTIME_SNAPSHOT) === 0) {
    ipcMain.handle(DESKTOP_CORE_CHANNELS.GET_RUNTIME_SNAPSHOT, () => desktopCoreRuntime.getSnapshot());
  }

  if (ipcMain.listenerCount(DESKTOP_CORE_CHANNELS.REQUEST) === 0) {
    ipcMain.handle(DESKTOP_CORE_CHANNELS.REQUEST, async (_, request) => desktopCoreRuntime.handleCommand(request));
  }

  if (ipcMain.listenerCount(TRACE_CHANNEL) === 0) {
    ipcMain.on(TRACE_CHANNEL, (_event, payload) => {
      examGuardTracer?.ingestRendererTrace?.(payload);
    });
  }
}

module.exports = {
  registerDesktopOAuthIpc,
  registerDesktopCoreIpc,
};
