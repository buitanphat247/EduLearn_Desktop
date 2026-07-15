const { ipcMain, shell, app } = require("electron");
const {
  DESKTOP_CORE_CHANNELS,
  isRendererAllowedCommand,
  MAIN_ONLY_COMMANDS,
} = require("./contracts/safe-exam");
const { TRACE_CHANNEL } = require("./exam-guard-trace");
const {
  enterExamDesktop,
  switchBackToDefaultDesktop,
  allowExamShellClose,
} = require("./exam-desktop-launcher");
const { verifyExitPasswordInMain, invalidateExitPasswordCache } = require("./exam-exit-verify");
const { verifyCapabilityToken } = require("./capability-token");

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
      // Only ever hand http(s) URLs to the OS shell. Blocking other schemes
      // (file:, javascript:, custom protocol handlers, …) stops a compromised
      // renderer from launching arbitrary local programs via openExternal.
      if (!isSafeExternalUrl(url)) {
        throw new Error("open-external rejected: unsupported URL scheme");
      }
      await shell.openExternal(url);
      return true;
    });
  }
}

// Allow only absolute http(s) URLs to reach the OS shell.
function isSafeExternalUrl(value) {
  if (typeof value !== "string" || value.length === 0) {
    return false;
  }
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

// Only accept desktop-core IPC that originates from the real exam window's
// webContents. This blocks commands injected by any other webContents (e.g. a
// rogue frame or a context opened via a compromised renderer) since the exam
// window loads an untrusted origin over plain http.
function isTrustedSender(event, getMainWindow) {
  try {
    const win = typeof getMainWindow === "function" ? getMainWindow() : null;
    return Boolean(win) && !win.isDestroyed() && event.sender === win.webContents;
  } catch {
    return false;
  }
}

// Basic shape validation so a malformed/injected message cannot reach the
// command dispatcher. Exported for unit testing.
function isValidCommandRequest(request) {
  return (
    Boolean(request) &&
    typeof request === "object" &&
    typeof request.cmd === "string" &&
    request.cmd.length > 0
  );
}

// C3: a desktop-core IPC message is only accepted when it comes from the exam
// window's webContents AND carries this launch's capability token (attached by
// our bundled preload). Both must hold — the token proves the call went through
// our bridge, not a reconstructed/rogue path. Exported for unit testing.
function isAuthorizedCoreRequest(event, token, getMainWindow) {
  return isTrustedSender(event, getMainWindow) && verifyCapabilityToken(token);
}

function registerDesktopCoreIpc({ desktopCoreRuntime, examGuardTracer, getMainWindow }) {
  if (ipcMain.listenerCount(DESKTOP_CORE_CHANNELS.GET_RUNTIME_SNAPSHOT) === 0) {
    ipcMain.handle(DESKTOP_CORE_CHANNELS.GET_RUNTIME_SNAPSHOT, (event, token) => {
      if (!isAuthorizedCoreRequest(event, token, getMainWindow)) {
        throw new Error("desktop-core IPC rejected: unauthorized sender");
      }
      return desktopCoreRuntime.getSnapshot();
    });
  }

  if (ipcMain.listenerCount(DESKTOP_CORE_CHANNELS.REQUEST) === 0) {
    ipcMain.handle(DESKTOP_CORE_CHANNELS.REQUEST, async (event, token, request) => {
      if (!isAuthorizedCoreRequest(event, token, getMainWindow)) {
        throw new Error("desktop-core IPC rejected: unauthorized sender");
      }
      if (!isValidCommandRequest(request)) {
        throw new Error("desktop-core IPC rejected: malformed request");
      }
      // VS-01: reject renderer-originated IPC for privileged main-only commands.
      // This is defense-in-depth — the command name is already validated as a
      // known string, but MAIN_ONLY commands must never reach the dispatcher.
      if (!isRendererAllowedCommand(request.cmd)) {
        if (MAIN_ONLY_COMMANDS.has(request.cmd)) {
          throw new Error(
            `desktop-core IPC rejected: '${request.cmd}' is a privileged main-only command`,
          );
        }
        throw new Error(
          `desktop-core IPC rejected: '${request.cmd}' is not a recognized command`,
        );
      }
      return desktopCoreRuntime.handleCommand(request);
    });
  }

  if (ipcMain.listenerCount(TRACE_CHANNEL) === 0) {
    ipcMain.on(TRACE_CHANNEL, (event, payload) => {
      if (!isTrustedSender(event, getMainWindow)) {
        return;
      }
      examGuardTracer?.ingestRendererTrace?.(payload);
    });
  }

  // Lobby → main: create the isolated exam desktop and spawn the exam-shell on
  // it. The renderer only supplies the room identity; main owns the launch spec
  // (electron path, app entry, env) so an untrusted origin cannot control it.
  if (ipcMain.listenerCount(DESKTOP_CORE_CHANNELS.ENTER_EXAM_DESKTOP) === 0) {
    ipcMain.handle(DESKTOP_CORE_CHANNELS.ENTER_EXAM_DESKTOP, async (event, token, request) => {
      if (!isAuthorizedCoreRequest(event, token, getMainWindow)) {
        throw new Error("desktop-core IPC rejected: unauthorized sender");
      }
      const roomUrl = typeof request?.roomUrl === "string" ? request.roomUrl : "";
      const sessionId = typeof request?.sessionId === "string" ? request.sessionId : "";
      const examCode = typeof request?.examCode === "string" ? request.examCode : "";
      if (!roomUrl) {
        throw new Error("desktop-core IPC rejected: roomUrl is required");
      }
      return enterExamDesktop(desktopCoreRuntime, { roomUrl, sessionId, examCode });
    });
  }

  // Exam-shell → main: password already verified in the renderer; switch the
  // visible desktop back to Default and quit the shell (which destroys the
  // isolated desktop). Only handled in the exam-shell process.
  if (ipcMain.listenerCount(DESKTOP_CORE_CHANNELS.EXAM_SHELL_EXIT) === 0) {
    ipcMain.handle(DESKTOP_CORE_CHANNELS.EXAM_SHELL_EXIT, async (event, token, request) => {
      if (!isAuthorizedCoreRequest(event, token, getMainWindow)) {
        throw new Error("desktop-core IPC rejected: unauthorized sender");
      }
      // Re-verify the exit password in the main process so a compromised/injected
      // exam page cannot bypass the exit gate by calling this IPC directly.
      const password = typeof request?.password === "string" ? request.password : "";
      const sessionId = typeof request?.sessionId === "string" ? request.sessionId : "";
      const verdict = await verifyExitPasswordInMain(sessionId, password);
      if (verdict === "denied") {
        return { applied: false, denied: true, detail: "Mật khẩu thoát không hợp lệ." };
      }

      // VS-02: invalidate the offline exit-password cache after a successful exit
      // so stale material is never reused (e.g. re-entering the same exam later).
      invalidateExitPasswordCache(sessionId);

      const restore = switchBackToDefaultDesktop();
      // Permit the window/app close now that this is a verified exit.
      allowExamShellClose();
      setTimeout(() => {
        app.quit();
      }, 150);
      return { ...restore, applied: true };
    });
  }
}

module.exports = {
  registerDesktopOAuthIpc,
  registerDesktopCoreIpc,
  isValidCommandRequest,
  isAuthorizedCoreRequest,
  isSafeExternalUrl,
  isRendererAllowedCommand,
  MAIN_ONLY_COMMANDS,
};
