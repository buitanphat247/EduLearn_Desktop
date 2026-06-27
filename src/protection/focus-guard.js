function createFocusGuard({ getMainWindow, onRuntimeEvent = () => {} }) {
  let active = false;
  let attachedWindow = null;
  let blurListener = null;
  let focusListener = null;
  let monitorInterval = null;
  let pendingRefocusTimer = null;
  let isRefocusing = false;

  function emitFocusEvent(code, message) {
    onRuntimeEvent({
      code,
      level: code === "FOCUS_LOCK_FAILED" ? "warn" : "info",
      message,
      timestamp: Date.now(),
    });
  }

  function clearPendingTimer() {
    if (pendingRefocusTimer) {
      clearTimeout(pendingRefocusTimer);
      pendingRefocusTimer = null;
    }
  }

  function attemptRefocus(reason) {
    if (!active || isRefocusing) {
      return;
    }

    const mainWindow = getMainWindow();
    if (!mainWindow || mainWindow.isDestroyed()) {
      emitFocusEvent("FOCUS_LOCK_FAILED", `Focus restore skipped because the exam window is unavailable (${reason}).`);
      return;
    }

    if (mainWindow.webContents.isDevToolsOpened()) {
      return;
    }

    clearPendingTimer();
    pendingRefocusTimer = setTimeout(() => {
      if (!active) {
        return;
      }

      const nextWindow = getMainWindow();
      if (!nextWindow || nextWindow.isDestroyed()) {
        emitFocusEvent("FOCUS_LOCK_FAILED", `Focus restore failed because the exam window was destroyed (${reason}).`);
        return;
      }

      if (nextWindow.isFocused()) {
        return;
      }

      isRefocusing = true;
      try {
        if (nextWindow.isMinimized()) {
          nextWindow.restore();
        }

        nextWindow.show();
        nextWindow.focus();
        emitFocusEvent("FOCUS_RESTORED", `Focus was restored to the exam shell after ${reason}.`);
      } catch (error) {
        emitFocusEvent(
          "FOCUS_LOCK_FAILED",
          `Focus restore raised an error after ${reason}: ${error instanceof Error ? error.message : String(error)}.`,
        );
      } finally {
        isRefocusing = false;
      }
    }, 120);
  }

  function activate() {
    if (active) {
      return {
        focusLockActive: true,
        lastRuntimeEventAt: Date.now(),
      };
    }

    const mainWindow = getMainWindow();
    if (!mainWindow || mainWindow.isDestroyed()) {
      throw new Error("Main exam window is not available for focus protection.");
    }

    blurListener = () => {
      emitFocusEvent("FOCUS_LOST", "Exam shell focus moved away from the main window.");
      attemptRefocus("window blur");
    };

    focusListener = () => {
      emitFocusEvent("FOCUS_RESTORED", "Exam shell focus is active.");
    };

    attachedWindow = mainWindow;
    attachedWindow.on("blur", blurListener);
    attachedWindow.on("focus", focusListener);

    monitorInterval = setInterval(() => {
      const currentWindow = getMainWindow();
      if (!active || !currentWindow || currentWindow.isDestroyed() || currentWindow.webContents.isDevToolsOpened()) {
        return;
      }

      if (!currentWindow.isFocused()) {
        attemptRefocus("focus heartbeat");
      }
    }, 1200);

    active = true;

    return {
      focusLockActive: true,
      lastRuntimeEventAt: Date.now(),
    };
  }

  function deactivate() {
    clearPendingTimer();

    if (monitorInterval) {
      clearInterval(monitorInterval);
      monitorInterval = null;
    }

    if (attachedWindow && !attachedWindow.isDestroyed()) {
      if (blurListener) {
        attachedWindow.removeListener("blur", blurListener);
      }

      if (focusListener) {
        attachedWindow.removeListener("focus", focusListener);
      }
    }

    attachedWindow = null;
    blurListener = null;
    focusListener = null;
    active = false;
    isRefocusing = false;

    return {
      focusLockActive: false,
      lastRuntimeEventAt: Date.now(),
    };
  }

  return {
    activate,
    deactivate,
    isActive() {
      return active;
    },
  };
}

module.exports = {
  createFocusGuard,
};
