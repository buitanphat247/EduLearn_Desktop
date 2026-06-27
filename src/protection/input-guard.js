const BEST_EFFORT_ACCELERATORS = [
  { accelerator: "Alt+F4", code: "ALT_F4" },
  { accelerator: "CommandOrControl+Escape", code: "CTRL_ESC" },
  { accelerator: "Super+D", code: "WIN_D" },
  { accelerator: "Super+Tab", code: "WIN_TAB" },
];

function createInputGuard({ globalShortcut, getMainWindow, onRuntimeEvent = () => {} }) {
  let registeredAccelerators = [];
  let attachedWindow = null;
  let beforeInputListener = null;
  let active = false;

  function emitBlockedEvent(code, source) {
    onRuntimeEvent({
      code: "KIOSK_ESCAPE_ATTEMPT",
      level: "warn",
      message: `Blocked shortcut attempt: ${code} via ${source}.`,
      timestamp: Date.now(),
    });
  }

  function isBlockedWindowShortcut(input) {
    if (!input || input.type !== "keyDown") {
      return null;
    }

    if (input.key === "F4" && input.alt) {
      return "ALT_F4";
    }

    if (input.key === "Escape" && input.control) {
      return "CTRL_ESC";
    }

    if (input.key === "Meta" || input.key === "Super") {
      return "WIN";
    }

    if (input.key === "D" && input.meta) {
      return "WIN_D";
    }

    if (input.key === "Tab" && input.meta) {
      return "WIN_TAB";
    }

    if (input.key === "Escape" && input.alt) {
      return "ALT_ESC";
    }

    // Windows owns Alt+Tab before Electron in most cases. The guard keeps the
    // intent visible here so later native hooks can replace this best-effort path.
    if (input.key === "Tab" && input.alt) {
      return "ALT_TAB";
    }

    return null;
  }

  function activate() {
    if (active) {
      return {
        keyboardHookActive: true,
        lastRuntimeEventAt: Date.now(),
      };
    }

    const mainWindow = getMainWindow();
    if (!mainWindow || mainWindow.isDestroyed()) {
      throw new Error("Main exam window is not available for input protection.");
    }

    beforeInputListener = (event, input) => {
      const blockedCode = isBlockedWindowShortcut(input);
      if (!blockedCode) {
        return;
      }

      event.preventDefault();
      emitBlockedEvent(blockedCode, "window");
    };

    attachedWindow = mainWindow;
    attachedWindow.webContents.on("before-input-event", beforeInputListener);

    registeredAccelerators = [];
    for (const entry of BEST_EFFORT_ACCELERATORS) {
      try {
        const registered = globalShortcut.register(entry.accelerator, () => {
          emitBlockedEvent(entry.code, "global-shortcut");
        });

        if (registered) {
          registeredAccelerators.push(entry.accelerator);
        }
      } catch (error) {
        console.warn("[desktop-core] Failed to register kiosk accelerator", {
          accelerator: entry.accelerator,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    active = true;

    return {
      keyboardHookActive: true,
      lastRuntimeEventAt: Date.now(),
    };
  }

  function deactivate() {
    if (attachedWindow && !attachedWindow.isDestroyed() && beforeInputListener) {
      attachedWindow.webContents.removeListener("before-input-event", beforeInputListener);
    }

    for (const accelerator of registeredAccelerators) {
      globalShortcut.unregister(accelerator);
    }

    registeredAccelerators = [];
    attachedWindow = null;
    beforeInputListener = null;
    active = false;

    return {
      keyboardHookActive: false,
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
  createInputGuard,
};
