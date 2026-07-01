const { BrowserWindow, screen } = require("electron");
const { buildDisplayProtectionPlan } = require("./protection/display-plan");
const {
  applyExamWindowPresentation,
  captureMainWindowState,
  restoreMainWindowPresentation,
} = require("./protection/main-window-manager");
const { createInputGuard } = require("./protection/input-guard");
const { createFocusGuard } = require("./protection/focus-guard");
const { createOverlayManager } = require("./protection/overlay-manager");

function createDesktopProtectionController({ getMainWindow, globalShortcut }) {
  const overlayManager = createOverlayManager({ BrowserWindow });
  const interactionState = {
    keyboardHookActive: false,
    focusLockActive: false,
    lastRuntimeEventAt: null,
  };
  const inputGuard = createInputGuard({
    globalShortcut,
    getMainWindow,
    onRuntimeEvent(event) {
      interactionState.lastRuntimeEventAt = event.timestamp;
      console.log("[desktop-core] Input guard event", event);
    },
  });
  const focusGuard = createFocusGuard({
    getMainWindow,
    onRuntimeEvent(event) {
      interactionState.lastRuntimeEventAt = event.timestamp;
      console.log("[desktop-core] Focus guard event", event);
    },
  });
  let savedMainWindowState = null;
  let isProtectionActive = false;
  let areDisplayListenersAttached = false;
  let displaySyncHandler = null;

  function getMainWindowHandleHex() {
    const mainWindow = getMainWindow();
    if (!mainWindow || mainWindow.isDestroyed()) {
      return null;
    }

    const rawHandle = mainWindow.getNativeWindowHandle?.();
    if (!rawHandle || typeof rawHandle.readBigUInt64LE !== "function") {
      return null;
    }

    try {
      return `0x${rawHandle.readBigUInt64LE(0).toString(16)}`;
    } catch {
      return null;
    }
  }

  async function syncOverlayWindows() {
    const displayPlan = buildDisplayProtectionPlan(screen);
    await overlayManager.syncSecondaryDisplays(displayPlan.secondaryDisplays);
    return displayPlan;
  }

  async function syncProtectionTopology() {
    if (typeof displaySyncHandler === "function") {
      await displaySyncHandler();
      return buildDisplayProtectionPlan(screen);
    }

    return syncOverlayWindows();
  }

  function getVisualSnapshotPatch() {
    const displayPlan = buildDisplayProtectionPlan(screen);
    const mainWindow = getMainWindow();
    const electronContentProtectionActive = Boolean(
      mainWindow &&
        !mainWindow.isDestroyed() &&
        typeof mainWindow.isContentProtected === "function" &&
        mainWindow.isContentProtected(),
    );

    return {
      kioskActive: isProtectionActive,
      overlayActive: overlayManager.getCount() > 0,
      keyboardHookActive: interactionState.keyboardHookActive,
      focusLockActive: interactionState.focusLockActive,
      electronContentProtectionActive,
      captureProtectionBestEffort: electronContentProtectionActive || overlayManager.getCount() > 0,
      activeMonitorCount: displayPlan.activeMonitorCount,
      blackOverlayCount: overlayManager.getCount(),
      lastRuntimeEventAt: interactionState.lastRuntimeEventAt,
    };
  }

  function hasActiveProtection() {
    return Boolean(
      isProtectionActive ||
        overlayManager.getCount() > 0 ||
        interactionState.keyboardHookActive ||
        interactionState.focusLockActive ||
        savedMainWindowState,
    );
  }

  function resetInteractionState() {
    interactionState.keyboardHookActive = false;
    interactionState.focusLockActive = false;
  }

  async function handleDisplayTopologyChanged() {
    if (!isProtectionActive) {
      return;
    }

    try {
      // Phase 6B should follow hot-plug events safely instead of leaving a
      // newly attached monitor uncovered during an active exam shell.
      await syncProtectionTopology();
    } catch (error) {
      console.error("[desktop-core] Failed to refresh overlay windows after display change", error);
    }
  }

  function attachDisplayListeners() {
    if (areDisplayListenersAttached) {
      return;
    }

    screen.on("display-added", handleDisplayTopologyChanged);
    screen.on("display-removed", handleDisplayTopologyChanged);
    screen.on("display-metrics-changed", handleDisplayTopologyChanged);
    areDisplayListenersAttached = true;
  }

  function detachDisplayListeners() {
    if (!areDisplayListenersAttached) {
      return;
    }

    screen.off("display-added", handleDisplayTopologyChanged);
    screen.off("display-removed", handleDisplayTopologyChanged);
    screen.off("display-metrics-changed", handleDisplayTopologyChanged);
    areDisplayListenersAttached = false;
  }

  async function enterExamProtection(options = {}) {
    const useOverlayFallback = Boolean(options.useOverlayFallback);

    if (isProtectionActive) {
      return {
        ...getVisualSnapshotPatch(),
        examProtectionActive: true,
      };
    }

    const mainWindow = getMainWindow();
    if (!mainWindow || mainWindow.isDestroyed()) {
      throw new Error("Main exam window is not available for visual kiosk entry.");
    }

    if (!savedMainWindowState) {
      savedMainWindowState = captureMainWindowState(mainWindow);
    }

    try {
      // Roll into visual protection in a deterministic order so restore can
      // unwind the same resources cleanly if any later step fails.
      applyExamWindowPresentation(mainWindow);
      attachDisplayListeners();
      if (useOverlayFallback) {
        await syncOverlayWindows();
      } else {
        overlayManager.destroyAll();
      }
      isProtectionActive = true;
    } catch (error) {
      detachDisplayListeners();
      overlayManager.destroyAll();
      restoreMainWindowPresentation(mainWindow, savedMainWindowState);
      savedMainWindowState = null;
      throw error;
    }

    return {
      ...getVisualSnapshotPatch(),
      examProtectionActive: true,
    };
  }

  async function enterInteractionProtection(options = {}) {
    const skipKeyboardGuard = Boolean(options.skipKeyboardGuard);
    const skipFocusGuard = Boolean(options.skipFocusGuard);
    const hasKeyboardProtection = skipKeyboardGuard ? true : interactionState.keyboardHookActive;
    const hasFocusProtection = skipFocusGuard ? true : interactionState.focusLockActive;

    if (hasKeyboardProtection && hasFocusProtection) {
      return {
        ...getVisualSnapshotPatch(),
        examProtectionActive: true,
      };
    }

    try {
      if (skipKeyboardGuard) {
        // Rust owns the real native keyboard hook. We still mirror the flag in
        // the controller snapshot so the renderer stays in sync during the same
        // lifecycle without installing a second Electron shortcut layer.
        interactionState.keyboardHookActive = true;
      } else {
        const inputPatch = inputGuard.activate();
        interactionState.keyboardHookActive = Boolean(inputPatch.keyboardHookActive);
        interactionState.lastRuntimeEventAt = inputPatch.lastRuntimeEventAt ?? interactionState.lastRuntimeEventAt;
      }

      if (skipFocusGuard) {
        // Rust owns the primary focus lock in native mode. Electron keeps only
        // the mirrored state instead of fighting for foreground ownership.
        interactionState.focusLockActive = true;
      } else {
        const focusPatch = focusGuard.activate();
        interactionState.focusLockActive = Boolean(focusPatch.focusLockActive);
        interactionState.lastRuntimeEventAt = focusPatch.lastRuntimeEventAt ?? interactionState.lastRuntimeEventAt;
      }
    } catch (error) {
      await restoreInteractionProtection();
      throw error;
    }

    return {
      ...getVisualSnapshotPatch(),
      examProtectionActive: true,
    };
  }

  async function restoreInteractionProtection() {
    const focusPatch = focusGuard.deactivate();
    const inputPatch = inputGuard.deactivate();
    resetInteractionState();
    interactionState.lastRuntimeEventAt =
      inputPatch.lastRuntimeEventAt ?? focusPatch.lastRuntimeEventAt ?? interactionState.lastRuntimeEventAt;

    return {
      ...getVisualSnapshotPatch(),
      examProtectionActive: isProtectionActive,
    };
  }

  async function restoreExamProtection() {
    const mainWindow = getMainWindow();
    await restoreInteractionProtection();
    detachDisplayListeners();
    overlayManager.destroyAll();
    isProtectionActive = false;

    if (mainWindow && !mainWindow.isDestroyed() && savedMainWindowState) {
      restoreMainWindowPresentation(mainWindow, savedMainWindowState);
    }

    savedMainWindowState = null;

    return {
      ...getVisualSnapshotPatch(),
      examProtectionActive: false,
      kioskActive: false,
      overlayActive: false,
      keyboardHookActive: false,
      focusLockActive: false,
      blackOverlayCount: 0,
    };
  }

  return {
    enterExamProtection,
    enterInteractionProtection,
    restoreInteractionProtection,
    restoreExamProtection,
    getVisualSnapshotPatch,
    getMainWindowHandleHex,
    hasActiveProtection,
    setDisplaySyncHandler(handler) {
      displaySyncHandler = typeof handler === "function" ? handler : null;
    },
  };
}

module.exports = {
  createDesktopProtectionController,
};
