function captureMainWindowState(mainWindow) {
  return {
    wasKiosk: typeof mainWindow.isKiosk === "function" ? mainWindow.isKiosk() : false,
    wasFullScreen: mainWindow.isFullScreen(),
    wasAlwaysOnTop: mainWindow.isAlwaysOnTop(),
    wasContentProtected:
      typeof mainWindow.isContentProtected === "function" ? mainWindow.isContentProtected() : false,
    wasMaximized: mainWindow.isMaximized(),
    bounds: mainWindow.getBounds(),
  };
}

function applyExamWindowPresentation(mainWindow) {
  // Phase 6B owns the visual kiosk shell. The exam window becomes the
  // dominant desktop surface before later phases add stronger input/focus
  // enforcement.
  if (typeof mainWindow.setKiosk === "function") {
    mainWindow.setKiosk(true);
  }
  if (typeof mainWindow.setContentProtection === "function") {
    mainWindow.setContentProtection(true);
  }
  mainWindow.setAlwaysOnTop(true, "screen-saver");
  mainWindow.setFullScreen(true);
  mainWindow.focus();
}

function restoreMainWindowPresentation(mainWindow, savedState) {
  if (!savedState) {
    return;
  }

  if (!savedState.wasFullScreen) {
    mainWindow.setFullScreen(false);
  }

  if (typeof mainWindow.setKiosk === "function" && !savedState.wasKiosk) {
    mainWindow.setKiosk(false);
  }

  mainWindow.setAlwaysOnTop(savedState.wasAlwaysOnTop);

  if (typeof mainWindow.setContentProtection === "function") {
    mainWindow.setContentProtection(Boolean(savedState.wasContentProtected));
  }

  if (savedState.wasMaximized) {
    mainWindow.maximize();
  } else {
    mainWindow.setBounds(savedState.bounds);
  }

  mainWindow.focus();
}

module.exports = {
  applyExamWindowPresentation,
  captureMainWindowState,
  restoreMainWindowPresentation,
};
