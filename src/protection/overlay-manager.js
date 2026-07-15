function createOverlayMarkup() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'" />
    <title>Exam Overlay</title>
    <style>
      html, body {
        margin: 0;
        width: 100%;
        height: 100%;
        background: #030712;
        cursor: none;
        overflow: hidden;
        user-select: none;
        -webkit-user-select: none;
        pointer-events: auto;
      }
    </style>
  </head>
  <body></body>
</html>`;
}

function toDisplayKey(display) {
  return String(display.id);
}

function createOverlayManager({ BrowserWindow }) {
  const overlayHtml = createOverlayMarkup();
  const overlayWindows = new Map();
  const internallyDestroyedWindows = new WeakSet();

  function destroyOverlayWindow(overlayWindow) {
    if (!overlayWindow || overlayWindow.isDestroyed()) {
      return;
    }

    internallyDestroyedWindows.add(overlayWindow);
    overlayWindow.destroy();
  }

  function createOverlayWindow(display) {
    const overlayWindow = new BrowserWindow({
      x: display.bounds.x,
      y: display.bounds.y,
      width: display.bounds.width,
      height: display.bounds.height,
      frame: false,
      show: false,
      resizable: false,
      movable: false,
      minimizable: false,
      maximizable: false,
      closable: false,
      focusable: false,
      skipTaskbar: true,
      alwaysOnTop: true,
      fullscreenable: false,
      hasShadow: false,
      roundedCorners: false,
      thickFrame: false,
      backgroundColor: "#030712",
      webPreferences: {
        // VS-04: these blackout covers have NO preload and load a static data:
        // page, so they are fully sandbox-compatible — run them sandboxed and
        // with DevTools disabled (they are non-focusable, non-interactive and
        // never need debugging). Tightens the exam attack surface at no cost.
        sandbox: true,
        contextIsolation: true,
        nodeIntegration: false,
        devTools: false,
      },
    });

    // These windows are pure visual covers for auxiliary displays. They must
    // stay non-focusable so the main exam window remains the active surface.
    overlayWindow.setMenuBarVisibility(false);
    overlayWindow.setAlwaysOnTop(true, "screen-saver");
    overlayWindow.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
    // The overlay must absorb pointer input on secondary displays so users
    // cannot keep dragging or clicking windows hidden behind the black layer.
    overlayWindow.setIgnoreMouseEvents(false);
    overlayWindow.setContentProtection(true);
    overlayWindow.on?.("close", (event) => {
      if (!internallyDestroyedWindows.has(overlayWindow)) {
        event.preventDefault();
      }
    });
    overlayWindow.setBounds(display.bounds, false);
    void overlayWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(overlayHtml)}`);
    overlayWindow.once("ready-to-show", () => {
      if (overlayWindow.isDestroyed()) {
        return;
      }

      overlayWindow.setBounds(display.bounds, false);
      overlayWindow.show();
      overlayWindow.moveTop();
    });

    return overlayWindow;
  }

  async function syncSecondaryDisplays(secondaryDisplays) {
    const desiredKeys = new Set(secondaryDisplays.map((display) => toDisplayKey(display)));

    for (const [displayKey, overlayWindow] of overlayWindows.entries()) {
      if (desiredKeys.has(displayKey)) {
        continue;
      }

      destroyOverlayWindow(overlayWindow);
      overlayWindows.delete(displayKey);
    }

    for (const display of secondaryDisplays) {
      const displayKey = toDisplayKey(display);
      const existingWindow = overlayWindows.get(displayKey);

      if (existingWindow && !existingWindow.isDestroyed()) {
        // Re-apply bounds when display metrics change so overlays continue to
        // cover the full monitor after resolution or topology changes.
        existingWindow.setBounds(display.bounds, false);
        existingWindow.moveTop();
        continue;
      }

      overlayWindows.set(displayKey, createOverlayWindow(display));
    }
  }

  function destroyAll() {
    for (const overlayWindow of overlayWindows.values()) {
      destroyOverlayWindow(overlayWindow);
    }
    overlayWindows.clear();
  }

  function getCount() {
    return overlayWindows.size;
  }

  return {
    destroyAll,
    getCount,
    syncSecondaryDisplays,
  };
}

module.exports = {
  createOverlayManager,
};
