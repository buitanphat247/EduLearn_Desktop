const test = require("node:test");
const assert = require("node:assert/strict");

const {
  applyExamWindowPresentation,
  captureMainWindowState,
  restoreMainWindowPresentation,
} = require("../src/protection/main-window-manager");

function createMainWindowStub() {
  const calls = [];
  const state = {
    kiosk: false,
    fullScreen: false,
    alwaysOnTop: false,
    contentProtected: false,
    maximized: false,
    bounds: { x: 10, y: 20, width: 1280, height: 720 },
  };

  return {
    calls,
    state,
    isKiosk() {
      return state.kiosk;
    },
    isFullScreen() {
      return state.fullScreen;
    },
    isAlwaysOnTop() {
      return state.alwaysOnTop;
    },
    isContentProtected() {
      return state.contentProtected;
    },
    isMaximized() {
      return state.maximized;
    },
    getBounds() {
      return state.bounds;
    },
    setKiosk(value) {
      state.kiosk = value;
      calls.push(["setKiosk", value]);
    },
    setContentProtection(value) {
      state.contentProtected = value;
      calls.push(["setContentProtection", value]);
    },
    setAlwaysOnTop(value, level) {
      state.alwaysOnTop = value;
      calls.push(["setAlwaysOnTop", value, level]);
    },
    setFullScreen(value) {
      state.fullScreen = value;
      calls.push(["setFullScreen", value]);
    },
    maximize() {
      state.maximized = true;
      calls.push(["maximize"]);
    },
    setBounds(value) {
      state.bounds = value;
      calls.push(["setBounds", value]);
    },
    focus() {
      calls.push(["focus"]);
    },
  };
}

test("main-window-manager captures and restores the original window presentation", () => {
  const mainWindow = createMainWindowStub();
  const savedState = captureMainWindowState(mainWindow);

  applyExamWindowPresentation(mainWindow);

  assert.equal(mainWindow.state.kiosk, true);
  assert.equal(mainWindow.state.fullScreen, true);
  assert.equal(mainWindow.state.alwaysOnTop, true);
  assert.equal(mainWindow.state.contentProtected, true);

  restoreMainWindowPresentation(mainWindow, savedState);

  assert.equal(mainWindow.state.kiosk, false);
  assert.equal(mainWindow.state.fullScreen, false);
  assert.equal(mainWindow.state.alwaysOnTop, false);
  assert.equal(mainWindow.state.contentProtected, false);
  assert.deepEqual(mainWindow.state.bounds, { x: 10, y: 20, width: 1280, height: 720 });
});
