const test = require("node:test");
const assert = require("node:assert/strict");

const { createOverlayManager } = require("../src/protection/overlay-manager");

class FakeBrowserWindow {
  static instances = [];

  constructor(options) {
    this.options = options;
    this.destroyed = false;
    this.handlers = new Map();
    this.bounds = options;
    this.ignoreMouseEvents = null;
    this.contentProtection = null;
    FakeBrowserWindow.instances.push(this);
  }

  setMenuBarVisibility() {}

  setAlwaysOnTop() {}

  setVisibleOnAllWorkspaces() {}

  setIgnoreMouseEvents(value) {
    this.ignoreMouseEvents = value;
  }

  setContentProtection(value) {
    this.contentProtection = value;
  }

  setBounds(bounds) {
    this.bounds = bounds;
  }

  async loadURL() {}

  once(eventName, handler) {
    this.handlers.set(eventName, handler);
    if (eventName === "ready-to-show") {
      handler();
    }
  }

  on(eventName, handler) {
    this.handlers.set(eventName, handler);
  }

  emitClose() {
    let prevented = false;
    this.handlers.get("close")?.({
      preventDefault() {
        prevented = true;
      },
    });
    return prevented;
  }

  isDestroyed() {
    return this.destroyed;
  }

  show() {}

  moveTop() {}

  destroy() {
    this.destroyed = true;
  }
}

test("overlay-manager creates one overlay per secondary display and destroys stale overlays", async () => {
  FakeBrowserWindow.instances.length = 0;
  const overlayManager = createOverlayManager({ BrowserWindow: FakeBrowserWindow });

  await overlayManager.syncSecondaryDisplays([
    { id: 2, bounds: { x: 1920, y: 0, width: 1920, height: 1080 } },
    { id: 3, bounds: { x: 3840, y: 0, width: 1920, height: 1080 } },
  ]);

  assert.equal(overlayManager.getCount(), 2);
  assert.equal(FakeBrowserWindow.instances[0].ignoreMouseEvents, false);
  assert.equal(FakeBrowserWindow.instances[0].contentProtection, true);
  assert.equal(FakeBrowserWindow.instances[0].emitClose(), true);

  await overlayManager.syncSecondaryDisplays([{ id: 3, bounds: { x: 3840, y: 0, width: 1600, height: 900 } }]);

  assert.equal(overlayManager.getCount(), 1);
  assert.equal(FakeBrowserWindow.instances[0].destroyed, true);
  assert.deepEqual(FakeBrowserWindow.instances[1].bounds, { x: 3840, y: 0, width: 1600, height: 900 });

  overlayManager.destroyAll();
  assert.equal(overlayManager.getCount(), 0);
  assert.equal(FakeBrowserWindow.instances[1].destroyed, true);
});
