const test = require("node:test");
const assert = require("node:assert/strict");
const Module = require("node:module");

// ipc.js requires("electron") at module load. Stub it so we can unit-test the
// pure authorization helpers without a running Electron.
const electronStub = {
  ipcMain: { listenerCount: () => 0, handle: () => {}, on: () => {} },
  shell: { openExternal: async () => true },
  app: { quit: () => {} },
};
const originalLoad = Module._load;
Module._load = function patchedLoad(request, ...rest) {
  if (request === "electron") {
    return electronStub;
  }
  return originalLoad.call(this, request, ...rest);
};
const { isAuthorizedCoreRequest, isSafeExternalUrl, isValidCommandRequest } =
  require("../src/ipc");
const { getCapabilityToken } = require("../src/capability-token");
Module._load = originalLoad;

// Build an event whose sender matches the "exam window" webContents.
function makeWindow() {
  const webContents = { id: 1 };
  const win = { isDestroyed: () => false, webContents };
  return { win, getMainWindow: () => win, webContents };
}

test("isAuthorizedCoreRequest requires BOTH a trusted sender and a valid token", () => {
  const { win, getMainWindow, webContents } = makeWindow();
  const token = getCapabilityToken();

  // trusted sender + valid token → authorized
  assert.equal(
    isAuthorizedCoreRequest({ sender: webContents }, token, getMainWindow),
    true,
  );

  // trusted sender but WRONG token → rejected (this is the C3 attack: the
  // untrusted page invoking without our preload's token)
  assert.equal(
    isAuthorizedCoreRequest({ sender: webContents }, "forged", getMainWindow),
    false,
  );

  // missing token → rejected
  assert.equal(
    isAuthorizedCoreRequest({ sender: webContents }, undefined, getMainWindow),
    false,
  );

  // valid token but sender is a DIFFERENT webContents → rejected
  assert.equal(
    isAuthorizedCoreRequest({ sender: { id: 999 } }, token, getMainWindow),
    false,
  );

  // destroyed window → rejected even with a valid token
  const destroyed = { isDestroyed: () => true, webContents };
  assert.equal(
    isAuthorizedCoreRequest({ sender: webContents }, token, () => destroyed),
    false,
  );
  void win;
});

test("isSafeExternalUrl only allows absolute http(s) URLs", () => {
  assert.equal(isSafeExternalUrl("https://accounts.google.com/o/oauth2"), true);
  assert.equal(isSafeExternalUrl("http://localhost:3000/callback"), true);
  assert.equal(isSafeExternalUrl("file:///C:/Windows/System32/cmd.exe"), false);
  assert.equal(isSafeExternalUrl("javascript:alert(1)"), false);
  assert.equal(isSafeExternalUrl("ms-settings:"), false);
  assert.equal(isSafeExternalUrl("not a url"), false);
  assert.equal(isSafeExternalUrl(""), false);
  assert.equal(isSafeExternalUrl(null), false);
});

test("isValidCommandRequest still validates command shape", () => {
  assert.equal(isValidCommandRequest({ cmd: "run_preflight" }), true);
  assert.equal(isValidCommandRequest({ cmd: "" }), false);
  assert.equal(isValidCommandRequest({}), false);
  assert.equal(isValidCommandRequest(null), false);
});
