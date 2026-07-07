const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const { resolveLoggerBaseDir } = require("../src/logger");

test("resolveLoggerBaseDir prefers Electron userData", () => {
  const fakeApp = {
    getPath(name) {
      return name === "userData"
        ? "C:\\Users\\Admin\\AppData\\Roaming\\Edulearn"
        : "";
    },
    isDestroyed() {
      return false;
    },
  };

  assert.equal(
    resolveLoggerBaseDir(fakeApp),
    "C:\\Users\\Admin\\AppData\\Roaming\\Edulearn",
  );
});

test("resolveLoggerBaseDir falls back to the desktop app root", () => {
  const fakeApp = {
    getPath() {
      throw new Error("userData unavailable");
    },
    isDestroyed() {
      return false;
    },
  };

  assert.equal(resolveLoggerBaseDir(fakeApp), path.resolve(__dirname, ".."));
});
