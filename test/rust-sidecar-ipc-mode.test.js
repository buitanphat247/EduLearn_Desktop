const test = require("node:test");
const assert = require("node:assert/strict");

const { resolveCoreIpcMode } = require("../src/rust-sidecar");

test("dev on Windows with no flags → unauthenticated stdio allowed", () => {
  const mode = resolveCoreIpcMode({}, "win32");
  assert.equal(mode.useAuthenticatedPipe, false);
  assert.equal(mode.requireAuthenticatedIpc, false);
  assert.equal(mode.refuseUnauthenticatedStdio, false);
});

test("explicit named-pipe opt-in on Windows → authenticated pipe", () => {
  const mode = resolveCoreIpcMode(
    { EDULEARN_CORE_IPC_MODE: "named-pipe" },
    "win32",
  );
  assert.equal(mode.useAuthenticatedPipe, true);
  assert.equal(mode.refuseUnauthenticatedStdio, false);
});

test("NODE_ENV=production on Windows → authenticated pipe forced (no stdio)", () => {
  const mode = resolveCoreIpcMode({ NODE_ENV: "production" }, "win32");
  assert.equal(mode.requireAuthenticatedIpc, true);
  assert.equal(mode.useAuthenticatedPipe, true);
  assert.equal(mode.refuseUnauthenticatedStdio, false);
});

test("EDULEARN_REQUIRE_SECURE_IPC=1 on Windows → authenticated pipe forced", () => {
  const mode = resolveCoreIpcMode(
    { EDULEARN_REQUIRE_SECURE_IPC: "1" },
    "win32",
  );
  assert.equal(mode.useAuthenticatedPipe, true);
  assert.equal(mode.refuseUnauthenticatedStdio, false);
});

test("production on a non-Windows host → refuse (cannot do named-pipe auth)", () => {
  const mode = resolveCoreIpcMode({ NODE_ENV: "production" }, "linux");
  assert.equal(mode.requireAuthenticatedIpc, true);
  assert.equal(mode.useAuthenticatedPipe, false);
  assert.equal(
    mode.refuseUnauthenticatedStdio,
    true,
    "must refuse rather than fall back to unauthenticated stdio",
  );
});

test("dev flag combos never force refusal", () => {
  assert.equal(
    resolveCoreIpcMode({ NODE_ENV: "development" }, "win32")
      .refuseUnauthenticatedStdio,
    false,
  );
});
