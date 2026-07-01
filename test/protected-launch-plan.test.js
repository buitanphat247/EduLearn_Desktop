const test = require("node:test");
const assert = require("node:assert/strict");

const { buildProtectedLaunchPlan } = require("../src/protected-launch-plan");

test("protected launch runs bootstrapper directly by default", () => {
  const plan = buildProtectedLaunchPlan({
    desktopRoot: "C:\\app",
    bootstrapperPath: "C:\\app\\bootstrapper.exe",
    rustCorePath: "C:\\app\\rust-core.exe",
    electronPath: "C:\\app\\electron.exe",
    env: {},
  });

  assert.equal(plan.mode, "bootstrapper");
  assert.deepEqual(plan.desktopIsolation, {
    enabled: false,
    reason: "EDULEARN_EXAM_DESKTOP_ISOLATION is not enabled.",
  });
  assert.equal(plan.executable, "C:\\app\\bootstrapper.exe");
  assert.deepEqual(plan.args, [
    "--electron",
    "C:\\app\\electron.exe",
    "--rust-core",
    "C:\\app\\rust-core.exe",
    "--",
    "C:\\app",
  ]);
  assert.equal(plan.env.EDULEARN_CORE_IPC_MODE, "named-pipe");
  assert.equal(plan.env.EDULEARN_REQUIRE_SIGNED_EXAM_POLICY, "1");
});

test("protected launch keeps desktop isolation disabled for non opt-in values", () => {
  const plan = buildProtectedLaunchPlan({
    desktopRoot: "C:\\app",
    bootstrapperPath: "C:\\app\\bootstrapper.exe",
    rustCorePath: "C:\\app\\rust-core.exe",
    electronPath: "C:\\app\\electron.exe",
    env: {
      EDULEARN_EXAM_DESKTOP_ISOLATION: "0",
      EDULEARN_DESKTOP_ISOLATION_PATH: "C:\\app\\desktop-isolation.exe",
    },
  });

  assert.equal(plan.mode, "bootstrapper");
  assert.equal(plan.desktopIsolation.enabled, false);
});

test("protected launch can opt in to bootstrapper-owned CreateDesktop before Electron starts", () => {
  const plan = buildProtectedLaunchPlan({
    desktopRoot: "C:\\app",
    bootstrapperPath: "C:\\app\\bootstrapper.exe",
    rustCorePath: "C:\\app\\rust-core.exe",
    electronPath: "C:\\app\\electron.exe",
    env: {
      EDULEARN_EXAM_DESKTOP_ISOLATION: "1",
      EDULEARN_EXAM_DESKTOP_NAME: "EduLearnExamLab",
      EDULEARN_REQUIRE_SIGNED_EXAM_POLICY: "1",
    },
  });

  assert.equal(plan.mode, "desktop-isolation");
  assert.equal(plan.executable, "C:\\app\\bootstrapper.exe");
  assert.deepEqual(plan.desktopIsolation, {
    enabled: true,
    desktopName: "EduLearnExamLab",
    switchDesktop: true,
    launchModel: "bootstrapper-owned-create-desktop-before-electron",
  });
  assert.deepEqual(plan.args, [
    "--desktop-isolation",
    "--desktop-name",
    "EduLearnExamLab",
    "--electron",
    "C:\\app\\electron.exe",
    "--rust-core",
    "C:\\app\\rust-core.exe",
    "--",
    "C:\\app",
  ]);
});
