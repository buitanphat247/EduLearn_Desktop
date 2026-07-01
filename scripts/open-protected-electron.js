const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const { buildProtectedLaunchPlan } = require("../src/protected-launch-plan");

const desktopRoot = path.resolve(__dirname, "..");
const bootstrapperPath =
  process.env.EDULEARN_BOOTSTRAPPER_PATH ??
  path.join(desktopRoot, "bootstrapper", "target", "release", "edulearn-bootstrapper.exe");
const rustCorePath =
  process.env.DESKTOP_RUST_CORE_PATH ??
  path.join(desktopRoot, "rust-core", "target", "release", "rust-core.exe");
const electronPath = require("electron");

for (const [name, filePath] of [
  ["bootstrapper", bootstrapperPath],
  ["Rust core", rustCorePath],
  ["Electron", electronPath],
]) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`${name} executable was not found at ${filePath}.`);
  }
}

const plan = buildProtectedLaunchPlan({
  desktopRoot,
  bootstrapperPath,
  rustCorePath,
  electronPath,
});

if (!fs.existsSync(plan.executable)) {
  throw new Error(`${plan.mode} executable was not found at ${plan.executable}.`);
}

const result = spawnSync(plan.executable, plan.args, {
  cwd: desktopRoot,
  stdio: "inherit",
  windowsHide: true,
  env: plan.env,
});

if (result.error) {
  throw result.error;
}

process.exitCode = result.status ?? 1;
