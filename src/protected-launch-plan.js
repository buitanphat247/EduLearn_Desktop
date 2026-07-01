"use strict";

function isEnabled(value) {
  return value === "1" || String(value).toLowerCase() === "true";
}

function buildProtectedLaunchPlan({
  desktopRoot,
  bootstrapperPath,
  rustCorePath,
  electronPath,
  env = process.env,
} = {}) {
  if (!desktopRoot || !bootstrapperPath || !rustCorePath || !electronPath) {
    throw new Error("desktopRoot, bootstrapperPath, rustCorePath and electronPath are required.");
  }

  const bootstrapperArgs = [
    "--electron",
    electronPath,
    "--rust-core",
    rustCorePath,
    "--",
    desktopRoot,
  ];

  const launchEnv = {
    ...env,
    EDULEARN_CORE_IPC_MODE: "named-pipe",
    EDULEARN_REQUIRE_SIGNED_EXAM_POLICY:
      env.EDULEARN_REQUIRE_SIGNED_EXAM_POLICY ?? "1",
  };

  if (!isEnabled(env.EDULEARN_EXAM_DESKTOP_ISOLATION)) {
    return {
      executable: bootstrapperPath,
      args: bootstrapperArgs,
      mode: "bootstrapper",
      desktopIsolation: {
        enabled: false,
        reason: "EDULEARN_EXAM_DESKTOP_ISOLATION is not enabled.",
      },
      env: launchEnv,
    };
  }

  const desktopName = env.EDULEARN_EXAM_DESKTOP_NAME ?? "EduLearnExamDesktop";

  return {
    executable: bootstrapperPath,
    args: [
      "--desktop-isolation",
      "--desktop-name",
      desktopName,
      ...bootstrapperArgs,
    ],
    mode: "desktop-isolation",
    desktopIsolation: {
      enabled: true,
      desktopName,
      switchDesktop: true,
      launchModel: "bootstrapper-owned-create-desktop-before-electron",
    },
    env: launchEnv,
  };
}

module.exports = {
  buildProtectedLaunchPlan,
};
