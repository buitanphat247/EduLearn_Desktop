"use strict";

function productionVerdict({
  hasOpenP0 = false,
  nativeMatrixExecuted = false,
  nativeMatrixPassed = false,
  destructiveMatrixExecuted = false,
  receiverCaptureEvidencePassed = false,
  serviceLifecycleEvidencePassed = false,
  performanceSoakPassed = false,
  benchmarkEvidencePassed = false,
  nativeEtwEvidencePassed = false,
  auditSyncReady = false,
  lintPassed = false,
  installerSigned = false,
  rollbackEvidencePassed = false,
  desktopIsolationEnabled = false,
  desktopIsolationCrashRestoreTested = false,
} = {}) {
  if (hasOpenP0) {
    return "NOT_PRODUCTION_READY";
  }
  const requiredEvidenceReady =
    nativeMatrixExecuted &&
    nativeMatrixPassed &&
    destructiveMatrixExecuted &&
    receiverCaptureEvidencePassed &&
    serviceLifecycleEvidencePassed &&
    performanceSoakPassed &&
    benchmarkEvidencePassed &&
    nativeEtwEvidencePassed &&
    auditSyncReady &&
    lintPassed &&
    installerSigned &&
    rollbackEvidencePassed;

  if (!requiredEvidenceReady) {
    return "BETA_LAB_READY_ONLY";
  }
  if (desktopIsolationEnabled && !desktopIsolationCrashRestoreTested) {
    return "BETA_LAB_READY_ONLY";
  }
  if (desktopIsolationEnabled && desktopIsolationCrashRestoreTested) {
    return "PRODUCTION_READY_DESKTOP_ISOLATION_MODE";
  }
  return "PRODUCTION_READY_USER_MODE_KIOSK_ONLY";
}

function releaseGateStatus({
  nativeMatrix = {},
  capture = {},
  service = {},
  performance = {},
  benchmark = {},
  processProducer = {},
  audit = {},
  lint = {},
  installer = {},
  rollback = {},
  desktopIsolation = {},
} = {}) {
  return {
    nativeMatrixExecuted: Boolean(nativeMatrix.executed),
    nativeMatrixPassed: Boolean(nativeMatrix.passed),
    destructiveMatrixExecuted: Boolean(nativeMatrix.destructiveExecuted),
    receiverCaptureEvidencePassed: Boolean(capture.receiverEvidencePassed),
    serviceLifecycleEvidencePassed: Boolean(service.lifecycleEvidencePassed),
    performanceSoakPassed: Boolean(performance.soakPassed),
    benchmarkEvidencePassed: Boolean(benchmark.evidencePassed),
    nativeEtwEvidencePassed: Boolean(processProducer.nativeEtwEvidencePassed),
    auditSyncReady: Boolean(audit.syncReady),
    lintPassed: Boolean(lint.passed),
    installerSigned: Boolean(installer.signed),
    rollbackEvidencePassed: Boolean(rollback.evidencePassed),
    desktopIsolationEnabled: Boolean(desktopIsolation.enabled),
    desktopIsolationCrashRestoreTested: Boolean(desktopIsolation.crashRestoreTested),
  };
}

function buildReleaseReport({
  version,
  commitHash = "unknown",
  testResults = [],
  nativeMatrix = {},
  capture = {},
  policy = {},
  service = {},
  performance = {},
  benchmark = {},
  processProducer = {},
  audit = {},
  lint = {},
  installer = {},
  rollback = {},
  desktopIsolation = {},
  knownLimitations = [],
  hasOpenP0 = false,
} = {}) {
  const gates = releaseGateStatus({
    nativeMatrix,
    capture,
    service,
    performance,
    benchmark,
    processProducer,
    audit,
    lint,
    installer,
    rollback,
    desktopIsolation,
  });
  const verdict = productionVerdict({
    hasOpenP0,
    ...gates,
  });
  const failedTests = testResults.filter((result) => result.status !== "passed");
  const gateLines = Object.entries(gates).map(
    ([name, passed]) => `- ${name}: ${Boolean(passed)}`,
  );

  return {
    version,
    commitHash,
    verdict,
    testsPassed: failedTests.length === 0,
    nativeMatrix,
    capture,
    policy,
    service,
    performance,
    benchmark,
    processProducer,
    audit,
    lint,
    installer,
    rollback,
    desktopIsolation,
    gates,
    knownLimitations,
    markdown: [
      `# Exam Guard Release Report`,
      ``,
      `Version: ${version ?? "unknown"}`,
      `Commit: ${commitHash}`,
      `Verdict: ${verdict}`,
      ``,
      `## Test Results`,
      ...testResults.map((result) => `- ${result.name}: ${result.status}`),
      ``,
      `## Native Matrix`,
      `- Executed: ${Boolean(nativeMatrix.executed)}`,
      `- Passed: ${Boolean(nativeMatrix.passed)}`,
      `- Destructive executed: ${Boolean(nativeMatrix.destructiveExecuted)}`,
      ``,
      `## Evidence Gates`,
      ...gateLines,
      ``,
      `## Known Limitations`,
      ...knownLimitations.map((item) => `- ${item}`),
    ].join("\n"),
  };
}

module.exports = {
  buildReleaseReport,
  productionVerdict,
  releaseGateStatus,
};
