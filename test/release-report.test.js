const test = require("node:test");
const assert = require("node:assert/strict");

const {
  buildReleaseReport,
  productionVerdict,
  releaseGateStatus,
} = require("../native-tests/release-report");

function completeProductionGates(overrides = {}) {
  return {
    nativeMatrixExecuted: true,
    nativeMatrixPassed: true,
    destructiveMatrixExecuted: true,
    receiverCaptureEvidencePassed: true,
    serviceLifecycleEvidencePassed: true,
    performanceSoakPassed: true,
    benchmarkEvidencePassed: true,
    nativeEtwEvidencePassed: true,
    emergencyRestoreEvidencePassed: true,
    auditSyncReady: true,
    lintPassed: true,
    installerSigned: true,
    rollbackEvidencePassed: true,
    desktopIsolationEnabled: false,
    desktopIsolationCrashRestoreTested: false,
    ...overrides,
  };
}

test("release verdict follows fail-closed production readiness gates", () => {
  assert.equal(
    productionVerdict({ hasOpenP0: true }),
    "NOT_PRODUCTION_READY",
  );
  assert.equal(
    productionVerdict({ nativeMatrixExecuted: false }),
    "BETA_LAB_READY_ONLY",
  );
  assert.equal(
    productionVerdict(completeProductionGates({ nativeEtwEvidencePassed: false })),
    "BETA_LAB_READY_ONLY",
  );
  assert.equal(
    productionVerdict(completeProductionGates({ emergencyRestoreEvidencePassed: false })),
    "BETA_LAB_READY_ONLY",
  );
  assert.equal(
    productionVerdict(completeProductionGates({
      nativeMatrixExecuted: true,
      nativeMatrixPassed: true,
      desktopIsolationEnabled: false,
    })),
    "PRODUCTION_READY_USER_MODE_KIOSK_ONLY",
  );
  assert.equal(
    productionVerdict(completeProductionGates({
      desktopIsolationEnabled: true,
      desktopIsolationCrashRestoreTested: false,
    })),
    "BETA_LAB_READY_ONLY",
  );
  assert.equal(
    productionVerdict(completeProductionGates({
      desktopIsolationEnabled: true,
      desktopIsolationCrashRestoreTested: true,
    })),
    "PRODUCTION_READY_DESKTOP_ISOLATION_MODE",
  );
});

test("release gate status maps evidence bundles to explicit booleans", () => {
  assert.deepEqual(
    releaseGateStatus({
      nativeMatrix: { executed: true, passed: true, destructiveExecuted: true },
      capture: { receiverEvidencePassed: true },
      service: { lifecycleEvidencePassed: true },
      performance: { soakPassed: true },
      benchmark: { evidencePassed: true },
      processProducer: { nativeEtwEvidencePassed: true },
      emergencyRestore: { evidencePassed: true },
      audit: { syncReady: true },
      lint: { passed: true },
      installer: { signed: true },
      rollback: { evidencePassed: true },
      desktopIsolation: { enabled: false },
    }),
    completeProductionGates({ desktopIsolationEnabled: false }),
  );
});

test("release report includes evidence status and limitations", () => {
  const report = buildReleaseReport({
    version: "0.0.1",
    commitHash: "unknown",
    testResults: [{ name: "rust-core", status: "passed" }],
    nativeMatrix: { executed: false, passed: false },
    policy: { signedPolicyParity: true },
    service: { namedPipeAuth: true },
    desktopIsolation: { enabled: false },
    knownLimitations: ["Capture protection is best-effort."],
  });

  assert.equal(report.verdict, "BETA_LAB_READY_ONLY");
  assert.equal(report.testsPassed, true);
  assert.equal(report.gates.receiverCaptureEvidencePassed, false);
  assert.equal(report.gates.nativeEtwEvidencePassed, false);
  assert.equal(report.gates.emergencyRestoreEvidencePassed, false);
  assert.match(report.markdown, /Capture protection is best-effort/);
  assert.match(report.markdown, /receiverCaptureEvidencePassed: false/);
  assert.match(report.markdown, /nativeEtwEvidencePassed: false/);
  assert.match(report.markdown, /emergencyRestoreEvidencePassed: false/);
});
