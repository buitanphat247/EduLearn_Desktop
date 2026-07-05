const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  summarizePerformanceGate,
  validatePerformanceRun,
} = require("../native-tests/performance-gate");
const {
  buildAuditSyncBundle,
  validateHashChain,
} = require("../native-tests/audit-sync");

const captureChecklist = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "native-tests", "capture-evidence-checklist.json"), "utf8"),
);
const faultChecklist = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "native-tests", "fault-injection-checklist.json"), "utf8"),
);

test("performance gate accepts stable runs and rejects leak trends", () => {
  const stable = {
    scenarioId: "runtime-30m",
    durationMinutes: 30,
    runtimeTickP95Ms: 80,
    heartbeatP95Ms: 40,
    cpuPercentAverage: 4,
    memoryGrowthMbPerHour: 12,
    handleGrowthPerHour: 8,
    threadGrowthPerHour: 1,
  };
  assert.deepEqual(validatePerformanceRun(stable), { pass: true, failures: [] });

  const leaking = {
    ...stable,
    scenarioId: "runtime-1h-leak",
    memoryGrowthMbPerHour: 512,
  };
  const summary = summarizePerformanceGate([stable, leaking]);
  assert.equal(summary.pass, false);
  assert.equal(summary.failed, 1);
  assert.equal(
    summary.validations[1].failures.includes("memory-growth-too-high"),
    true,
  );
});

test("performance gate fails closed when required metrics are missing", () => {
  const validation = validatePerformanceRun({
    scenarioId: "runtime-missing-metrics",
    durationMinutes: 30,
  });
  assert.equal(validation.pass, false);
  assert.equal(validation.failures.includes("runtimeTickP95Ms-missing"), true);
  assert.equal(validation.failures.includes("cpuPercentAverage-missing"), true);
});

test("performance gate does not pass an empty evidence set", () => {
  assert.deepEqual(summarizePerformanceGate([]), {
    pass: false,
    total: 0,
    failed: 0,
    validations: [],
  });
});

test("audit sync bundle requires an intact hash chain and sync identity", () => {
  const records = [
    { event: "FIRST", previousHash: null, currentHash: "a".repeat(64) },
    { event: "SECOND", previousHash: "a".repeat(64), currentHash: "b".repeat(64) },
  ];

  assert.deepEqual(validateHashChain(records), { valid: true, reason: "ok" });
  const bundle = buildAuditSyncBundle({
    records,
    deviceIdHash: "device-hash",
    sessionId: "session-1",
    policyVersion: 1,
    generatedAt: "2026-06-30T00:00:00.000Z",
    uploadEndpoint: "/exam-security/audit/upload",
    ackCommand: "ack_audit_upload_batch",
  });
  assert.equal(bundle.ready, true);
  assert.equal(bundle.schemaVersion, 2);
  assert.equal(bundle.recordCount, 2);
  assert.equal(bundle.headHash, "b".repeat(64));
  assert.equal(bundle.localRetention, "retain-until-ack");

  const broken = buildAuditSyncBundle({
    records: [{ event: "SECOND", previousHash: "wrong", currentHash: "b".repeat(64) }],
    deviceIdHash: "device-hash",
    sessionId: "session-1",
    generatedAt: "2026-06-30T00:00:00.000Z",
    uploadEndpoint: "/exam-security/audit/upload",
    ackCommand: "ack_audit_upload_batch",
  });
  assert.equal(broken.ready, false);

  const missingAck = buildAuditSyncBundle({
    records,
    deviceIdHash: "device-hash",
    sessionId: "session-1",
    generatedAt: "2026-06-30T00:00:00.000Z",
    uploadEndpoint: "/exam-security/audit/upload",
  });
  assert.equal(missingAck.ready, false);
  assert.equal(missingAck.reason, "missing-local-ack-command");
});

test("capture evidence checklist covers required tools, modes and limitations", () => {
  for (const tool of ["OBS", "Discord", "Teams", "Zoom", "Google Meet", "AnyDesk", "UltraViewer", "RDP"]) {
    assert.equal(captureChecklist.tools.includes(tool), true, tool);
  }
  for (const mode of ["window-capture", "display-capture", "game-capture", "remote-receiver"]) {
    assert.equal(captureChecklist.captureModes.includes(mode), true, mode);
  }
  assert.equal(captureChecklist.acceptance.bestEffortLimitationAcknowledged, true);
  assert.match(captureChecklist.disclaimer, /best-effort/i);
});

test("fault injection checklist is destructive-vm-only and requires restore proof", () => {
  assert.equal(faultChecklist.mode, "destructive-vm-only");
  assert.equal(faultChecklist.safety.requiresDisposableVm, true);
  for (const scenario of [
    "electron-crash",
    "rust-core-crash",
    "service-crash",
    "explorer-restart",
    "dwm-restart",
    "sleep",
    "resume",
    "guard-thread-exit",
    "late-runtime-tick-after-restore",
    "display-sync-after-restore",
    "process-pid-reuse",
    "process-churn-debounce-bound",
    "named-pipe-accept-cancellation",
    "service-client-response-timeout",
  ]) {
    assert.equal(faultChecklist.scenarios.includes(scenario), true, scenario);
  }
  for (const outcome of ["recover", "rollback", "restore", "audit-log"]) {
    assert.equal(faultChecklist.requiredOutcome.includes(outcome), true, outcome);
  }
  assert.equal(faultChecklist.requiredArtifacts.includes("restore-proof"), true);
});
