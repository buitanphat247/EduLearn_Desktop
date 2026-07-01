const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const matrix = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "native-tests", "matrix.json"), "utf8"),
);
const evidenceSchema = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "native-tests", "evidence-schema.json"),
    "utf8",
  ),
);
const acceptanceMatrix = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "native-tests", "acceptance-matrix.json"),
    "utf8",
  ),
);
const desktopIsolationChecklist = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "native-tests", "desktop-isolation-checklist.json"),
    "utf8",
  ),
);
const desktopPackage = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"),
);
const {
  summarizeCoverage,
  summarizeReleaseGate,
  validateEvidenceRecord,
  validationVerdict,
} = require("../native-tests/release-gate");
const { buildValidationReport } = require("../native-tests/validation-report");

test("native matrix covers required Windows, DPI, display, app and fault dimensions", () => {
  assert.deepEqual(matrix.windowsVersions, ["Windows 10", "Windows 11"]);
  assert.deepEqual(matrix.windowsBuilds, ["22H2", "23H2", "24H2"]);
  assert.deepEqual(matrix.architectures, ["x64", "ARM64"]);
  assert.deepEqual(matrix.dpiScales, [100, 125, 150, 175]);
  assert.equal(matrix.dpiAwareness.includes("PerMonitorV2"), true);
  assert.equal(matrix.dpiAwareness.includes("mixed-dpi"), true);

  for (const position of ["left", "right", "top", "bottom"]) {
    assert.equal(matrix.monitorPositions.includes(position), true, position);
  }
  for (const hardware of ["usb-display", "displaylink", "dock", "external-gpu", "hdr"]) {
    assert.equal(matrix.displayHardware.includes(hardware), true, hardware);
  }
  for (const scenario of [
    "single-monitor",
    "dual-monitor",
    "triple-monitor",
    "hot-plug",
    "resolution-change",
    "orientation-change",
    "sleep-resume",
    "hibernate-resume",
    "lock-unlock",
    "fast-user-switching",
    "rdp-attach",
    "rdp-detach",
    "uac-prompt",
    "explorer-restart",
    "dwm-restart",
    "dock",
    "undock",
  ]) {
    assert.equal(matrix.displayScenarios.includes(scenario), true, scenario);
  }
  for (const app of [
    "OBS",
    "Discord",
    "Zoom",
    "Teams",
    "Google Meet",
    "Webex",
    "Skype",
    "AnyDesk",
    "TeamViewer",
    "UltraViewer",
    "RustDesk",
    "RDP",
    "Quick Assist",
    "Windows Snipping Tool",
    "Win+Shift+S",
    "Lightshot",
    "Greenshot",
    "ShareX",
    "Game Bar",
    "Xbox Capture",
    "VMware",
    "VirtualBox",
  ]) {
    assert.equal(matrix.captureAndRemoteApps.includes(app), true, app);
  }
  for (const mode of [
    "window-capture",
    "display-capture",
    "game-capture",
    "remote-receiver",
    "recording",
    "stream",
  ]) {
    assert.equal(matrix.captureModes.includes(mode), true, mode);
  }
  for (const fault of [
    "kill-electron",
    "kill-rust-core",
    "kill-bootstrapper",
    "kill-watchdog",
    "kill-service",
    "close-stdin",
    "named-pipe-disconnect",
    "named-pipe-failure",
    "heartbeat-timeout",
    "kill-explorer",
    "restart-explorer",
    "restart-dwm",
    "uac-prompt",
    "crash-during-kiosk",
    "crash-during-restore",
    "crash-during-desktop-switch",
    "clipboard-failure",
    "guard-thread-exit",
    "late-runtime-tick-after-restore",
    "display-sync-after-restore",
    "process-pid-reuse",
    "process-churn-debounce-bound",
    "etw-session-stop",
    "etw-provider-disable",
    "etw-buffer-loss",
    "named-pipe-accept-cancellation",
    "service-client-response-timeout",
    "sleep-during-kiosk",
    "power-interruption-simulated",
  ]) {
    assert.equal(matrix.faultScenarios.includes(fault), true, fault);
  }
  assert.equal(matrix.requiredEvidence.includes("runtime-metrics"), true);
  assert.equal(matrix.requiredEvidence.includes("performance-metrics"), true);
  assert.equal(matrix.requiredEvidence.includes("desktop-telemetry"), true);
  assert.equal(matrix.requiredEvidence.includes("fault-injection-log"), true);
  assert.equal(matrix.requiredEvidence.includes("acceptance-decision"), true);
  assert.deepEqual(matrix.runnerModes, [
    "non-destructive",
    "destructive-vm-only",
    "manual-evidence",
    "automated-validation",
  ]);
  for (const item of [
    "overlay-bounds-match-physical-monitor",
    "overlay-recreated-on-bounds-mismatch",
    "overlay-recreated-on-invalid-hwnd",
    "display-hotplug-rebuilds-overlays",
    "mixed-dpi-100-125-150-175-no-gap",
  ]) {
    assert.equal(matrix.overlayAcceptance.includes(item), true, item);
  }
  for (const item of [
    "etw-is-primary-when-native-session-is-healthy",
    "etw-start-stop-rundown-events-reach-runtime-state",
    "etw-loss-counters-degrade-producer-and-trigger-reconciliation",
    "etw-recovery-uses-exponential-backoff",
    "polling-is-reconciliation-only",
    "prohibited-process-launch-to-terminate-under-500ms",
    "runtime-1s-tick-remains-fallback",
    "service-elevated-remediation-retries-admin-process",
  ]) {
    assert.equal(matrix.processWatcherAcceptance.includes(item), true, item);
  }
  for (const scenario of [
    "etw-provider-start",
    "etw-process-start",
    "etw-process-stop",
    "etw-process-rundown",
    "etw-tdh-field-extraction",
    "etw-health-heartbeat",
    "etw-loss-accounting",
    "etw-automatic-recovery",
    "etw-to-polling-reconciliation",
    "etw-process-flood-100",
    "etw-process-flood-500",
    "etw-process-flood-1000",
    "etw-process-flood-5000",
  ]) {
    assert.equal(matrix.etwValidationScenarios.includes(scenario), true, scenario);
  }
  assert.deepEqual(matrix.protectionClassifications, [
    "Blocked",
    "Best Effort",
    "Unsupported",
    "Bypass Possible",
  ]);
});

test("native evidence schema v2 requires capture, runtime, performance and restore proof", () => {
  assert.equal(evidenceSchema.schemaVersion, 2);
  for (const field of [
    "scenarioId",
    "category",
    "classification",
    "startedAt",
    "completedAt",
    "timestamp",
    "version",
    "commitHash",
    "machineInfo",
    "windowsVersion",
    "windowsBuild",
    "architecture",
    "runtimeMetrics",
    "performanceMetrics",
    "desktopTelemetry",
    "faultInjectionLog",
    "acceptanceDecision",
    "knownLimitations",
    "result",
    "evidence",
  ]) {
    assert.equal(evidenceSchema.requiredTopLevelFields.includes(field), true, field);
  }
  assert.deepEqual(evidenceSchema.allowedResults, ["pass", "fail", "blocked", "not-tested"]);
  assert.deepEqual(evidenceSchema.allowedClassifications, matrix.protectionClassifications);
  for (const item of matrix.requiredEvidence) {
    assert.equal(evidenceSchema.requiredEvidence.includes(item), true, item);
  }
  assert.deepEqual(evidenceSchema.acceptanceFields["receiver-capture"], [
    "blackFrameObserved",
    "toolName",
    "captureMode",
    "artifactPath",
    "expectedResult",
    "observedResult",
  ]);
  assert.deepEqual(evidenceSchema.acceptanceFields.recording, [
    "artifactPath",
    "toolName",
    "expectedResult",
    "observedResult",
  ]);
  assert.equal(evidenceSchema.requiredReports.includes("performance-report"), true);
  assert.equal(evidenceSchema.requiredReports.includes("service-validation-report"), true);
  assert.equal(evidenceSchema.requiredReports.includes("etw-producer-validation-report"), true);
  assert.equal(evidenceSchema.requiredReports.includes("benchmark-report"), true);
  for (const field of [
    "etwCallbackP95Micros",
    "etwQueueDelayP95Ms",
    "etwEventsLost",
    "etwBuffersLost",
    "etwRealTimeBuffersLost",
    "etwProducerRestartCount",
  ]) {
    assert.equal(evidenceSchema.acceptanceFields["runtime-metrics"].includes(field), true, field);
  }
});

test("acceptance matrix keeps missing native evidence explicit", () => {
  assert.deepEqual(acceptanceMatrix.verdicts, [
    "PASS",
    "PASS WITH LIMITATIONS",
    "FAIL",
    "NOT TESTED",
  ]);
  for (const category of [
    "capture-validation",
    "runtime-validation",
    "etw-producer-validation",
    "fault-injection",
    "soak-test",
    "stress-test",
    "desktop-validation",
    "service-validation",
    "benchmark-validation",
  ]) {
    assert.equal(
      acceptanceMatrix.categories.some((item) => item.id === category),
      true,
      category,
    );
  }
  assert.match(acceptanceMatrix.knownLimitations.wda.join(" "), /not DRM/i);
});

test("desktop isolation checklist covers lifecycle, crash recovery and Windows edge cases", () => {
  assert.equal(desktopIsolationChecklist.owner, "bootstrapper");
  assert.equal(desktopIsolationChecklist.mode, "destructive-vm-only");
  for (const event of [
    "DesktopCreated",
    "DesktopSwitched",
    "DesktopRestored",
    "DesktopDestroyed",
    "DesktopRecoveryStarted",
    "DesktopRecoveryCompleted",
    "DesktopCrashRecovered",
  ]) {
    assert.equal(desktopIsolationChecklist.requiredTelemetryEvents.includes(event), true, event);
  }
  for (const scenario of [
    "create-desktop-before-electron",
    "electron-startupinfo-lpdesktop-assigned",
    "switch-desktop-failure-terminates-child",
    "electron-crash-restores-default-desktop",
    "watchdog-timeout-restores-default-desktop",
  ]) {
    assert.equal(
      desktopIsolationChecklist.desktopLifecycleScenarios.includes(scenario),
      true,
      scenario,
    );
  }
  for (const edge of ["sleep-resume", "rdp-attach", "uac-secure-desktop", "dwm-restart"]) {
    assert.equal(desktopIsolationChecklist.systemEdgeScenarios.includes(edge), true, edge);
  }
});

function completeEvidenceRecord(overrides = {}) {
  const base = {
    scenarioId: "capture-obs-win11",
    category: "capture-validation",
    classification: "Blocked",
    startedAt: "2026-06-30T00:00:00.000Z",
    completedAt: "2026-06-30T00:01:00.000Z",
    timestamp: "2026-06-30T00:01:00.000Z",
    version: "0.0.1",
    commitHash: "unknown",
    machineInfo: { computerName: "VM-WIN11" },
    windowsVersion: "Windows 11",
    windowsBuild: "24H2",
    architecture: "x64",
    dpiInfo: { scale: 125, awareness: "PerMonitorV2" },
    dpiScale: 125,
    monitorInfo: { count: 2 },
    displayScenario: "dual-monitor",
    captureAndRemoteApp: "OBS",
    captureMode: "display-capture",
    runtimeSnapshot: { sessionState: "EXAM_RUNNING" },
    policySnapshot: { policyVersion: 1 },
    localScreenshot: { artifactPath: "local.png" },
    receiverCaptureEvidence: { artifactPath: "receiver.png" },
    processRemediationLog: [],
    runtimeMetrics: {
      runtimeTickP95Ms: 80,
      watcherLatencyP95Ms: 120,
      detectionLatencyP95Ms: 140,
      remediationLatencyP95Ms: 180,
      guardRestartP95Ms: 90,
      overlayRecoveryP95Ms: 110,
      desktopRestoreP95Ms: 1000,
      heartbeatDelayP95Ms: 40,
      maximumTickJitterMs: 20,
      etwCallbackP95Micros: 75,
      etwQueueDelayP95Ms: 2,
      etwEventsLost: 0,
      etwBuffersLost: 0,
      etwRealTimeBuffersLost: 0,
      etwProducerRestartCount: 0,
    },
    performanceMetrics: {
      durationMinutes: 30,
      cpuPercentAverage: 4,
      memoryGrowthMbPerHour: 12,
      handleGrowthPerHour: 8,
      threadGrowthPerHour: 1,
    },
    desktopTelemetry: {
      desktopCreated: true,
      desktopDestroyed: true,
      desktopRestored: true,
      desktopRestoreLatencyMs: 1000,
      desktopHealth: "restored",
    },
    faultInjectionLog: {
      faultScenario: "kill-electron",
      faultInjected: true,
      recoveryObserved: true,
      artifactPath: "fault.json",
    },
    restoreStateBefore: { desktopName: "EduLearnExamDesktop" },
    restoreStateAfter: { desktopRestored: true },
    acceptanceDecision: {
      expected: "receiver-black-frame",
      actual: "receiver-black-frame",
      verdict: "PASS",
      reproduction: "Run OBS display capture from a second account receiver.",
    },
    knownLimitations: [],
    result: "pass",
    failureReason: null,
    evidence: [
      { type: "runner-log", artifactPath: "runner.log" },
      { type: "machine-info", artifactPath: "machine.json" },
      { type: "dpi-info", artifactPath: "dpi.json" },
      { type: "monitor-info", artifactPath: "monitor.json" },
      {
        type: "runtime-snapshot",
        sessionState: "EXAM_RUNNING",
        captureProtectionBestEffort: true,
        guardHealth: {},
      },
      { type: "policy-snapshot", artifactPath: "policy.json" },
      {
        type: "receiver-capture",
        blackFrameObserved: true,
        toolName: "OBS",
        captureMode: "display-capture",
        artifactPath: "receiver.png",
        expectedResult: "black-or-excluded",
        observedResult: "black-frame",
      },
      {
        type: "recording",
        artifactPath: "recording.mp4",
        toolName: "OBS",
        expectedResult: "black-or-excluded",
        observedResult: "black-frame",
      },
      { type: "local-screen", artifactPath: "local.png" },
      { type: "process-remediation-log", artifactPath: "process.json" },
      {
        type: "runtime-metrics",
        runtimeTickP95Ms: 80,
        watcherLatencyP95Ms: 120,
        detectionLatencyP95Ms: 140,
        remediationLatencyP95Ms: 180,
        guardRestartP95Ms: 90,
        overlayRecoveryP95Ms: 110,
        desktopRestoreP95Ms: 1000,
        heartbeatDelayP95Ms: 40,
        maximumTickJitterMs: 20,
        etwCallbackP95Micros: 75,
        etwQueueDelayP95Ms: 2,
        etwEventsLost: 0,
        etwBuffersLost: 0,
        etwRealTimeBuffersLost: 0,
        etwProducerRestartCount: 0,
      },
      {
        type: "performance-metrics",
        durationMinutes: 30,
        cpuPercentAverage: 4,
        memoryGrowthMbPerHour: 12,
        handleGrowthPerHour: 8,
        threadGrowthPerHour: 1,
      },
      {
        type: "desktop-telemetry",
        desktopCreated: true,
        desktopDestroyed: true,
        desktopRestored: true,
        desktopRestoreLatencyMs: 1000,
        desktopHealth: "restored",
      },
      {
        type: "fault-injection-log",
        faultScenario: "kill-electron",
        faultInjected: true,
        recoveryObserved: true,
        artifactPath: "fault.json",
      },
      {
        type: "restore-state-before",
        desktopName: "EduLearnExamDesktop",
        cursorClipped: true,
        taskbarHidden: true,
      },
      {
        type: "restore-state-after",
        desktopRestored: true,
        cursorUnclipped: true,
        taskbarRestored: true,
      },
      {
        type: "acceptance-decision",
        expected: "receiver-black-frame",
        actual: "receiver-black-frame",
        verdict: "PASS",
        reproduction: "Run OBS display capture from a second account receiver.",
      },
    ],
  };
  return {
    ...base,
    ...overrides,
  };
}

test("native release gate accepts complete evidence and rejects incomplete evidence", () => {
  const complete = completeEvidenceRecord();
  assert.deepEqual(validateEvidenceRecord(complete, evidenceSchema), {
    valid: true,
    missingFields: [],
  });

  const incomplete = {
    ...complete,
    evidence: complete.evidence.filter((item) => item.type !== "receiver-capture"),
  };
  const validation = validateEvidenceRecord(incomplete, evidenceSchema);
  assert.equal(validation.valid, false);
  assert.equal(validation.missingFields.includes("evidence:receiver-capture"), true);
});

test("native release gate requires recording evidence for receiver validation", () => {
  const complete = completeEvidenceRecord();
  const incomplete = {
    ...complete,
    evidence: complete.evidence.filter((item) => item.type !== "recording"),
  };
  const validation = validateEvidenceRecord(incomplete, evidenceSchema);
  assert.equal(validation.valid, false);
  assert.equal(validation.missingFields.includes("evidence:recording"), true);
});

test("native release gate treats best-effort or not-tested records as non-production", () => {
  const complete = completeEvidenceRecord();
  assert.equal(validationVerdict(complete, evidenceSchema), "PASS");

  const bestEffort = completeEvidenceRecord({
    scenarioId: "best-effort-case",
    classification: "Best Effort",
    knownLimitations: ["WDA is not DRM."],
  });
  assert.equal(validationVerdict(bestEffort, evidenceSchema), "PASS WITH LIMITATIONS");

  const notTested = completeEvidenceRecord({
    scenarioId: "not-tested-case",
    result: "not-tested",
  });
  const summary = summarizeReleaseGate([complete, bestEffort, notTested], evidenceSchema);
  assert.equal(summary.productionReady, false);
  assert.equal(summary.passWithLimitations, 1);
  assert.equal(summary.notTested, 1);
});

test("native validation report fails closed when required evidence categories are absent", () => {
  const report = buildValidationReport({
    records: [completeEvidenceRecord()],
    matrix,
    schema: evidenceSchema,
    acceptance: acceptanceMatrix,
    generatedAt: "2026-07-01T00:00:00.000Z",
  });

  assert.equal(report.verdict, "NOT TESTED");
  assert.equal(
    report.categoryRows.some(
      (row) => row.id === "service-validation" && row.verdict === "NOT TESTED",
    ),
    true,
  );
  assert.equal(
    report.categoryRows.some(
      (row) => row.id === "etw-producer-validation" && row.verdict === "NOT TESTED",
    ),
    true,
  );
  assert.match(report.markdown, /Service Validation/);
  assert.match(report.markdown, /ETW Producer Validation/);
});

test("native release gate blocks production readiness on blocked, failed or invalid evidence", () => {
  const complete = completeEvidenceRecord();
  const blocked = { ...complete, scenarioId: "blocked-case", result: "blocked" };
  const failed = { ...complete, scenarioId: "failed-case", result: "fail" };
  const invalid = { ...complete, scenarioId: "invalid-case" };
  delete invalid.classification;

  const summary = summarizeReleaseGate([complete, blocked, failed, invalid], evidenceSchema);
  assert.equal(summary.productionReady, false);
  assert.equal(summary.blocked, 1);
  assert.equal(summary.failed, 1);
  assert.equal(summary.invalid, 1);
});

test("coverage summary exposes untested matrix axes", () => {
  const coverage = summarizeCoverage([completeEvidenceRecord()], matrix);
  assert.equal(coverage.captureAppsCovered, 1);
  assert.equal(coverage.displayScenariosCovered, 1);
  assert.equal(coverage.faultScenariosCovered, 1);
  assert.equal(coverage.missingCaptureApps.includes("Discord"), true);
  assert.equal(coverage.missingDisplayScenarios.includes("single-monitor"), true);
  assert.equal(coverage.missingFaultScenarios.includes("kill-rust-core"), true);
});

test("coverage does not count not-tested evidence slots as executed scenarios", () => {
  const notTested = completeEvidenceRecord({
    result: "not-tested",
    captureAndRemoteApp: "OBS",
    displayScenario: "dual-monitor",
  });
  const coverage = summarizeCoverage([notTested], matrix);
  assert.equal(coverage.captureAppsCovered, 0);
  assert.equal(coverage.displayScenariosCovered, 0);
  assert.equal(coverage.faultScenariosCovered, 0);
  assert.equal(coverage.missingCaptureApps.includes("OBS"), true);
  assert.equal(coverage.missingDisplayScenarios.includes("dual-monitor"), true);
  assert.equal(coverage.missingFaultScenarios.includes("kill-electron"), true);
});

test("release gate reads reviewed evidence separately from matrix run history", () => {
  assert.match(
    desktopPackage.scripts["native:etw-smoke"],
    /Run-EtwProducerSmoke\.ps1/,
  );
  assert.match(desktopPackage.scripts["native:report"], /native-tests[\\/]results/);
  assert.match(
    desktopPackage.scripts["native:release-gate"],
    /native-tests[\\/]release-evidence/,
  );
  assert.doesNotMatch(
    desktopPackage.scripts["native:release-gate"],
    /--input\s+\S*native-tests[\\/]results(?:\s|$)/,
  );
});

test("formal release verification runs every Exam Guard test boundary", () => {
  const releaseTests = desktopPackage.scripts["test:release"];
  for (const requiredCommand of [
    "npm run test",
    "npm run test:core",
    "npm run service:test",
    "npm run bootstrapper:test",
    "npm run desktop-isolation:test",
    "npm run test:ipc",
    "client",
    "server",
  ]) {
    assert.match(releaseTests, new RegExp(requiredCommand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(desktopPackage.scripts["release:verify"], /npm run test:release/);
  assert.match(desktopPackage.scripts["release:verify"], /npm run build:release/);
  assert.match(desktopPackage.scripts["release:verify"], /npm run native:release-gate/);
  const releaseBuilds = desktopPackage.scripts["build:release"];
  for (const requiredBuild of [
    "core:build",
    "service:build",
    "bootstrapper:build",
    "desktop-isolation:build",
    "client",
    "server",
  ]) {
    assert.match(releaseBuilds, new RegExp(requiredBuild));
  }
});
