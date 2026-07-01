"use strict";

const fs = require("fs");
const path = require("path");
const { summarizeCoverage, summarizeReleaseGate } = require("./release-gate");
const { summarizePerformanceGate } = require("./performance-gate");

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function createNotTestedRecord(manifest, scenario) {
  const machine = manifest.machine ?? {};
  const timestamp =
    manifest.completedAt ?? manifest.collectedAt ?? manifest.startedAt ?? new Date(0).toISOString();
  const classification = ["Blocked", "Best Effort", "Unsupported", "Bypass Possible"].includes(
    scenario.classification,
  )
    ? scenario.classification
    : "Best Effort";
  const faultScenario = scenario.faultScenario ?? null;
  const captureMode = scenario.captureMode ?? null;
  const captureApp = scenario.captureAndRemoteApp ?? null;
  const displayScenario = scenario.displayScenario ?? null;
  const reason =
    "The matrix runner created an evidence slot, but no acceptance evidence was collected.";
  const acceptanceDecision = {
    expected: "scenario-specific acceptance evidence",
    actual: "not collected",
    verdict: "NOT TESTED",
    reproduction: "Run this scenario in the required Windows VM or receiver environment.",
  };
  const runtimeMetrics = {
    runtimeTickP95Ms: null,
    watcherLatencyP95Ms: null,
    detectionLatencyP95Ms: null,
    remediationLatencyP95Ms: null,
    guardRestartP95Ms: null,
    overlayRecoveryP95Ms: null,
    desktopRestoreP95Ms: null,
    heartbeatDelayP95Ms: null,
    maximumTickJitterMs: null,
    etwCallbackP95Micros: null,
    etwQueueDelayP95Ms: null,
    etwEventsLost: null,
    etwBuffersLost: null,
    etwRealTimeBuffersLost: null,
    etwProducerRestartCount: null,
  };
  const performanceMetrics = {
    durationMinutes: scenario.durationMinutes ?? null,
    cpuPercentAverage: null,
    memoryGrowthMbPerHour: null,
    handleGrowthPerHour: null,
    threadGrowthPerHour: null,
  };
  const desktopTelemetry = {
    desktopCreated: null,
    desktopDestroyed: null,
    desktopRestored: null,
    desktopRestoreLatencyMs: null,
    desktopHealth: "not-tested",
  };
  const faultInjectionLog = {
    faultScenario,
    faultInjected: false,
    recoveryObserved: false,
    artifactPath: null,
  };
  const restoreStateBefore = {
    desktopName: null,
    cursorClipped: null,
    taskbarHidden: null,
  };
  const restoreStateAfter = {
    desktopRestored: null,
    cursorUnclipped: null,
    taskbarRestored: null,
  };

  return {
    scenarioId: scenario.scenarioId,
    category: scenario.category,
    classification,
    startedAt: manifest.startedAt ?? timestamp,
    completedAt: manifest.completedAt ?? timestamp,
    timestamp,
    version: manifest.version ?? "unknown",
    commitHash: manifest.commitHash ?? "unknown",
    machineInfo: machine,
    windowsVersion: machine.windowsProductName ?? "unknown",
    windowsBuild: machine.windowsBuild ?? "unknown",
    architecture: machine.architecture ?? "unknown",
    dpiInfo: { scale: machine.dpiScale ?? null, awareness: "unknown" },
    dpiScale: machine.dpiScale ?? null,
    monitorInfo: { count: machine.monitorCount ?? null },
    displayScenario,
    captureAndRemoteApp: captureApp,
    captureMode,
    runtimeSnapshot: null,
    policySnapshot: null,
    localScreenshot: null,
    receiverCaptureEvidence: null,
    processRemediationLog: [],
    runtimeMetrics: null,
    performanceMetrics: null,
    desktopTelemetry: null,
    faultInjectionLog,
    restoreStateBefore: null,
    restoreStateAfter: null,
    acceptanceDecision,
    knownLimitations: [reason],
    result: "not-tested",
    failureReason: reason,
    evidence: [
      { type: "runner-log", artifactPath: null },
      { type: "machine-info", artifactPath: null },
      { type: "dpi-info", artifactPath: null },
      { type: "monitor-info", artifactPath: null },
      {
        type: "runtime-snapshot",
        sessionState: "NOT_TESTED",
        captureProtectionBestEffort: true,
        guardHealth: {},
      },
      { type: "policy-snapshot", artifactPath: null },
      {
        type: "receiver-capture",
        blackFrameObserved: false,
        toolName: captureApp,
        captureMode,
        artifactPath: null,
        expectedResult: "scenario-specific",
        observedResult: "not-tested",
      },
      {
        type: "recording",
        artifactPath: null,
        toolName: captureApp,
        expectedResult: "scenario-specific",
        observedResult: "not-tested",
      },
      { type: "local-screen", artifactPath: null },
      { type: "process-remediation-log", artifactPath: null },
      { type: "runtime-metrics", ...runtimeMetrics },
      { type: "performance-metrics", ...performanceMetrics },
      { type: "desktop-telemetry", ...desktopTelemetry },
      { type: "fault-injection-log", ...faultInjectionLog },
      { type: "restore-state-before", ...restoreStateBefore },
      { type: "restore-state-after", ...restoreStateAfter },
      { type: "acceptance-decision", ...acceptanceDecision },
    ],
  };
}

function recordsFromRunManifest(manifest) {
  if (
    !manifest ||
    typeof manifest !== "object" ||
    !(
      Array.isArray(manifest.captureScenarios) ||
      Array.isArray(manifest.runtimeScenarios) ||
      Array.isArray(manifest.faultScenarios) ||
      Array.isArray(manifest.soakScenarios) ||
      Array.isArray(manifest.stressScenarios)
    )
  ) {
    return [];
  }

  const scenarios = [];
  for (const scenario of manifest.captureScenarios ?? []) {
    scenarios.push({
      scenarioId: scenario.id,
      category: "capture-validation",
      classification: scenario.classification,
      captureAndRemoteApp: scenario.app,
      captureMode: scenario.mode,
    });
  }
  for (const scenario of manifest.runtimeScenarios ?? []) {
    scenarios.push({
      scenarioId: scenario.id,
      category: "runtime-validation",
      classification: "Best Effort",
    });
  }
  for (const scenario of manifest.faultScenarios ?? []) {
    scenarios.push({
      scenarioId: `fault-${scenario.id}`,
      category: "fault-injection",
      classification: "Best Effort",
      faultScenario: scenario.id,
    });
  }
  for (const scenario of manifest.soakScenarios ?? []) {
    scenarios.push({
      scenarioId: `soak-${scenario.durationMinutes}m`,
      category: "soak-test",
      classification: "Best Effort",
      durationMinutes: scenario.durationMinutes,
    });
  }
  for (const scenario of manifest.stressScenarios ?? []) {
    scenarios.push({
      scenarioId: `stress-${scenario.id}`,
      category: "stress-test",
      classification: "Best Effort",
    });
  }
  for (const scenario of manifest.etwValidationScenarios ?? []) {
    scenarios.push({
      scenarioId: `etw-${scenario.id ?? scenario}`,
      category: "etw-producer-validation",
      classification: "Best Effort",
      faultScenario: String(scenario.id ?? scenario).includes("loss")
        ? "etw-buffer-loss"
        : null,
    });
  }
  for (const scenario of manifest.serviceValidationScenarios ?? []) {
    scenarios.push({
      scenarioId: `service-${scenario}`,
      category: "service-validation",
      classification: "Best Effort",
    });
  }
  for (const scenario of manifest.benchmarkScenarios ?? []) {
    scenarios.push({
      scenarioId: `benchmark-${scenario}`,
      category: "benchmark-validation",
      classification: "Best Effort",
    });
  }
  for (const displayScenario of manifest.matrixCoverage?.displayScenarios ?? []) {
    scenarios.push({
      scenarioId: `display-${displayScenario}`,
      category: "desktop-validation",
      classification: "Best Effort",
      displayScenario,
    });
  }

  return scenarios.map((scenario) => createNotTestedRecord(manifest, scenario));
}

function readEvidenceRecords(inputPath) {
  if (!inputPath || !fs.existsSync(inputPath)) {
    return [];
  }
  const stat = fs.statSync(inputPath);
  const files = stat.isDirectory()
    ? fs
        .readdirSync(inputPath)
        .filter((name) => name.endsWith(".json") || name.endsWith(".jsonl"))
        .map((name) => path.join(inputPath, name))
    : [inputPath];

  const records = [];
  for (const file of files) {
    const contents = fs.readFileSync(file, "utf8").trim();
    if (!contents) {
      continue;
    }
    if (file.endsWith(".jsonl")) {
      for (const line of contents.split(/\r?\n/)) {
        records.push(JSON.parse(line));
      }
    } else {
      const parsed = JSON.parse(contents);
      if (Array.isArray(parsed)) {
        records.push(...parsed);
      } else if (Array.isArray(parsed.records)) {
        records.push(...parsed.records);
      } else if (parsed.scenarioId && parsed.result) {
        records.push(parsed);
      } else {
        records.push(...recordsFromRunManifest(parsed));
      }
    }
  }
  return records;
}

function groupByCategory(records) {
  return records.reduce((groups, record) => {
    const category = record.category || "uncategorized";
    groups[category] = groups[category] || [];
    groups[category].push(record);
    return groups;
  }, {});
}

function verdictFromSummary(summary) {
  if (summary.total === 0 || summary.notTested > 0) {
    return "NOT TESTED";
  }
  if (summary.invalid > 0 || summary.failed > 0 || summary.blocked > 0) {
    return "FAIL";
  }
  if (summary.passWithLimitations > 0) {
    return "PASS WITH LIMITATIONS";
  }
  return "PASS";
}

function hasCoverageGaps(coverage) {
  return (
    coverage.missingCaptureApps.length > 0 ||
    coverage.missingDisplayScenarios.length > 0 ||
    coverage.missingFaultScenarios.length > 0
  );
}

function overallVerdict({ releaseSummary, coverage, performanceVerdict }) {
  const releaseVerdict = verdictFromSummary(releaseSummary);
  if (releaseVerdict === "FAIL" || performanceVerdict === "FAIL") {
    return "FAIL";
  }
  if (
    releaseVerdict === "NOT TESTED" ||
    performanceVerdict === "NOT TESTED" ||
    hasCoverageGaps(coverage)
  ) {
    return "NOT TESTED";
  }
  if (releaseVerdict === "PASS WITH LIMITATIONS") {
    return "PASS WITH LIMITATIONS";
  }
  return "PASS";
}

function hasRequiredCategoryGaps(categoryRows) {
  return categoryRows.some((row) => row.total === 0 || row.verdict === "NOT TESTED");
}

function buildValidationReport({
  records,
  matrix,
  schema,
  acceptance,
  generatedAt = new Date().toISOString(),
}) {
  const releaseSummary = summarizeReleaseGate(records, schema);
  const coverage = summarizeCoverage(records, matrix);
  const performanceRuns = records
    .filter((record) => record.performanceMetrics)
    .map((record) => ({
      scenarioId: record.scenarioId,
      ...record.performanceMetrics,
      runtimeTickP95Ms: record.runtimeMetrics?.runtimeTickP95Ms,
      heartbeatP95Ms: record.runtimeMetrics?.heartbeatDelayP95Ms,
    }));
  const performanceSummary = summarizePerformanceGate(performanceRuns);
  const performanceVerdict =
    performanceRuns.length === 0 ? "NOT TESTED" : performanceSummary.pass ? "PASS" : "FAIL";
  const byCategory = groupByCategory(records);
  const categoryRows = (acceptance.categories ?? []).map((category) => {
    const categoryRecords = byCategory[category.id] ?? [];
    const summary = summarizeReleaseGate(categoryRecords, schema);
    return {
      id: category.id,
      title: category.title,
      total: categoryRecords.length,
      verdict: verdictFromSummary(summary),
      expected: category.expected,
    };
  });
  const verdict = hasRequiredCategoryGaps(categoryRows)
    ? "NOT TESTED"
    : overallVerdict({
        releaseSummary,
        coverage,
        performanceVerdict,
      });
  const missingCategoryRows = categoryRows.filter(
    (row) => row.total === 0 || row.verdict === "NOT TESTED",
  );

  const markdown = [
    "# Exam Guard Native Validation Report",
    "",
    `Generated: ${generatedAt}`,
    "",
    "## Final Verdict",
    "",
    `Overall: **${verdict}**`,
    "",
    "| Metric | Value |",
    "|---|---:|",
    `| Evidence records | ${releaseSummary.total} |`,
    `| Invalid | ${releaseSummary.invalid} |`,
    `| Failed | ${releaseSummary.failed} |`,
    `| Blocked | ${releaseSummary.blocked} |`,
    `| Not tested | ${releaseSummary.notTested} |`,
    `| Pass with limitations | ${releaseSummary.passWithLimitations} |`,
    "",
    "## Category Verdicts",
    "",
    "| Category | Records | Verdict | Expected |",
    "|---|---:|---|---|",
    ...categoryRows.map(
      (row) => `| ${row.title} | ${row.total} | ${row.verdict} | ${row.expected} |`,
    ),
    "",
    "## Detailed Rejection Report",
    "",
    missingCategoryRows.length === 0
      ? "No required category gaps were detected."
      : "Release is rejected because one or more required evidence categories are missing or not tested.",
    "",
    "| Category | Records | Verdict | Required Action |",
    "|---|---:|---|---|",
    ...missingCategoryRows.map(
      (row) =>
        `| ${row.title} | ${row.total} | ${row.verdict} | Attach reviewed evidence records for ${row.id}. |`,
    ),
    "",
    "## Coverage Gaps",
    "",
    `Missing capture apps: ${coverage.missingCaptureApps.join(", ") || "none"}`,
    "",
    `Missing display scenarios: ${coverage.missingDisplayScenarios.join(", ") || "none"}`,
    "",
    `Missing fault scenarios: ${coverage.missingFaultScenarios.join(", ") || "none"}`,
    "",
    "## Performance Gate",
    "",
    `Performance records: ${performanceRuns.length}`,
    "",
    `Performance summary: **${performanceVerdict}**`,
    "",
    "## Known Limitations",
    "",
    ...(acceptance.knownLimitations?.windows ?? []).map((item) => `- Windows: ${item}`),
    ...(acceptance.knownLimitations?.electron ?? []).map((item) => `- Electron: ${item}`),
    ...(acceptance.knownLimitations?.wda ?? []).map((item) => `- WDA: ${item}`),
  ].join("\n");

  return {
    generatedAt,
    verdict,
    releaseSummary,
    coverage,
    performanceSummary,
    performanceVerdict,
    categoryRows,
    missingCategoryRows,
    markdown,
  };
}

function main(argv = process.argv.slice(2)) {
  const inputIndex = argv.indexOf("--input");
  const outputIndex = argv.indexOf("--output");
  const allowNotTested = argv.includes("--allow-not-tested");
  const inputPath = inputIndex >= 0 ? argv[inputIndex + 1] : path.join(__dirname, "results");
  const outputPath = outputIndex >= 0 ? argv[outputIndex + 1] : "";
  const matrix = readJson(path.join(__dirname, "matrix.json"));
  const schema = readJson(path.join(__dirname, "evidence-schema.json"));
  const acceptance = readJson(path.join(__dirname, "acceptance-matrix.json"));
  const report = buildValidationReport({
    records: readEvidenceRecords(inputPath),
    matrix,
    schema,
    acceptance,
  });

  if (outputPath) {
    fs.writeFileSync(outputPath, report.markdown);
  } else {
    process.stdout.write(`${report.markdown}\n`);
  }

  if (report.verdict === "FAIL") {
    return 1;
  }
  if (report.verdict === "NOT TESTED" && !allowNotTested) {
    return 2;
  }
  return 0;
}

if (require.main === module) {
  process.exitCode = main();
}

module.exports = {
  buildValidationReport,
  hasRequiredCategoryGaps,
  main,
  overallVerdict,
  readEvidenceRecords,
  recordsFromRunManifest,
  verdictFromSummary,
};
