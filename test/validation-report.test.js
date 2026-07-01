const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const matrix = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "native-tests", "matrix.json"), "utf8"),
);
const schema = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "native-tests", "evidence-schema.json"),
    "utf8",
  ),
);
const acceptance = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "native-tests", "acceptance-matrix.json"),
    "utf8",
  ),
);
const {
  buildValidationReport,
  main,
  overallVerdict,
  readEvidenceRecords,
} = require("../native-tests/validation-report");

function releaseSummary(overrides = {}) {
  return {
    total: 1,
    invalid: 0,
    failed: 0,
    blocked: 0,
    notTested: 0,
    passWithLimitations: 0,
    productionReady: true,
    verdicts: [],
    ...overrides,
  };
}

function completeCoverage(overrides = {}) {
  return {
    missingCaptureApps: [],
    missingDisplayScenarios: [],
    missingFaultScenarios: [],
    ...overrides,
  };
}

test("overall validation verdict is fail-closed and preserves limitations", () => {
  assert.equal(
    overallVerdict({
      releaseSummary: releaseSummary(),
      coverage: completeCoverage(),
      performanceVerdict: "PASS",
    }),
    "PASS",
  );
  assert.equal(
    overallVerdict({
      releaseSummary: releaseSummary({ passWithLimitations: 1 }),
      coverage: completeCoverage(),
      performanceVerdict: "PASS",
    }),
    "PASS WITH LIMITATIONS",
  );
  assert.equal(
    overallVerdict({
      releaseSummary: releaseSummary(),
      coverage: completeCoverage({ missingCaptureApps: ["OBS"] }),
      performanceVerdict: "PASS",
    }),
    "NOT TESTED",
  );
  assert.equal(
    overallVerdict({
      releaseSummary: releaseSummary(),
      coverage: completeCoverage(),
      performanceVerdict: "FAIL",
    }),
    "FAIL",
  );
});

test("validation report labels an empty evidence directory as NOT TESTED", () => {
  const report = buildValidationReport({
    records: [],
    matrix,
    schema,
    acceptance,
    generatedAt: "2026-06-30T00:00:00.000Z",
  });

  assert.equal(report.verdict, "NOT TESTED");
  assert.equal(report.releaseSummary.productionReady, false);
  assert.equal(report.performanceSummary.pass, false);
  assert.equal(report.performanceVerdict, "NOT TESTED");
  assert.match(report.markdown, /Overall: \*\*NOT TESTED\*\*/);
  assert.match(report.markdown, /Performance records: 0/);
});

test("validation report CLI exits 2 for missing evidence unless explicitly allowed", () => {
  const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "edulearn-native-validation-"),
  );
  const reportPath = path.join(temporaryDirectory, "validation.md");

  try {
    assert.equal(
      main(["--input", temporaryDirectory, "--output", reportPath]),
      2,
    );
    assert.equal(
      main([
        "--input",
        temporaryDirectory,
        "--output",
        reportPath,
        "--allow-not-tested",
      ]),
      0,
    );
    assert.match(fs.readFileSync(reportPath, "utf8"), /Overall: \*\*NOT TESTED\*\*/);
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});

test("matrix run manifests become valid NOT TESTED records instead of invalid evidence", () => {
  const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "edulearn-native-manifest-"),
  );
  const manifestPath = path.join(temporaryDirectory, "matrix-run.json");
  const manifest = {
    schemaVersion: 2,
    artifactType: "native-matrix-run-manifest",
    version: "1.0.0",
    commitHash: "unknown",
    startedAt: "2026-06-30T00:00:00.000Z",
    completedAt: "2026-06-30T00:01:00.000Z",
    mode: "non-destructive",
    machine: {
      windowsProductName: "Windows 11",
      windowsBuild: "24H2",
      architecture: "X64",
      dpiScale: 125,
      monitorCount: 2,
    },
    captureScenarios: [
      {
        id: "capture-OBS-display-capture",
        app: "OBS",
        mode: "display-capture",
        classification: "Best Effort",
        status: "not-tested",
      },
    ],
    runtimeScenarios: [{ id: "runtime-tick", status: "not-tested" }],
    faultScenarios: [{ id: "kill-electron", status: "skipped" }],
    soakScenarios: [{ durationMinutes: 30, status: "not-tested" }],
    stressScenarios: [{ id: "repeated-restore", status: "not-tested" }],
    matrixCoverage: { displayScenarios: ["dual-monitor"] },
  };
  fs.writeFileSync(manifestPath, JSON.stringify(manifest));

  try {
    const records = readEvidenceRecords(temporaryDirectory);
    assert.equal(records.length, 6);
    assert.equal(records.every((record) => record.result === "not-tested"), true);
    assert.equal(records.some((record) => record.category === "desktop-validation"), true);
    const report = buildValidationReport({
      records,
      matrix,
      schema,
      acceptance,
      generatedAt: "2026-06-30T00:02:00.000Z",
    });
    assert.equal(report.releaseSummary.invalid, 0);
    assert.equal(report.releaseSummary.notTested, 6);
    assert.equal(report.verdict, "NOT TESTED");
    assert.equal(report.coverage.captureAppsCovered, 0);
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});
