"use strict";

function validateEvidenceRecord(record, schema) {
  const missingFields = [];
  for (const field of schema.requiredTopLevelFields ?? []) {
    if (!(field in record)) {
      missingFields.push(field);
    }
  }

  const evidence = Array.isArray(record.evidence) ? record.evidence : [];
  const evidenceByType = new Map(evidence.map((item) => [item.type, item]));
  for (const type of schema.requiredEvidence ?? []) {
    if (!evidenceByType.has(type)) {
      missingFields.push(`evidence:${type}`);
      continue;
    }
    const requiredFields = schema.acceptanceFields?.[type] ?? [];
    for (const field of requiredFields) {
      if (!(field in evidenceByType.get(type))) {
        missingFields.push(`evidence:${type}.${field}`);
      }
    }
  }

  if (!schema.allowedResults?.includes(record.result)) {
    missingFields.push("result");
  }
  if (
    Array.isArray(schema.allowedClassifications) &&
    !schema.allowedClassifications.includes(record.classification)
  ) {
    missingFields.push("classification");
  }

  return {
    valid: missingFields.length === 0,
    missingFields,
  };
}

function validationVerdict(record, schema) {
  const validation = validateEvidenceRecord(record, schema);
  if (!validation.valid) {
    return "FAIL";
  }
  if (record.result === "not-tested") {
    return "NOT TESTED";
  }
  if (record.result === "blocked" || record.result === "fail") {
    return "FAIL";
  }
  if (
    record.classification === "Best Effort" ||
    record.classification === "Bypass Possible" ||
    (Array.isArray(record.knownLimitations) && record.knownLimitations.length > 0)
  ) {
    return "PASS WITH LIMITATIONS";
  }
  return "PASS";
}

function summarizeReleaseGate(records, schema) {
  const validations = records.map((record) => ({
    scenarioId: record.scenarioId,
    ...validateEvidenceRecord(record, schema),
    verdict: validationVerdict(record, schema),
  }));
  const failed = validations.filter((validation) => !validation.valid);
  const blocked = records.filter((record) => record.result === "blocked");
  const failedCases = records.filter((record) => record.result === "fail");
  const notTested = records.filter((record) => record.result === "not-tested");
  const limitations = validations.filter(
    (validation) => validation.verdict === "PASS WITH LIMITATIONS",
  );
  return {
    productionReady:
      records.length > 0 &&
      failed.length === 0 &&
      blocked.length === 0 &&
      failedCases.length === 0 &&
      notTested.length === 0 &&
      limitations.length === 0,
    total: records.length,
    invalid: failed.length,
    blocked: blocked.length,
    failed: failedCases.length,
    notTested: notTested.length,
    passWithLimitations: limitations.length,
    validations,
  };
}

function summarizeCoverage(records, matrix = {}) {
  const testedRecords = records.filter((record) => record.result !== "not-tested");
  const testedApps = new Set(
    testedRecords.map((record) => record.captureAndRemoteApp).filter(Boolean),
  );
  const testedDisplayScenarios = new Set(
    testedRecords.map((record) => record.displayScenario).filter(Boolean),
  );
  const testedFaultScenarios = new Set(
    testedRecords
      .map((record) => record.faultInjectionLog?.faultScenario)
      .filter(Boolean),
  );
  const missingCaptureApps = (matrix.captureAndRemoteApps ?? []).filter((app) => !testedApps.has(app));
  const missingDisplayScenarios = (matrix.displayScenarios ?? []).filter(
    (scenario) => !testedDisplayScenarios.has(scenario),
  );
  const missingFaultScenarios = (matrix.faultScenarios ?? []).filter(
    (scenario) => !testedFaultScenarios.has(scenario),
  );

  return {
    captureAppsCovered: testedApps.size,
    displayScenariosCovered: testedDisplayScenarios.size,
    faultScenariosCovered: testedFaultScenarios.size,
    missingCaptureApps,
    missingDisplayScenarios,
    missingFaultScenarios,
  };
}

module.exports = {
  summarizeReleaseGate,
  summarizeCoverage,
  validateEvidenceRecord,
  validationVerdict,
};
