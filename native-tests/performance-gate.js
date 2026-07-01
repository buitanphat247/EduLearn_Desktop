"use strict";

const DEFAULT_THRESHOLDS = {
  maxRuntimeTickP95Ms: 250,
  maxHeartbeatP95Ms: 150,
  maxCpuPercentAverage: 10,
  maxMemoryGrowthMbPerHour: 64,
  maxHandleGrowthPerHour: 128,
  maxThreadGrowthPerHour: 16,
};

function validatePerformanceRun(run, thresholds = DEFAULT_THRESHOLDS) {
  const failures = [];
  if (!run || typeof run !== "object") {
    return { pass: false, failures: ["run-missing"] };
  }
  const requiredNumberFields = [
    "durationMinutes",
    "runtimeTickP95Ms",
    "heartbeatP95Ms",
    "cpuPercentAverage",
    "memoryGrowthMbPerHour",
    "handleGrowthPerHour",
    "threadGrowthPerHour",
  ];
  for (const field of requiredNumberFields) {
    if (typeof run[field] !== "number" || !Number.isFinite(run[field])) {
      failures.push(`${field}-missing`);
    }
  }
  if (failures.length > 0) {
    return { pass: false, failures };
  }
  if (run.durationMinutes < 30) {
    failures.push("duration-below-30m");
  }
  if (run.runtimeTickP95Ms > thresholds.maxRuntimeTickP95Ms) {
    failures.push("runtime-tick-p95-too-high");
  }
  if (run.heartbeatP95Ms > thresholds.maxHeartbeatP95Ms) {
    failures.push("heartbeat-p95-too-high");
  }
  if (run.cpuPercentAverage > thresholds.maxCpuPercentAverage) {
    failures.push("cpu-average-too-high");
  }
  if (run.memoryGrowthMbPerHour > thresholds.maxMemoryGrowthMbPerHour) {
    failures.push("memory-growth-too-high");
  }
  if (run.handleGrowthPerHour > thresholds.maxHandleGrowthPerHour) {
    failures.push("handle-growth-too-high");
  }
  if (run.threadGrowthPerHour > thresholds.maxThreadGrowthPerHour) {
    failures.push("thread-growth-too-high");
  }
  return {
    pass: failures.length === 0,
    failures,
  };
}

function summarizePerformanceGate(runs, thresholds = DEFAULT_THRESHOLDS) {
  const validations = runs.map((run) => ({
    scenarioId: run.scenarioId,
    ...validatePerformanceRun(run, thresholds),
  }));
  return {
    pass: validations.length > 0 && validations.every((validation) => validation.pass),
    total: validations.length,
    failed: validations.filter((validation) => !validation.pass).length,
    validations,
  };
}

module.exports = {
  DEFAULT_THRESHOLDS,
  summarizePerformanceGate,
  validatePerformanceRun,
};
