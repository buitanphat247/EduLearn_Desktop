"use strict";

const DESKTOP_CORE_CHANNELS = {
  GET_RUNTIME_SNAPSHOT: "desktop-core:get-runtime-snapshot",
  REQUEST: "desktop-core:request",
  RUNTIME_CHANGED: "desktop-core:runtime-changed",
  ENTER_EXAM_DESKTOP: "desktop-core:enter-exam-desktop",
  EXAM_SHELL_EXIT: "desktop-core:exam-shell-exit",
};

const RUNTIME_CHANGED_EVENT = "edulearn:runtime-changed";

const CORE_ERROR_CODES = {
  INVALID_REQUEST: "INVALID_REQUEST",
  INVALID_COMMAND: "INVALID_COMMAND",
  CORE_NOT_CONNECTED: "CORE_NOT_CONNECTED",
  NOT_IMPLEMENTED: "NOT_IMPLEMENTED",
  IPC_FAILURE: "IPC_FAILURE",
  PROTECTION_FAILURE: "PROTECTION_FAILURE",
  POLICY_REQUIRED: "POLICY_REQUIRED",
  POLICY_VERIFICATION_FAILED: "POLICY_VERIFICATION_FAILED",
  DEVICE_KEY_FAILURE: "DEVICE_KEY_FAILURE",
  EXAM_KEY_FAILURE: "EXAM_KEY_FAILURE",
  EXAM_KEY_REQUIRED: "EXAM_KEY_REQUIRED",
  AUDIT_FAILURE: "AUDIT_FAILURE",
  AUDIT_TAMPERED: "AUDIT_TAMPERED",
};

const SESSION_STATES = {
  INIT: "INIT",
  CORE_READY: "CORE_READY",
  COMPATIBILITY_CHECK: "COMPATIBILITY_CHECK",
  LOGIN: "LOGIN",
  DEVICE_REGISTER: "DEVICE_REGISTER",
  FETCH_CONFIG: "FETCH_CONFIG",
  VERIFY_CONFIG: "VERIFY_CONFIG",
  LOAD_POLICY: "LOAD_POLICY",
  ENV_CHECK: "ENV_CHECK",
  READY: "READY",
  PREFLIGHT: "PREFLIGHT",
  PREFLIGHT_READY: "PREFLIGHT_READY",
  STARTING_EXAM_SESSION: "STARTING_EXAM_SESSION",
  SAVING_DESKTOP_STATE: "SAVING_DESKTOP_STATE",
  ENTERING_KIOSK: "ENTERING_KIOSK",
  EXAM_RUNNING_CONFIRMED: "EXAM_RUNNING_CONFIRMED",
  PROTECTION_ACTIVE: "PROTECTION_ACTIVE",
  EXAM_RUNNING: "EXAM_RUNNING",
  EXAM_EXIT_REQUESTED: "EXAM_EXIT_REQUESTED",
  EXAM_EXITING: "EXAM_EXITING",
  EXITED: "EXITED",
  PAUSED: "PAUSED",
  RECOVERY_REQUIRED: "RECOVERY_REQUIRED",
  EXIT_REQUESTED: "EXIT_REQUESTED",
  EXITING_KIOSK: "EXITING_KIOSK",
  RESTORING_DESKTOP: "RESTORING_DESKTOP",
  SUBMITTING: "SUBMITTING",
  SYNC_LOGS: "SYNC_LOGS",
  EXAM_ENDED: "EXAM_ENDED",
  IDLE: "IDLE",
  EXIT: "EXIT",
  PROTECTION_FAILED: "PROTECTION_FAILED",
  RESTORE_FAILED: "RESTORE_FAILED",
  ERROR: "ERROR",
};

const SAFE_EXAM_COMMANDS = new Set([
  "ping",
  "get_core_version",
  "shutdown",
  "get_system_info",
  "get_display_info",
  "get_process_list",
  "get_process_categories",
  "get_vm_signals",
  "get_remote_signals",
  "get_screen_capture_signals",
  "collect_precheck_snapshot",
  "collect_precheck_report",
  "preflight_kill",
  "run_preflight",
  "start_exam_session",
  "begin_exam_exit_confirmation",
  "cancel_exam_exit_confirmation",
  "exit_exam_session",
  "force_restore_desktop",
  "request_emergency_restore",
  "create_exam_desktop",
  "switch_default_desktop",
  "activate_input_lockdown",
  "deactivate_input_lockdown",
  "sync_display_topology",
  "run_runtime_monitor_tick",
  "get_protection_status",
  "get_policy_status",
  "get_audit_status",
  "verify_audit_chain",
  "drain_audit_upload_batch",
  "ack_audit_upload_batch",
  "record_audit_upload_failure",
  "get_exam_device_identity",
  "sign_exam_challenge",
  "sign_audit_upload",
  "sign_app_request",
  "check_debugger",
  "scan_process_heuristics",
  "compatibility_check",
  "verify_config",
  "load_policy",
  "check_environment",
  "start_exam",
  "enter_kiosk",
  "pause_exam",
  "resume_exam",
  "submit_exam",
  "exit_kiosk",
  "scan_processes",
  "sync_logs",
  "get_status",
  "create_recovery_snapshot",
  "restore_session",
  "check_update",
]);

function normalizeNumber(value, fallback) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function normalizeString(value, fallback = null) {
  return typeof value === "string" ? value : fallback;
}

function normalizeStringArray(value) {
  return Array.isArray(value) ? value.filter((entry) => typeof entry === "string") : null;
}

function normalizeRuntimeTelemetry(value) {
  const telemetry = value && typeof value === "object" ? value : {};
  return {
    runtimeLatencyMs: normalizeNumber(telemetry.runtimeLatencyMs, 0),
    runtimeTickDurationMs: normalizeNumber(telemetry.runtimeTickDurationMs, 0),
    watcherLatencyMs: normalizeNumber(telemetry.watcherLatencyMs, 0),
    detectionLatencyMs: normalizeNumber(telemetry.detectionLatencyMs, 0),
    classificationLatencyMs: normalizeNumber(telemetry.classificationLatencyMs, 0),
    processClassificationTimeMs: normalizeNumber(telemetry.processClassificationTimeMs, 0),
    killLatencyMs: normalizeNumber(telemetry.killLatencyMs, 0),
    remediationTimeMs: normalizeNumber(telemetry.remediationTimeMs, 0),
    recoveryLatencyMs: normalizeNumber(telemetry.recoveryLatencyMs, 0),
    queueLatencyMs: normalizeNumber(telemetry.queueLatencyMs, 0),
    producerLatencyMs: normalizeNumber(telemetry.producerLatencyMs, 0),
    guardRestartCount: normalizeNumber(telemetry.guardRestartCount, 0),
    watchdogRestartCount: normalizeNumber(telemetry.watchdogRestartCount, 0),
    eventQueueLength: normalizeNumber(telemetry.eventQueueLength, 0),
    runtimeHealth: normalizeString(telemetry.runtimeHealth, "unknown"),
  };
}

function normalizeProcessWatcher(value) {
  const watcher = value && typeof value === "object" ? value : {};
  return {
    source: normalizeString(watcher.source, "Polling"),
    eventCount: normalizeNumber(watcher.eventCount, 0),
    remediationCount: normalizeNumber(watcher.remediationCount, 0),
    ignoredCount: normalizeNumber(watcher.ignoredCount, 0),
    maxDetectionLatencyMs: normalizeNumber(watcher.maxDetectionLatencyMs, 0),
    ignoredReasons: normalizeStringArray(watcher.ignoredReasons) ?? [],
  };
}

function normalizeProcessWatcherProducer(value) {
  const producer = value && typeof value === "object" ? value : {};
  return {
    selectedSource: normalizeString(producer.selectedSource, "Polling"),
    eventDriven: Boolean(producer.eventDriven),
    fallbackReason: normalizeString(producer.fallbackReason, null),
    health: normalizeString(producer.health, "unknown"),
    producerState: normalizeString(producer.producerState, "unknown"),
    fallbackActive: Boolean(producer.fallbackActive),
    heartbeatAtMs: normalizeNumber(producer.heartbeatAtMs, null),
    activeSinceMs: normalizeNumber(producer.activeSinceMs, null),
    failureCount: normalizeNumber(producer.failureCount, 0),
    recoveryAttemptCount: normalizeNumber(producer.recoveryAttemptCount, 0),
    retryCount: normalizeNumber(producer.retryCount, 0),
    queueDepth: normalizeNumber(producer.queueDepth, 0),
    drainedEventCount: normalizeNumber(producer.drainedEventCount, 0),
    droppedEventCount: normalizeNumber(producer.droppedEventCount, 0),
    producerLatencyMs: normalizeNumber(producer.producerLatencyMs, 0),
    eventsLostCount: normalizeNumber(producer.eventsLostCount, 0),
    buffersLostCount: normalizeNumber(producer.buffersLostCount, 0),
    realtimeBuffersLostCount: normalizeNumber(producer.realtimeBuffersLostCount, 0),
    callbackLatencyMicros: normalizeNumber(producer.callbackLatencyMicros, 0),
    producerRestartCount: normalizeNumber(producer.producerRestartCount, 0),
    parseErrorCount: normalizeNumber(producer.parseErrorCount, 0),
    lastFailure: normalizeString(producer.lastFailure, null),
    unavailableProducers: Array.isArray(producer.unavailableProducers)
      ? producer.unavailableProducers.filter((entry) => entry && typeof entry === "object")
      : [],
  };
}

function normalizeRuntimeStateEngine(value) {
  const engine = value && typeof value === "object" ? value : {};
  const queueState = engine.queueState && typeof engine.queueState === "object" ? engine.queueState : {};
  const synchronizationState =
    engine.synchronizationState && typeof engine.synchronizationState === "object"
      ? engine.synchronizationState
      : {};
  return {
    runtimeVersion: normalizeString(engine.runtimeVersion, "unknown"),
    runtimeState: normalizeString(engine.runtimeState, "initializing"),
    producerState:
      engine.producerState && typeof engine.producerState === "object" ? engine.producerState : {},
    queueState: {
      capacity: normalizeNumber(queueState.capacity, 0),
      depth: normalizeNumber(queueState.depth, 0),
      droppedEvents: normalizeNumber(queueState.droppedEvents, 0),
      backpressureActive: Boolean(queueState.backpressureActive),
    },
    healthState: normalizeString(engine.healthState, "unknown"),
    synchronizationState: {
      duplicateEventCount: normalizeNumber(synchronizationState.duplicateEventCount, 0),
      lateEventCount: normalizeNumber(synchronizationState.lateEventCount, 0),
      outOfOrderEventCount: normalizeNumber(synchronizationState.outOfOrderEventCount, 0),
      pidReuseCount: normalizeNumber(synchronizationState.pidReuseCount, 0),
      exitBeforeCreateCount: normalizeNumber(synchronizationState.exitBeforeCreateCount, 0),
      mergeCount: normalizeNumber(synchronizationState.mergeCount, 0),
    },
    processIdentityCount: normalizeNumber(engine.processIdentityCount, 0),
    activeProcessCount: normalizeNumber(engine.activeProcessCount, 0),
    remediationStatus: normalizeString(engine.remediationStatus, "unknown"),
    reconciliationCount: normalizeNumber(engine.reconciliationCount, 0),
    recoveryCount: normalizeNumber(engine.recoveryCount, 0),
    droppedEvents: normalizeNumber(engine.droppedEvents, 0),
  };
}

function normalizeRuntimeEvents(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .filter((event) => event && typeof event === "object")
    .map((event) => ({
      eventId: normalizeNumber(event.eventId, 0),
      kind: normalizeString(event.kind, "Unknown"),
      severity: normalizeString(event.severity, "info"),
      timestamp: normalizeNumber(event.timestamp, 0),
      detail: normalizeString(event.detail, ""),
      metadata: event.metadata && typeof event.metadata === "object" ? event.metadata : {},
    }));
}

function normalizeAuditHealth(value) {
  const audit = value && typeof value === "object" ? value : {};
  return {
    auditEnabled: Boolean(audit.auditEnabled),
    auditHealth: normalizeString(audit.auditHealth, "disabled"),
    auditQueueDepth: normalizeNumber(audit.auditQueueDepth, 0),
    pendingUploads: normalizeNumber(audit.pendingUploads, 0),
    failedUploads: normalizeNumber(audit.failedUploads, 0),
    lastSuccessfulUpload: normalizeNumber(audit.lastSuccessfulUpload, null),
    lastFailure: normalizeString(audit.lastFailure, null),
    hashChainStatus: normalizeString(audit.hashChainStatus, "unknown"),
    syncLatencyMs: normalizeNumber(audit.syncLatencyMs, null),
  };
}

function normalizeEmergencyRestore(value) {
  const restore = value && typeof value === "object" ? value : {};
  return {
    emergencyRestoreWidgetVisible: Boolean(restore.emergencyRestoreWidgetVisible),
    emergencyRestoreWidgetState: normalizeString(restore.emergencyRestoreWidgetState, "hidden"),
    lastEmergencyRestoreRequestAt: normalizeNumber(restore.lastEmergencyRestoreRequestAt, null),
    lastEmergencyRestoreResult: normalizeString(restore.lastEmergencyRestoreResult, null),
    emergencyRestoreAttemptCount: normalizeNumber(restore.emergencyRestoreAttemptCount, 0),
    emergencyRestoreLastError: normalizeString(restore.emergencyRestoreLastError, null),
    widgetId: normalizeString(restore.widgetId, null),
    correlationId: normalizeString(restore.correlationId, null),
    requireHoldMs: normalizeNumber(restore.requireHoldMs, 2000),
  };
}

function normalizeSummary(value) {
  if (!value || typeof value !== "object") {
    return null;
  }

  const summary = value;
  if (
    typeof summary.totalProcessCount !== "number" ||
    typeof summary.monitorCount !== "number" ||
    typeof summary.browserAppCount !== "number" ||
    typeof summary.remoteAppCount !== "number" ||
    typeof summary.screenCaptureAppCount !== "number" ||
    typeof summary.vmSignalCount !== "number"
  ) {
    return null;
  }

  return {
    totalProcessCount: summary.totalProcessCount,
    monitorCount: summary.monitorCount,
    browserAppCount: summary.browserAppCount,
    remoteAppCount: summary.remoteAppCount,
    screenCaptureAppCount: summary.screenCaptureAppCount,
    vmSignalCount: summary.vmSignalCount,
  };
}

function normalizeGuardHealth(snapshot) {
  const status = (active, degraded = false) => {
    if (degraded) {
      return "degraded";
    }
    return active ? "alive" : "inactive";
  };
  const guardHealth =
    snapshot.guardHealth && typeof snapshot.guardHealth === "object" ? snapshot.guardHealth : {};

  return {
    input: normalizeString(guardHealth.input, status(Boolean(snapshot.inputHookActive))),
    keyboard: normalizeString(
      guardHealth.keyboard,
      status(Boolean(snapshot.inputHookActive || snapshot.keyboardHookActive)),
    ),
    mouse: normalizeString(guardHealth.mouse, status(Boolean(snapshot.mouseHookActive))),
    focus: normalizeString(guardHealth.focus, status(Boolean(snapshot.focusHookActive))),
    clipboard: normalizeString(guardHealth.clipboard, status(Boolean(snapshot.clipboardListenerActive))),
    overlay: normalizeString(
      guardHealth.overlay,
      status(Boolean(snapshot.overlayHealActive), Boolean(snapshot.overlayActive && !snapshot.overlayHealActive)),
    ),
    capture: normalizeString(
      guardHealth.capture,
      status(Boolean(snapshot.captureHealActive), Boolean(snapshot.captureProtectionActive && !snapshot.captureHealActive)),
    ),
    runtime: normalizeString(
      guardHealth.runtime,
      normalizeRuntimeTelemetry(snapshot.runtimeTelemetry).runtimeHealth === "healthy" ? "alive" : "degraded",
    ),
    watcher: normalizeString(
      guardHealth.watcher,
      status(Boolean(snapshot.processWatcherProducer?.selectedSource || snapshot.processWatcher?.source)),
    ),
    policy: normalizeString(guardHealth.policy, status(Boolean(snapshot.policyVersion || snapshot.policyDigestSha256))),
    runtimeMonitor: normalizeString(guardHealth.runtimeMonitor, status(Boolean(snapshot.runtimeMonitorActive))),
  };
}

function createDesktopRuntimeSnapshot(snapshot = {}) {
  const runtime = snapshot.runtime === "web" ? "web" : "electron";
  const isDesktop = Boolean(snapshot.isDesktop ?? runtime === "electron");
  const normalizedSessionState = normalizeString(
    snapshot.sessionState,
    SESSION_STATES.INIT,
  );
  const sessionState =
    normalizedSessionState === SESSION_STATES.EXAM_RUNNING
      ? SESSION_STATES.EXAM_RUNNING_CONFIRMED
      : normalizedSessionState;

  return {
    runtime,
    shell:
      snapshot.shell === "browser" || (!isDesktop && snapshot.shell !== "edulearn-desktop")
        ? "browser"
        : "edulearn-desktop",
    isDesktop,
    platform: normalizeString(snapshot.platform, isDesktop ? "win32" : "unknown"),
    safeExamMode: Boolean(snapshot.safeExamMode),
    examMode: normalizeString(snapshot.examMode, null),
    audioLockActive:
      sessionState === SESSION_STATES.EXAM_RUNNING_CONFIRMED ||
      Boolean(snapshot.audioLockActive),
    exitInProgress: Boolean(snapshot.exitInProgress),
    stateTransitionLock: Boolean(snapshot.stateTransitionLock),
    uiInteractionLocked: Boolean(snapshot.uiInteractionLocked),
    stateGovernorId: normalizeString(snapshot.stateGovernorId, null),
    stateGovernorReady: Boolean(snapshot.stateGovernorReady),
    stateGovernorSafeMode: Boolean(snapshot.stateGovernorSafeMode),
    stateGovernorProductionGatePassed: Boolean(snapshot.stateGovernorProductionGatePassed),
    stateGovernorSequenceId: normalizeNumber(snapshot.stateGovernorSequenceId, 0),
    stateGovernorLockMode:
      snapshot.stateGovernorLockMode === "EXIT_LOCK"
        ? "EXIT_LOCK"
        : null,
    stateGovernorEventQueueLength: normalizeNumber(
      snapshot.stateGovernorEventQueueLength,
      0,
    ),
    stateGovernorLastValidation: snapshot.stateGovernorLastValidation && typeof snapshot.stateGovernorLastValidation === "object"
      ? snapshot.stateGovernorLastValidation
      : null,
    kioskHandoffCompleted: Boolean(snapshot.kioskHandoffCompleted),
    nativeCoreConnected: Boolean(snapshot.nativeCoreConnected),
    coreVersion: normalizeString(snapshot.coreVersion, null),
    sessionState,
    lastCoreHeartbeat: normalizeNumber(snapshot.lastCoreHeartbeat, null),
    precheckCollectedAt: normalizeNumber(snapshot.precheckCollectedAt, null),
    precheckAvailable: Boolean(snapshot.precheckAvailable),
    precheckSummary: normalizeSummary(snapshot.precheckSummary),
    precheckStatus:
      snapshot.precheckStatus === "ready" ||
      snapshot.precheckStatus === "review" ||
      snapshot.precheckStatus === "block"
        ? snapshot.precheckStatus
        : null,
    precheckRiskScore: normalizeNumber(snapshot.precheckRiskScore, null),
    precheckRecommendations: normalizeStringArray(snapshot.precheckRecommendations),
    preflightCollectedAt: normalizeNumber(snapshot.preflightCollectedAt, null),
    preflightStatus:
      snapshot.preflightStatus === "ready" ||
      snapshot.preflightStatus === "review" ||
      snapshot.preflightStatus === "block"
        ? snapshot.preflightStatus
        : null,
    preflightCanEnterExam:
      typeof snapshot.preflightCanEnterExam === "boolean" ? snapshot.preflightCanEnterExam : null,
    preflightPrimaryReasonCode: normalizeString(snapshot.preflightPrimaryReasonCode, null),
    runtimeRiskLevel:
      snapshot.runtimeRiskLevel === "elevated" ? "elevated" : "normal",
    examProtectionActive: Boolean(snapshot.examProtectionActive),
    protectionDryRun: Boolean(snapshot.protectionDryRun),
    kioskActive: Boolean(snapshot.kioskActive),
    overlayActive: Boolean(snapshot.overlayActive),
    taskbarHidden: Boolean(snapshot.taskbarHidden),
    keyboardHookActive: Boolean(snapshot.keyboardHookActive),
    focusLockActive: Boolean(snapshot.focusLockActive),
    inputHookActive: Boolean(snapshot.inputHookActive),
    mouseHookActive: Boolean(snapshot.mouseHookActive),
    focusHookActive: Boolean(snapshot.focusHookActive),
    clipboardListenerActive: Boolean(snapshot.clipboardListenerActive),
    overlayHealActive: Boolean(snapshot.overlayHealActive),
    captureHealActive: Boolean(snapshot.captureHealActive),
    captureProtectionActive: Boolean(snapshot.captureProtectionActive),
    captureProtectionStatus: normalizeString(snapshot.captureProtectionStatus, "inactive"),
    electronContentProtectionActive: Boolean(snapshot.electronContentProtectionActive),
    rustOverlayCaptureProtectionActive: Boolean(snapshot.rustOverlayCaptureProtectionActive),
    captureProtectionBestEffort: Boolean(snapshot.captureProtectionBestEffort),
    runtimeMonitorActive: Boolean(snapshot.runtimeMonitorActive),
    activeMonitorCount: normalizeNumber(snapshot.activeMonitorCount, 0),
    blackOverlayCount: normalizeNumber(snapshot.blackOverlayCount, 0),
    lastRuntimeEventAt: normalizeNumber(snapshot.lastRuntimeEventAt, null),
    errorCode: normalizeString(snapshot.errorCode, null),
    policyVersion: normalizeString(snapshot.policyVersion, null),
    policySource: normalizeString(snapshot.policySource, null),
    policyDigestSha256: normalizeString(snapshot.policyDigestSha256, null),
    signedPolicyRequired: Boolean(snapshot.signedPolicyRequired),
    emergencyRestore: normalizeEmergencyRestore(snapshot.emergencyRestore),
    guardHealth: normalizeGuardHealth(snapshot),
    runtimeTelemetry: normalizeRuntimeTelemetry(snapshot.runtimeTelemetry),
    processWatcher: normalizeProcessWatcher(snapshot.processWatcher),
    processWatcherProducer: normalizeProcessWatcherProducer(snapshot.processWatcherProducer),
    runtimeStateEngine: normalizeRuntimeStateEngine(snapshot.runtimeStateEngine),
    runtimeEvents: normalizeRuntimeEvents(snapshot.runtimeEvents),
    audit: normalizeAuditHealth(snapshot.audit),
  };
}

function createCoreSuccessResponse(requestId, data = {}) {
  return {
    requestId: typeof requestId === "string" && requestId.trim() ? requestId : `desktop-core-${Date.now()}`,
    ok: true,
    data,
    error: null,
  };
}

function createCoreErrorResponse(requestId, code, message) {
  return {
    requestId: typeof requestId === "string" && requestId.trim() ? requestId : `desktop-core-${Date.now()}`,
    ok: false,
    data: null,
    error: {
      code: typeof code === "string" ? code : CORE_ERROR_CODES.IPC_FAILURE,
      message: typeof message === "string" && message.trim() ? message : "Desktop core request failed.",
    },
  };
}

function isSafeExamCommand(value) {
  return typeof value === "string" && SAFE_EXAM_COMMANDS.has(value);
}

module.exports = {
  CORE_ERROR_CODES,
  DESKTOP_CORE_CHANNELS,
  RUNTIME_CHANGED_EVENT,
  SAFE_EXAM_COMMANDS,
  SESSION_STATES,
  createCoreErrorResponse,
  createCoreSuccessResponse,
  createDesktopRuntimeSnapshot,
  isSafeExamCommand,
};
