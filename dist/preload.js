var __getOwnPropNames = Object.getOwnPropertyNames;
var __commonJS = (cb, mod) => function __require() {
  try {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  } catch (e) {
    throw mod = 0, e;
  }
};

// src/contracts/safe-exam.js
var require_safe_exam = __commonJS({
  "src/contracts/safe-exam.js"(exports2, module2) {
    "use strict";
    var DESKTOP_CORE_CHANNELS2 = {
      GET_RUNTIME_SNAPSHOT: "desktop-core:get-runtime-snapshot",
      REQUEST: "desktop-core:request",
      RUNTIME_CHANGED: "desktop-core:runtime-changed",
      ENTER_EXAM_DESKTOP: "desktop-core:enter-exam-desktop",
      EXAM_SHELL_EXIT: "desktop-core:exam-shell-exit"
    };
    var RUNTIME_CHANGED_EVENT2 = "edulearn:runtime-changed";
    var CORE_ERROR_CODES = {
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
      AUDIT_TAMPERED: "AUDIT_TAMPERED"
    };
    var SESSION_STATES2 = {
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
      ERROR: "ERROR"
    };
    var SAFE_EXAM_COMMANDS = /* @__PURE__ */ new Set([
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
      "check_update"
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
        runtimeHealth: normalizeString(telemetry.runtimeHealth, "unknown")
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
        ignoredReasons: normalizeStringArray(watcher.ignoredReasons) ?? []
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
        unavailableProducers: Array.isArray(producer.unavailableProducers) ? producer.unavailableProducers.filter((entry) => entry && typeof entry === "object") : []
      };
    }
    function normalizeRuntimeStateEngine(value) {
      const engine = value && typeof value === "object" ? value : {};
      const queueState = engine.queueState && typeof engine.queueState === "object" ? engine.queueState : {};
      const synchronizationState = engine.synchronizationState && typeof engine.synchronizationState === "object" ? engine.synchronizationState : {};
      return {
        runtimeVersion: normalizeString(engine.runtimeVersion, "unknown"),
        runtimeState: normalizeString(engine.runtimeState, "initializing"),
        producerState: engine.producerState && typeof engine.producerState === "object" ? engine.producerState : {},
        queueState: {
          capacity: normalizeNumber(queueState.capacity, 0),
          depth: normalizeNumber(queueState.depth, 0),
          droppedEvents: normalizeNumber(queueState.droppedEvents, 0),
          backpressureActive: Boolean(queueState.backpressureActive)
        },
        healthState: normalizeString(engine.healthState, "unknown"),
        synchronizationState: {
          duplicateEventCount: normalizeNumber(synchronizationState.duplicateEventCount, 0),
          lateEventCount: normalizeNumber(synchronizationState.lateEventCount, 0),
          outOfOrderEventCount: normalizeNumber(synchronizationState.outOfOrderEventCount, 0),
          pidReuseCount: normalizeNumber(synchronizationState.pidReuseCount, 0),
          exitBeforeCreateCount: normalizeNumber(synchronizationState.exitBeforeCreateCount, 0),
          mergeCount: normalizeNumber(synchronizationState.mergeCount, 0)
        },
        processIdentityCount: normalizeNumber(engine.processIdentityCount, 0),
        activeProcessCount: normalizeNumber(engine.activeProcessCount, 0),
        remediationStatus: normalizeString(engine.remediationStatus, "unknown"),
        reconciliationCount: normalizeNumber(engine.reconciliationCount, 0),
        recoveryCount: normalizeNumber(engine.recoveryCount, 0),
        droppedEvents: normalizeNumber(engine.droppedEvents, 0)
      };
    }
    function normalizeRuntimeEvents(value) {
      if (!Array.isArray(value)) {
        return [];
      }
      return value.filter((event) => event && typeof event === "object").map((event) => ({
        eventId: normalizeNumber(event.eventId, 0),
        kind: normalizeString(event.kind, "Unknown"),
        severity: normalizeString(event.severity, "info"),
        timestamp: normalizeNumber(event.timestamp, 0),
        detail: normalizeString(event.detail, ""),
        metadata: event.metadata && typeof event.metadata === "object" ? event.metadata : {}
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
        syncLatencyMs: normalizeNumber(audit.syncLatencyMs, null)
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
        requireHoldMs: normalizeNumber(restore.requireHoldMs, 2e3)
      };
    }
    function normalizeSummary(value) {
      if (!value || typeof value !== "object") {
        return null;
      }
      const summary = value;
      if (typeof summary.totalProcessCount !== "number" || typeof summary.monitorCount !== "number" || typeof summary.browserAppCount !== "number" || typeof summary.remoteAppCount !== "number" || typeof summary.screenCaptureAppCount !== "number" || typeof summary.vmSignalCount !== "number") {
        return null;
      }
      return {
        totalProcessCount: summary.totalProcessCount,
        monitorCount: summary.monitorCount,
        browserAppCount: summary.browserAppCount,
        remoteAppCount: summary.remoteAppCount,
        screenCaptureAppCount: summary.screenCaptureAppCount,
        vmSignalCount: summary.vmSignalCount
      };
    }
    function normalizeGuardHealth(snapshot) {
      const status = (active, degraded = false) => {
        if (degraded) {
          return "degraded";
        }
        return active ? "alive" : "inactive";
      };
      const guardHealth = snapshot.guardHealth && typeof snapshot.guardHealth === "object" ? snapshot.guardHealth : {};
      return {
        input: normalizeString(guardHealth.input, status(Boolean(snapshot.inputHookActive))),
        keyboard: normalizeString(
          guardHealth.keyboard,
          status(Boolean(snapshot.inputHookActive || snapshot.keyboardHookActive))
        ),
        mouse: normalizeString(guardHealth.mouse, status(Boolean(snapshot.mouseHookActive))),
        focus: normalizeString(guardHealth.focus, status(Boolean(snapshot.focusHookActive))),
        clipboard: normalizeString(guardHealth.clipboard, status(Boolean(snapshot.clipboardListenerActive))),
        overlay: normalizeString(
          guardHealth.overlay,
          status(Boolean(snapshot.overlayHealActive), Boolean(snapshot.overlayActive && !snapshot.overlayHealActive))
        ),
        capture: normalizeString(
          guardHealth.capture,
          status(Boolean(snapshot.captureHealActive), Boolean(snapshot.captureProtectionActive && !snapshot.captureHealActive))
        ),
        runtime: normalizeString(
          guardHealth.runtime,
          normalizeRuntimeTelemetry(snapshot.runtimeTelemetry).runtimeHealth === "healthy" ? "alive" : "degraded"
        ),
        watcher: normalizeString(
          guardHealth.watcher,
          status(Boolean(snapshot.processWatcherProducer?.selectedSource || snapshot.processWatcher?.source))
        ),
        policy: normalizeString(guardHealth.policy, status(Boolean(snapshot.policyVersion || snapshot.policyDigestSha256))),
        runtimeMonitor: normalizeString(guardHealth.runtimeMonitor, status(Boolean(snapshot.runtimeMonitorActive)))
      };
    }
    function createDesktopRuntimeSnapshot2(snapshot = {}) {
      const runtime = snapshot.runtime === "web" ? "web" : "electron";
      const isDesktop = Boolean(snapshot.isDesktop ?? runtime === "electron");
      const normalizedSessionState = normalizeString(
        snapshot.sessionState,
        SESSION_STATES2.INIT
      );
      const sessionState = normalizedSessionState === SESSION_STATES2.EXAM_RUNNING ? SESSION_STATES2.EXAM_RUNNING_CONFIRMED : normalizedSessionState;
      return {
        runtime,
        shell: snapshot.shell === "browser" || !isDesktop && snapshot.shell !== "edulearn-desktop" ? "browser" : "edulearn-desktop",
        isDesktop,
        platform: normalizeString(snapshot.platform, isDesktop ? "win32" : "unknown"),
        safeExamMode: Boolean(snapshot.safeExamMode),
        examMode: normalizeString(snapshot.examMode, null),
        audioLockActive: sessionState === SESSION_STATES2.EXAM_RUNNING_CONFIRMED || Boolean(snapshot.audioLockActive),
        exitInProgress: Boolean(snapshot.exitInProgress),
        stateTransitionLock: Boolean(snapshot.stateTransitionLock),
        uiInteractionLocked: Boolean(snapshot.uiInteractionLocked),
        stateGovernorId: normalizeString(snapshot.stateGovernorId, null),
        stateGovernorReady: Boolean(snapshot.stateGovernorReady),
        stateGovernorSafeMode: Boolean(snapshot.stateGovernorSafeMode),
        stateGovernorProductionGatePassed: Boolean(snapshot.stateGovernorProductionGatePassed),
        stateGovernorSequenceId: normalizeNumber(snapshot.stateGovernorSequenceId, 0),
        stateGovernorLockMode: snapshot.stateGovernorLockMode === "EXIT_LOCK" ? "EXIT_LOCK" : null,
        stateGovernorEventQueueLength: normalizeNumber(
          snapshot.stateGovernorEventQueueLength,
          0
        ),
        stateGovernorLastValidation: snapshot.stateGovernorLastValidation && typeof snapshot.stateGovernorLastValidation === "object" ? snapshot.stateGovernorLastValidation : null,
        kioskHandoffCompleted: Boolean(snapshot.kioskHandoffCompleted),
        nativeCoreConnected: Boolean(snapshot.nativeCoreConnected),
        coreVersion: normalizeString(snapshot.coreVersion, null),
        sessionState,
        lastCoreHeartbeat: normalizeNumber(snapshot.lastCoreHeartbeat, null),
        precheckCollectedAt: normalizeNumber(snapshot.precheckCollectedAt, null),
        precheckAvailable: Boolean(snapshot.precheckAvailable),
        precheckSummary: normalizeSummary(snapshot.precheckSummary),
        precheckStatus: snapshot.precheckStatus === "ready" || snapshot.precheckStatus === "review" || snapshot.precheckStatus === "block" ? snapshot.precheckStatus : null,
        precheckRiskScore: normalizeNumber(snapshot.precheckRiskScore, null),
        precheckRecommendations: normalizeStringArray(snapshot.precheckRecommendations),
        preflightCollectedAt: normalizeNumber(snapshot.preflightCollectedAt, null),
        preflightStatus: snapshot.preflightStatus === "ready" || snapshot.preflightStatus === "review" || snapshot.preflightStatus === "block" ? snapshot.preflightStatus : null,
        preflightCanEnterExam: typeof snapshot.preflightCanEnterExam === "boolean" ? snapshot.preflightCanEnterExam : null,
        preflightPrimaryReasonCode: normalizeString(snapshot.preflightPrimaryReasonCode, null),
        runtimeRiskLevel: snapshot.runtimeRiskLevel === "elevated" ? "elevated" : "normal",
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
        audit: normalizeAuditHealth(snapshot.audit)
      };
    }
    function createCoreSuccessResponse(requestId, data = {}) {
      return {
        requestId: typeof requestId === "string" && requestId.trim() ? requestId : `desktop-core-${Date.now()}`,
        ok: true,
        data,
        error: null
      };
    }
    function createCoreErrorResponse(requestId, code, message) {
      return {
        requestId: typeof requestId === "string" && requestId.trim() ? requestId : `desktop-core-${Date.now()}`,
        ok: false,
        data: null,
        error: {
          code: typeof code === "string" ? code : CORE_ERROR_CODES.IPC_FAILURE,
          message: typeof message === "string" && message.trim() ? message : "Desktop core request failed."
        }
      };
    }
    function isSafeExamCommand(value) {
      return typeof value === "string" && SAFE_EXAM_COMMANDS.has(value);
    }
    module2.exports = {
      CORE_ERROR_CODES,
      DESKTOP_CORE_CHANNELS: DESKTOP_CORE_CHANNELS2,
      RUNTIME_CHANGED_EVENT: RUNTIME_CHANGED_EVENT2,
      SAFE_EXAM_COMMANDS,
      SESSION_STATES: SESSION_STATES2,
      createCoreErrorResponse,
      createCoreSuccessResponse,
      createDesktopRuntimeSnapshot: createDesktopRuntimeSnapshot2,
      isSafeExamCommand
    };
  }
});

// src/contracts/trace-channel.js
var require_trace_channel = __commonJS({
  "src/contracts/trace-channel.js"(exports2, module2) {
    "use strict";
    module2.exports = { TRACE_CHANNEL: "exam-guard:trace" };
  }
});

// src/capability-token.js
var require_capability_token = __commonJS({
  "src/capability-token.js"(exports2, module2) {
    "use strict";
    var CAPABILITY_TOKEN_ARG_PREFIX = "--edulearn-cap-token=";
    var EXAM_SHELL_LAUNCH_ARG = "--edulearn-exam-shell=1";
    var EXAM_SESSION_ARG_PREFIX = "--edulearn-exam-session=";
    var EXAM_CODE_ARG_PREFIX = "--edulearn-exam-code=";
    var cachedToken = null;
    function getCapabilityToken() {
      if (!cachedToken) {
        const crypto = require("crypto");
        cachedToken = crypto.randomBytes(32).toString("hex");
      }
      return cachedToken;
    }
    function capabilityTokenLaunchArg() {
      return `${CAPABILITY_TOKEN_ARG_PREFIX}${getCapabilityToken()}`;
    }
    function readCapabilityTokenFromArgv2(argv) {
      const args = Array.isArray(argv) ? argv : [];
      for (const entry of args) {
        if (typeof entry === "string" && entry.startsWith(CAPABILITY_TOKEN_ARG_PREFIX)) {
          return entry.slice(CAPABILITY_TOKEN_ARG_PREFIX.length);
        }
      }
      return null;
    }
    function isExamShellFromArgv2(argv) {
      const args = Array.isArray(argv) ? argv : [];
      return args.includes(EXAM_SHELL_LAUNCH_ARG);
    }
    function examShellIdentityLaunchArgs(sessionId, examCode) {
      const args = [];
      if (sessionId) {
        args.push(`${EXAM_SESSION_ARG_PREFIX}${sessionId}`);
      }
      if (examCode) {
        args.push(`${EXAM_CODE_ARG_PREFIX}${examCode}`);
      }
      return args;
    }
    function readExamShellIdentityFromArgv2(argv) {
      const args = Array.isArray(argv) ? argv : [];
      let sessionId = null;
      let examCode = null;
      for (const entry of args) {
        if (typeof entry !== "string") {
          continue;
        }
        if (entry.startsWith(EXAM_SESSION_ARG_PREFIX)) {
          sessionId = entry.slice(EXAM_SESSION_ARG_PREFIX.length) || null;
        } else if (entry.startsWith(EXAM_CODE_ARG_PREFIX)) {
          examCode = entry.slice(EXAM_CODE_ARG_PREFIX.length) || null;
        }
      }
      return { sessionId, examCode };
    }
    function verifyCapabilityToken(candidate) {
      if (typeof candidate !== "string" || candidate.length === 0) {
        return false;
      }
      const expected = getCapabilityToken();
      const a = Buffer.from(candidate, "utf8");
      const b = Buffer.from(expected, "utf8");
      if (a.length !== b.length) {
        return false;
      }
      try {
        const crypto = require("crypto");
        return crypto.timingSafeEqual(a, b);
      } catch {
        return false;
      }
    }
    module2.exports = {
      CAPABILITY_TOKEN_ARG_PREFIX,
      EXAM_SHELL_LAUNCH_ARG,
      EXAM_SESSION_ARG_PREFIX,
      EXAM_CODE_ARG_PREFIX,
      getCapabilityToken,
      capabilityTokenLaunchArg,
      examShellIdentityLaunchArgs,
      readCapabilityTokenFromArgv: readCapabilityTokenFromArgv2,
      isExamShellFromArgv: isExamShellFromArgv2,
      readExamShellIdentityFromArgv: readExamShellIdentityFromArgv2,
      verifyCapabilityToken
    };
  }
});

// src/preload.js
var { contextBridge, ipcRenderer } = require("electron");
var {
  DESKTOP_CORE_CHANNELS,
  RUNTIME_CHANGED_EVENT,
  SESSION_STATES,
  createDesktopRuntimeSnapshot
} = require_safe_exam();
var { TRACE_CHANNEL } = require_trace_channel();
var {
  readCapabilityTokenFromArgv,
  isExamShellFromArgv,
  readExamShellIdentityFromArgv
} = require_capability_token();
function readEnv(name) {
  try {
    return typeof process !== "undefined" && process.env ? process.env[name] : void 0;
  } catch {
    return void 0;
  }
}
var CAPABILITY_TOKEN = readCapabilityTokenFromArgv(process.argv);
var IS_ISOLATED_EXAM_SHELL = isExamShellFromArgv(process.argv) || readEnv("EDULEARN_EXAM_SHELL") === "1";
var EXAM_SHELL_IDENTITY = readExamShellIdentityFromArgv(process.argv);
var EXAM_SHELL_SESSION_ID = EXAM_SHELL_IDENTITY.sessionId || readEnv("EDULEARN_EXAM_SHELL_SESSION_ID") || null;
var EXAM_SHELL_EXAM_CODE = EXAM_SHELL_IDENTITY.examCode || readEnv("EDULEARN_EXAM_SHELL_EXAM_CODE") || null;
function invokeCore(channel, payload) {
  return payload === void 0 ? ipcRenderer.invoke(channel, CAPABILITY_TOKEN) : ipcRenderer.invoke(channel, CAPABILITY_TOKEN, payload);
}
var runtimeSnapshot = createDesktopRuntimeSnapshot({
  platform: process.platform
});
var commandCounter = 0;
function applyRuntimeSnapshot(snapshot) {
  const incomingGovernorId = typeof snapshot?.stateGovernorId === "string" ? snapshot.stateGovernorId : null;
  const incomingSequenceId = typeof snapshot?.stateGovernorSequenceId === "number" ? snapshot.stateGovernorSequenceId : null;
  const isSameGovernor = incomingGovernorId !== null && incomingGovernorId === runtimeSnapshot.stateGovernorId;
  if (isSameGovernor && (incomingSequenceId === null || incomingSequenceId <= runtimeSnapshot.stateGovernorSequenceId)) {
    ipcRenderer.send(TRACE_CHANNEL, {
      kind: "electron_loop",
      action: "renderer_snapshot_discarded",
      decision: "stale",
      state: runtimeSnapshot.sessionState,
      reason: `incoming_sequence=${String(incomingSequenceId)} current_sequence=${runtimeSnapshot.stateGovernorSequenceId}`
    });
    return runtimeSnapshot;
  }
  const previousSessionState = runtimeSnapshot.sessionState;
  runtimeSnapshot = createDesktopRuntimeSnapshot({
    ...runtimeSnapshot,
    ...snapshot || {}
  });
  document.documentElement.dataset.runtime = runtimeSnapshot.runtime;
  document.documentElement.dataset.shell = runtimeSnapshot.shell;
  document.documentElement.dataset.desktop = runtimeSnapshot.isDesktop ? "true" : "false";
  document.documentElement.dataset.safeExamMode = runtimeSnapshot.safeExamMode ? "true" : "false";
  document.documentElement.dataset.examMode = runtimeSnapshot.examMode ?? "";
  document.documentElement.dataset.audioLockActive = runtimeSnapshot.audioLockActive ? "true" : "false";
  document.documentElement.dataset.kioskHandoffCompleted = runtimeSnapshot.kioskHandoffCompleted ? "true" : "false";
  document.documentElement.dataset.nativeCoreConnected = runtimeSnapshot.nativeCoreConnected ? "true" : "false";
  document.documentElement.dataset.runtimePlatform = runtimeSnapshot.platform;
  document.documentElement.dataset.coreVersion = runtimeSnapshot.coreVersion ?? "";
  document.documentElement.dataset.sessionState = runtimeSnapshot.sessionState ?? SESSION_STATES.INIT;
  document.documentElement.dataset.stateGovernorSequenceId = String(
    runtimeSnapshot.stateGovernorSequenceId ?? 0
  );
  document.documentElement.dataset.stateGovernorLockMode = runtimeSnapshot.stateGovernorLockMode ?? "";
  document.documentElement.dataset.lastCoreHeartbeat = runtimeSnapshot.lastCoreHeartbeat ? String(runtimeSnapshot.lastCoreHeartbeat) : "";
  document.documentElement.dataset.precheckCollectedAt = runtimeSnapshot.precheckCollectedAt ? String(runtimeSnapshot.precheckCollectedAt) : "";
  document.documentElement.dataset.precheckAvailable = runtimeSnapshot.precheckAvailable ? "true" : "false";
  document.documentElement.dataset.precheckSummary = runtimeSnapshot.precheckSummary ? JSON.stringify(runtimeSnapshot.precheckSummary) : "";
  document.documentElement.dataset.precheckStatus = runtimeSnapshot.precheckStatus ?? "";
  document.documentElement.dataset.precheckRiskScore = typeof runtimeSnapshot.precheckRiskScore === "number" ? String(runtimeSnapshot.precheckRiskScore) : "";
  document.documentElement.dataset.precheckRecommendations = Array.isArray(runtimeSnapshot.precheckRecommendations) ? JSON.stringify(runtimeSnapshot.precheckRecommendations) : "";
  document.documentElement.dataset.preflightCollectedAt = runtimeSnapshot.preflightCollectedAt ? String(runtimeSnapshot.preflightCollectedAt) : "";
  document.documentElement.dataset.preflightStatus = runtimeSnapshot.preflightStatus ?? "";
  document.documentElement.dataset.preflightCanEnterExam = typeof runtimeSnapshot.preflightCanEnterExam === "boolean" ? String(runtimeSnapshot.preflightCanEnterExam) : "";
  document.documentElement.dataset.preflightPrimaryReasonCode = runtimeSnapshot.preflightPrimaryReasonCode ?? "";
  document.documentElement.dataset.examProtectionActive = runtimeSnapshot.examProtectionActive ? "true" : "false";
  document.documentElement.dataset.protectionDryRun = runtimeSnapshot.protectionDryRun ? "true" : "false";
  document.documentElement.dataset.kioskActive = runtimeSnapshot.kioskActive ? "true" : "false";
  document.documentElement.dataset.overlayActive = runtimeSnapshot.overlayActive ? "true" : "false";
  document.documentElement.dataset.taskbarHidden = runtimeSnapshot.taskbarHidden ? "true" : "false";
  document.documentElement.dataset.keyboardHookActive = runtimeSnapshot.keyboardHookActive ? "true" : "false";
  document.documentElement.dataset.focusLockActive = runtimeSnapshot.focusLockActive ? "true" : "false";
  document.documentElement.dataset.captureProtectionActive = runtimeSnapshot.captureProtectionActive ? "true" : "false";
  document.documentElement.dataset.captureProtectionStatus = runtimeSnapshot.captureProtectionStatus ?? "inactive";
  document.documentElement.dataset.electronContentProtectionActive = runtimeSnapshot.electronContentProtectionActive ? "true" : "false";
  document.documentElement.dataset.rustOverlayCaptureProtectionActive = runtimeSnapshot.rustOverlayCaptureProtectionActive ? "true" : "false";
  document.documentElement.dataset.captureProtectionBestEffort = runtimeSnapshot.captureProtectionBestEffort ? "true" : "false";
  document.documentElement.dataset.runtimeMonitorActive = runtimeSnapshot.runtimeMonitorActive ? "true" : "false";
  document.documentElement.dataset.activeMonitorCount = String(runtimeSnapshot.activeMonitorCount ?? 0);
  document.documentElement.dataset.blackOverlayCount = String(runtimeSnapshot.blackOverlayCount ?? 0);
  document.documentElement.dataset.lastRuntimeEventAt = runtimeSnapshot.lastRuntimeEventAt ? String(runtimeSnapshot.lastRuntimeEventAt) : "";
  document.documentElement.dataset.coreErrorCode = runtimeSnapshot.errorCode ?? "";
  document.documentElement.dataset.guardHealth = JSON.stringify(runtimeSnapshot.guardHealth ?? {});
  if (typeof previousSessionState === "string" && previousSessionState !== runtimeSnapshot.sessionState) {
    const audioState = runtimeSnapshot.sessionState === SESSION_STATES.EXAM_EXITING || runtimeSnapshot.sessionState === SESSION_STATES.EXITED ? "RESTORE" : runtimeSnapshot.exitInProgress || runtimeSnapshot.sessionState === SESSION_STATES.ENTERING_KIOSK ? "HOLD" : runtimeSnapshot.audioLockActive ? "MUTE" : "RESTORE";
    const uiShellMode = runtimeSnapshot.sessionState === SESSION_STATES.EXAM_RUNNING_CONFIRMED ? "ExamShellLayout" : [
      SESSION_STATES.STARTING_EXAM_SESSION,
      SESSION_STATES.ENTERING_KIOSK,
      SESSION_STATES.EXAM_EXIT_REQUESTED,
      SESSION_STATES.EXAM_EXITING
    ].includes(runtimeSnapshot.sessionState) ? "AtomicLoadingScreen" : "AppLayout";
    console.log("[STATE_TRACE]", {
      from: previousSessionState,
      to: runtimeSnapshot.sessionState,
      source: "preload-governor-snapshot",
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      governorId: runtimeSnapshot.stateGovernorId,
      kioskFlag: runtimeSnapshot.kioskActive,
      overlayFlag: runtimeSnapshot.overlayActive,
      audioState,
      inputLock: Boolean(
        runtimeSnapshot.uiInteractionLocked || runtimeSnapshot.stateTransitionLock || [
          SESSION_STATES.STARTING_EXAM_SESSION,
          SESSION_STATES.ENTERING_KIOSK,
          SESSION_STATES.RECOVERY_REQUIRED,
          SESSION_STATES.EXAM_EXIT_REQUESTED,
          SESSION_STATES.EXAM_EXITING
        ].includes(runtimeSnapshot.sessionState)
      ),
      uiShellMode
    });
    ipcRenderer.send(TRACE_CHANNEL, {
      kind: "state_trace",
      from: previousSessionState,
      to: runtimeSnapshot.sessionState,
      source: "preload",
      reason: "runtime_snapshot_applied"
    });
  }
  window.dispatchEvent(
    new CustomEvent(RUNTIME_CHANGED_EVENT, {
      detail: runtimeSnapshot
    })
  );
  return runtimeSnapshot;
}
function buildCommandRequest(command) {
  commandCounter += 1;
  return {
    requestId: typeof command?.requestId === "string" && command.requestId.trim() ? command.requestId : `renderer-${Date.now()}-${commandCounter}`,
    cmd: command?.cmd,
    payload: command?.payload ?? {}
  };
}
contextBridge.exposeInMainWorld("desktopRuntime", {
  getSnapshot: () => runtimeSnapshot,
  get runtime() {
    return runtimeSnapshot.runtime;
  },
  get shell() {
    return runtimeSnapshot.shell;
  },
  get isDesktop() {
    return runtimeSnapshot.isDesktop;
  },
  get platform() {
    return runtimeSnapshot.platform;
  },
  get safeExamMode() {
    return runtimeSnapshot.safeExamMode;
  },
  get examMode() {
    return runtimeSnapshot.examMode;
  },
  get audioLockActive() {
    return runtimeSnapshot.audioLockActive;
  },
  get kioskHandoffCompleted() {
    return runtimeSnapshot.kioskHandoffCompleted;
  },
  get nativeCoreConnected() {
    return runtimeSnapshot.nativeCoreConnected;
  },
  get coreVersion() {
    return runtimeSnapshot.coreVersion;
  },
  get sessionState() {
    return runtimeSnapshot.sessionState;
  },
  get stateGovernorSequenceId() {
    return runtimeSnapshot.stateGovernorSequenceId;
  },
  get stateGovernorLockMode() {
    return runtimeSnapshot.stateGovernorLockMode;
  },
  get stateGovernorEventQueueLength() {
    return runtimeSnapshot.stateGovernorEventQueueLength;
  },
  get lastCoreHeartbeat() {
    return runtimeSnapshot.lastCoreHeartbeat;
  },
  get precheckCollectedAt() {
    return runtimeSnapshot.precheckCollectedAt;
  },
  get precheckAvailable() {
    return runtimeSnapshot.precheckAvailable;
  },
  get precheckSummary() {
    return runtimeSnapshot.precheckSummary;
  },
  get precheckStatus() {
    return runtimeSnapshot.precheckStatus;
  },
  get precheckRiskScore() {
    return runtimeSnapshot.precheckRiskScore;
  },
  get precheckRecommendations() {
    return runtimeSnapshot.precheckRecommendations;
  },
  get preflightCollectedAt() {
    return runtimeSnapshot.preflightCollectedAt;
  },
  get preflightStatus() {
    return runtimeSnapshot.preflightStatus;
  },
  get preflightCanEnterExam() {
    return runtimeSnapshot.preflightCanEnterExam;
  },
  get preflightPrimaryReasonCode() {
    return runtimeSnapshot.preflightPrimaryReasonCode;
  },
  get examProtectionActive() {
    return runtimeSnapshot.examProtectionActive;
  },
  get protectionDryRun() {
    return runtimeSnapshot.protectionDryRun;
  },
  get kioskActive() {
    return runtimeSnapshot.kioskActive;
  },
  get overlayActive() {
    return runtimeSnapshot.overlayActive;
  },
  get taskbarHidden() {
    return runtimeSnapshot.taskbarHidden;
  },
  get keyboardHookActive() {
    return runtimeSnapshot.keyboardHookActive;
  },
  get focusLockActive() {
    return runtimeSnapshot.focusLockActive;
  },
  get captureProtectionActive() {
    return runtimeSnapshot.captureProtectionActive;
  },
  get captureProtectionStatus() {
    return runtimeSnapshot.captureProtectionStatus;
  },
  get electronContentProtectionActive() {
    return runtimeSnapshot.electronContentProtectionActive;
  },
  get rustOverlayCaptureProtectionActive() {
    return runtimeSnapshot.rustOverlayCaptureProtectionActive;
  },
  get captureProtectionBestEffort() {
    return runtimeSnapshot.captureProtectionBestEffort;
  },
  get runtimeMonitorActive() {
    return runtimeSnapshot.runtimeMonitorActive;
  },
  get activeMonitorCount() {
    return runtimeSnapshot.activeMonitorCount;
  },
  get blackOverlayCount() {
    return runtimeSnapshot.blackOverlayCount;
  },
  get lastRuntimeEventAt() {
    return runtimeSnapshot.lastRuntimeEventAt;
  },
  get errorCode() {
    return runtimeSnapshot.errorCode;
  },
  get guardHealth() {
    return runtimeSnapshot.guardHealth;
  },
  get policyVersion() {
    return runtimeSnapshot.policyVersion;
  },
  get policySource() {
    return runtimeSnapshot.policySource;
  },
  get signedPolicyRequired() {
    return runtimeSnapshot.signedPolicyRequired;
  },
  onRuntimeChanged: (handler) => {
    const listener = (event) => handler(event.detail);
    window.addEventListener(RUNTIME_CHANGED_EVENT, listener);
    return () => window.removeEventListener(RUNTIME_CHANGED_EVENT, listener);
  }
});
contextBridge.exposeInMainWorld("desktopCore", {
  getRuntimeSnapshot: () => invokeCore(DESKTOP_CORE_CHANNELS.GET_RUNTIME_SNAPSHOT),
  request: (command) => invokeCore(DESKTOP_CORE_CHANNELS.REQUEST, buildCommandRequest(command)),
  startExamSession: (payload) => invokeCore(
    DESKTOP_CORE_CHANNELS.REQUEST,
    buildCommandRequest({
      cmd: "start_exam_session",
      payload
    })
  ).then(async (response) => {
    if (response?.ok) {
      const governedSnapshot = await invokeCore(
        DESKTOP_CORE_CHANNELS.GET_RUNTIME_SNAPSHOT
      );
      applyRuntimeSnapshot(governedSnapshot);
    }
    return response;
  }),
  exitExamSession: (payload) => invokeCore(
    DESKTOP_CORE_CHANNELS.REQUEST,
    buildCommandRequest({
      cmd: "exit_exam_session",
      payload
    })
  ),
  forceRestoreDesktop: () => invokeCore(
    DESKTOP_CORE_CHANNELS.REQUEST,
    buildCommandRequest({
      cmd: "force_restore_desktop"
    })
  ),
  getProtectionStatus: () => invokeCore(
    DESKTOP_CORE_CHANNELS.REQUEST,
    buildCommandRequest({
      cmd: "get_protection_status"
    })
  ),
  loadExamPolicy: (payload) => invokeCore(
    DESKTOP_CORE_CHANNELS.REQUEST,
    buildCommandRequest({
      cmd: "load_policy",
      payload
    })
  ),
  getPolicyStatus: () => invokeCore(
    DESKTOP_CORE_CHANNELS.REQUEST,
    buildCommandRequest({
      cmd: "get_policy_status"
    })
  )
});
contextBridge.exposeInMainWorld("desktopExam", {
  // True when this Electron process is the isolated exam-shell (spawned onto a
  // dedicated Windows desktop), so the UI can render the exam room + exit flow.
  isExamShell: IS_ISOLATED_EXAM_SHELL,
  sessionId: EXAM_SHELL_SESSION_ID,
  examCode: EXAM_SHELL_EXAM_CODE,
  // Lobby: create the isolated desktop + launch the exam-shell on it.
  enterExamDesktop: (info) => invokeCore(DESKTOP_CORE_CHANNELS.ENTER_EXAM_DESKTOP, {
    roomUrl: info?.roomUrl,
    sessionId: info?.sessionId,
    examCode: info?.examCode
  }),
  // Exam-shell: switch back to Default + quit shell. The password is re-verified
  // in the main process (not trusted from the renderer), so it must be passed.
  confirmExit: (info) => invokeCore(DESKTOP_CORE_CHANNELS.EXAM_SHELL_EXIT, {
    password: info?.password,
    sessionId: info?.sessionId
  })
});
contextBridge.exposeInMainWorld("desktopOAuth", {
  openExternal: (url) => ipcRenderer.invoke("desktop-oauth:open-external", url),
  getPendingCallback: () => ipcRenderer.invoke("desktop-oauth:get-pending"),
  onCallback: (handler) => {
    const listener = (_event, payload) => handler(payload);
    ipcRenderer.on("desktop-oauth:callback", listener);
    return () => ipcRenderer.removeListener("desktop-oauth:callback", listener);
  }
});
contextBridge.exposeInMainWorld("examGuardTrace", {
  log: (payload) => ipcRenderer.send(TRACE_CHANNEL, payload)
});
var ACTIVE_INPUT_LOCK_STATES = /* @__PURE__ */ new Set([
  SESSION_STATES.STARTING_EXAM_SESSION,
  SESSION_STATES.ENTERING_KIOSK,
  SESSION_STATES.EXAM_RUNNING_CONFIRMED,
  SESSION_STATES.EXAM_RUNNING,
  SESSION_STATES.RECOVERY_REQUIRED
]);
var SINGLE_KEY_ALLOWED_STATES = /* @__PURE__ */ new Set([
  SESSION_STATES.EXAM_RUNNING_CONFIRMED
]);
var FULL_INPUT_BLOCK_STATES = /* @__PURE__ */ new Set([
  SESSION_STATES.STARTING_EXAM_SESSION,
  SESSION_STATES.ENTERING_KIOSK,
  SESSION_STATES.EXAM_RUNNING,
  SESSION_STATES.RECOVERY_REQUIRED
]);
var pressedKeys = /* @__PURE__ */ new Set();
var mediaPatchInstalled = false;
var mediaObserverInstalled = false;
function tracePreloadLoop(action, decision, reason, extra = {}) {
  ipcRenderer.send(TRACE_CHANNEL, {
    kind: "electron_loop",
    action,
    decision,
    state: runtimeSnapshot.sessionState,
    reason,
    source: "preload",
    ...extra
  });
}
function traceAudioGuard(event, action, reason, extra = {}) {
  ipcRenderer.send(TRACE_CHANNEL, {
    kind: "audio_guard",
    event,
    processName: "renderer",
    action,
    state: runtimeSnapshot.sessionState,
    audioLockActive: runtimeSnapshot.audioLockActive,
    reason,
    source: "preload",
    ...extra
  });
}
function isMediaLocked() {
  if (runtimeSnapshot.sessionState === SESSION_STATES.EXAM_EXITING || runtimeSnapshot.sessionState === SESSION_STATES.EXITED) {
    return false;
  }
  return Boolean(
    runtimeSnapshot.sessionState === SESSION_STATES.EXAM_RUNNING_CONFIRMED || runtimeSnapshot.audioLockActive && runtimeSnapshot.exitInProgress
  );
}
function muteElement(element, reason) {
  if (!element) {
    return;
  }
  try {
    element.muted = true;
    if (typeof element.pause === "function") {
      element.pause();
    }
    traceAudioGuard("AUDIO_PLAY_ATTEMPT_BLOCKED", "media_element_blocked", reason, {
      processName: element.tagName
    });
    tracePreloadLoop("audio_block_event", "blocked", reason, {
      tagName: element.tagName
    });
  } catch (error) {
    tracePreloadLoop("audio_block_event", "failed", reason, {
      error: error instanceof Error ? error.message : String(error)
    });
  }
}
function applyMediaLock(reason) {
  if (!isMediaLocked()) {
    return;
  }
  document.querySelectorAll("audio,video").forEach((element) => {
    muteElement(element, reason);
  });
}
function installMediaObserver() {
  if (mediaObserverInstalled || typeof MutationObserver === "undefined") {
    return;
  }
  mediaObserverInstalled = true;
  const observer = new MutationObserver(() => {
    applyMediaLock("dom_media_mutation");
  });
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
}
function installMediaLockPatches() {
  if (mediaPatchInstalled) {
    return;
  }
  mediaPatchInstalled = true;
  const mediaPrototype = window.HTMLMediaElement?.prototype;
  const originalPlay = mediaPrototype?.play;
  if (mediaPrototype && typeof originalPlay === "function") {
    mediaPrototype.play = function patchedPlay() {
      if (isMediaLocked()) {
        muteElement(this, "media_play_during_locked_exam_state");
        return Promise.reject(new DOMException("Media playback is blocked during protected exam state.", "NotAllowedError"));
      }
      return originalPlay.apply(this, arguments);
    };
  }
  const AudioContextCtor = window.AudioContext;
  const WebkitAudioContextCtor = window.webkitAudioContext;
  for (const AudioCtor of [AudioContextCtor, WebkitAudioContextCtor]) {
    const audioContextPrototype = AudioCtor?.prototype;
    const originalResume = audioContextPrototype?.resume;
    if (!audioContextPrototype || typeof originalResume !== "function") {
      continue;
    }
    audioContextPrototype.resume = function patchedResume() {
      if (isMediaLocked()) {
        if (typeof this.suspend === "function") {
          void this.suspend().catch(() => null);
        }
        traceAudioGuard("AUDIO_PLAY_ATTEMPT_BLOCKED", "audio_context_resume_blocked", "audio_context_resume_during_audio_lock");
        tracePreloadLoop("audio_block_event", "blocked", "audio_context_resume_during_locked_exam_state");
        return Promise.reject(new DOMException("AudioContext resume is blocked during protected exam state.", "NotAllowedError"));
      }
      return originalResume.apply(this, arguments);
    };
  }
  if (navigator.mediaSession && typeof navigator.mediaSession.setActionHandler === "function") {
    for (const action of ["play", "pause", "previoustrack", "nexttrack", "seekbackward", "seekforward"]) {
      try {
        navigator.mediaSession.setActionHandler(action, () => {
          if (isMediaLocked()) {
            traceAudioGuard("AUDIO_PLAY_ATTEMPT_BLOCKED", "media_session_action_blocked", action);
            applyMediaLock(`media_session_${action}`);
          }
        });
      } catch {
      }
    }
  }
}
window.addEventListener("DOMContentLoaded", () => {
  installMediaLockPatches();
  installMediaObserver();
  applyRuntimeSnapshot(runtimeSnapshot);
  ipcRenderer.on(DESKTOP_CORE_CHANNELS.RUNTIME_CHANGED, (_event, snapshot) => {
    applyRuntimeSnapshot(snapshot);
    applyMediaLock("runtime_changed");
  });
  invokeCore(DESKTOP_CORE_CHANNELS.GET_RUNTIME_SNAPSHOT).then((snapshot) => {
    applyRuntimeSnapshot(snapshot);
    applyMediaLock("snapshot_hydrated");
  }).catch((error) => {
    console.error("[desktop] Failed to hydrate core runtime snapshot", error);
  });
  console.log("Electron preload ready");
});
function keyEventId(event) {
  return event.code || event.key || "unknown";
}
function isFunctionKey(event) {
  return /^F\d{1,2}$/.test(event.key);
}
function isWinKey(event) {
  return event.key === "Meta" || event.key === "OS" || event.code === "MetaLeft" || event.code === "MetaRight";
}
function isPrintScreenKey(event) {
  return event.key === "PrintScreen" || event.code === "PrintScreen";
}
function isContextMenuKey(event) {
  return event.key === "ContextMenu" || event.code === "ContextMenu";
}
function isEditableTarget(event) {
  const target = event.target;
  if (!target || typeof target !== "object") {
    return false;
  }
  const tagName = target.tagName;
  return tagName === "INPUT" || tagName === "TEXTAREA" || target.isContentEditable === true;
}
function blockInputEvent(event, reason) {
  event.preventDefault();
  event.stopImmediatePropagation();
  tracePreloadLoop("input_block_event", "blocked", reason, {
    eventType: event.type,
    key: event.key,
    code: event.code,
    ctrlKey: event.ctrlKey,
    altKey: event.altKey,
    metaKey: event.metaKey,
    shiftKey: event.shiftKey,
    pressedKeyCount: pressedKeys.size
  });
  if (event.type === "keydown") {
    console.warn(`[InputBlockedEvent] ${reason}: ${event.key}`);
  }
}
var filterInputEvent = (event) => {
  const state = runtimeSnapshot.sessionState;
  const isActiveSession = IS_ISOLATED_EXAM_SHELL || ACTIVE_INPUT_LOCK_STATES.has(state);
  if (runtimeSnapshot.exitInProgress) {
    if (event.type === "keydown") {
      pressedKeys.add(keyEventId(event));
    }
    blockInputEvent(event, "exit_in_progress_blocks_all_input");
    if (event.type === "keyup") {
      pressedKeys.delete(keyEventId(event));
    }
    return;
  }
  if (!isActiveSession) {
    if (event.type === "keyup") {
      pressedKeys.delete(keyEventId(event));
    }
    return;
  }
  if (event.type === "keydown") {
    pressedKeys.add(keyEventId(event));
  }
  if (isWinKey(event) || isPrintScreenKey(event) || isContextMenuKey(event)) {
    blockInputEvent(event, "global_hotkey_blocked");
    if (event.type === "keyup") {
      pressedKeys.delete(keyEventId(event));
    }
    return;
  }
  if (FULL_INPUT_BLOCK_STATES.has(state)) {
    blockInputEvent(event, `state_${state}_blocks_all_input`);
    if (event.type === "keyup") {
      pressedKeys.delete(keyEventId(event));
    }
    return;
  }
  if (SINGLE_KEY_ALLOWED_STATES.has(state) || IS_ISOLATED_EXAM_SHELL) {
    if (isEditableTarget(event)) {
      if (event.ctrlKey || event.altKey || event.metaKey) {
        blockInputEvent(event, "modifier_key_combination_in_field");
        if (event.type === "keyup") {
          pressedKeys.delete(keyEventId(event));
        }
        return;
      }
      if (isFunctionKey(event)) {
        blockInputEvent(event, "function_key_blocked");
        if (event.type === "keyup") {
          pressedKeys.delete(keyEventId(event));
        }
        return;
      }
      if (event.type === "keyup") {
        pressedKeys.delete(keyEventId(event));
      }
      return;
    }
    const isModifierPressed = event.ctrlKey || event.altKey || event.metaKey || event.shiftKey;
    if (isModifierPressed) {
      blockInputEvent(event, "modifier_key_combination");
      if (event.type === "keyup") {
        pressedKeys.delete(keyEventId(event));
      }
      return;
    }
    const isMultiKeyChord = event.type === "keydown" && pressedKeys.size > 1;
    if (isMultiKeyChord) {
      blockInputEvent(event, "multi_key_chord");
      if (event.type === "keyup") {
        pressedKeys.delete(keyEventId(event));
      }
      return;
    }
    if (isFunctionKey(event)) {
      blockInputEvent(event, "function_key_blocked");
      if (event.type === "keyup") {
        pressedKeys.delete(keyEventId(event));
      }
      return;
    }
    const isSingleKey = typeof event.key === "string" && event.key.length === 1;
    if (!isSingleKey) {
      blockInputEvent(event, "non_single_character_key");
      if (event.type === "keyup") {
        pressedKeys.delete(keyEventId(event));
      }
      return;
    }
    if (event.type === "keyup") {
      pressedKeys.delete(keyEventId(event));
    }
    return;
  }
  blockInputEvent(event, `state_${state}_blocks_all_input`);
  if (event.type === "keyup") {
    pressedKeys.delete(keyEventId(event));
  }
};
window.addEventListener("keydown", filterInputEvent, true);
window.addEventListener("keypress", filterInputEvent, true);
window.addEventListener("keyup", filterInputEvent, true);
