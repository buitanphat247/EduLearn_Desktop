const { EventEmitter } = require("events");

const {
  CORE_ERROR_CODES,
  SESSION_STATES,
  createCoreErrorResponse,
  createCoreSuccessResponse,
  createDesktopRuntimeSnapshot,
  isSafeExamCommand,
} = require("./contracts/safe-exam");
const { createRustSidecarTransport } = require("./rust-sidecar");
const { logger } = require("./logger");
const { cacheExitPasswordHash } = require("./exam-exit-verify");
const {
  GOVERNOR_EVENT_SCOPES,
  GOVERNOR_LOCK_MODES,
  createAtomicStateEngine,
} = require("./state-governor");

const PROCESS_WATCH_INTERVAL_MS = 500;
const NATIVE_KIOSK_COMMAND_TIMEOUT_MS = 30_000;
const PRE_SESSION_PROTECTION_STATUS_DEBOUNCE_MS = 3_000;
const KIOSK_HANDOFF_GRACE_PERIOD_MS = 10_000;
// V10.9X: Watchdog grace period for ENTERING_KIOSK — no state reset for this duration
const ENTERING_KIOSK_WATCHDOG_GRACE_MS = 10_000;
const DEMO_STATIC_EXAM_MODE = "DEMO_STATIC";
const DEMO_STATIC_CONFIRM_DELAY_MS = 800;
const EXIT_AUDIO_RESTORE_TIMEOUT_MS = 5_000;
const EXIT_FORCE_CLEANUP_TIMEOUT_MS = 5_000;
const EXIT_RUST_ACK_TIMEOUT_MS = 5_000;

const PROTECTION_STATUS_ALLOWED_SESSION_STATES = new Set([
  SESSION_STATES.EXAM_RUNNING_CONFIRMED,
]);

// The runtime monitor is allowed only after atomic confirmation.
const RUNTIME_MONITOR_ALLOWED_SESSION_STATES = new Set([
  SESSION_STATES.EXAM_RUNNING_CONFIRMED,
]);

const EXIT_FLOW_SESSION_STATES = new Set([
  SESSION_STATES.EXAM_EXIT_REQUESTED,
  SESSION_STATES.EXAM_EXITING,
  SESSION_STATES.EXITED,
]);

const STATE_LOCKED_SESSION_STATES = new Set([
  SESSION_STATES.EXAM_RUNNING_CONFIRMED,
]);

const LOCKED_STATE_CRITICAL_FIELDS = [
  "sessionState",
  "safeExamMode",
  "examProtectionActive",
  "protectionDryRun",
  "kioskActive",
  "overlayActive",
  "taskbarHidden",
  "keyboardHookActive",
  "focusLockActive",
  "inputHookActive",
  "mouseHookActive",
  "focusHookActive",
  "clipboardListenerActive",
  "overlayHealActive",
  "captureHealActive",
  "captureProtectionActive",
  "electronContentProtectionActive",
  "rustOverlayCaptureProtectionActive",
  "captureProtectionBestEffort",
  "runtimeMonitorActive",
  "kioskHandoffCompleted",
  "blackOverlayCount",
];

function isAudioLockMutationAllowed(options = {}) {
  return options.allowAudioLockMutation === true;
}

function logDesktopCore(message, details) {
  if (typeof details === "undefined") {
    logger.info("application", message, {});
    return;
  }

  logger.info("application", message, details);
}

function isProtectionStatusAllowedSessionState(sessionState) {
  return PROTECTION_STATUS_ALLOWED_SESSION_STATES.has(sessionState);
}

function isRuntimeMonitorAllowedSessionState(sessionState) {
  return RUNTIME_MONITOR_ALLOWED_SESSION_STATES.has(sessionState);
}

function isStateLocked(sessionState) {
  return STATE_LOCKED_SESSION_STATES.has(sessionState);
}

function isValidLockedStateForwardTransition(from, to) {
  if (from === SESSION_STATES.EXAM_RUNNING_CONFIRMED) {
    return to === SESSION_STATES.EXAM_RUNNING_CONFIRMED;
  }

  return from === to;
}

function hasExplicitActiveExamRestoreIntent(payload = {}) {
  return Boolean(
    payload.explicitExit ||
      payload.explicitTermination ||
      payload.userInitiated ||
      payload.allowActiveExamRestore ||
      payload.emergencyRestore ||
      payload.reason === "user_exit" ||
      payload.reason === "user_emergency_restore" ||
      payload.reason === "application_shutdown",
  );
}

function waitForDelay(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function createStateGovernorValidation(governorId) {
  const checks = {
    stateMachineIntegrity: Boolean(governorId),
    raceCondition: true,
    audioLock: true,
    exitFlow: true,
    watchdogSafety: true,
    authority: true,
  };
  const passed = Object.values(checks).every(Boolean);
  return {
    governorId,
    checkedAt: Date.now(),
    checks,
    passed,
    safeMode: !passed,
  };
}

function createDesktopCoreRuntime({
  platform,
  protectionController = null,
  createSidecarTransport = createRustSidecarTransport,
  examGuardTracer = null,
}) {
  const emitter = new EventEmitter();
  let runtimeMonitorTimer = null;
  let runtimeMonitorTickInFlight = false;
  let runtimeMonitorGeneration = 0;
  let lastPreSessionProtectionStatusAt = 0;
  let enteringKioskSince = null;
  let activeExamMode = null;
  const stateGovernorId = `state-governor-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const stateGovernorValidation = createStateGovernorValidation(stateGovernorId);
  let exitPreviousSessionState = null;
  let exitAudioRestoreTimer = null;
  let exitForceCleanupTimer = null;
  let exitFlowGeneration = 0;
  const initialRuntimeSnapshot = createDesktopRuntimeSnapshot({
    platform,
    sessionState: SESSION_STATES.INIT,
    audioLockActive: false,
    exitInProgress: false,
    stateTransitionLock: false,
    uiInteractionLocked: false,
    stateGovernorId,
    stateGovernorReady: stateGovernorValidation.passed,
    stateGovernorSafeMode: stateGovernorValidation.safeMode,
    stateGovernorProductionGatePassed: stateGovernorValidation.passed,
    stateGovernorLastValidation: stateGovernorValidation,
  });
  const stateEngine = createAtomicStateEngine({
    governorId: stateGovernorId,
    initialSnapshot: initialRuntimeSnapshot,
    normalizeSnapshot: createDesktopRuntimeSnapshot,
    onApplied({ event, previousSnapshot, snapshot }) {
      if (previousSnapshot.sessionState !== snapshot.sessionState) {
        lastPreSessionProtectionStatusAt = 0;
        if (snapshot.sessionState === SESSION_STATES.ENTERING_KIOSK) {
          enteringKioskSince = Date.now();
        } else if (
          previousSnapshot.sessionState === SESSION_STATES.ENTERING_KIOSK
        ) {
          enteringKioskSince = null;
        }
        logger.info("session", "sessionStateTransition", {
          previousSessionState: previousSnapshot.sessionState,
          nextSessionState: snapshot.sessionState,
          sequenceId: event.sequenceId,
          source: event.source,
          reason: event.reason,
        });
        examGuardTracer?.recordStateTransition?.({
          from: previousSnapshot.sessionState,
          to: snapshot.sessionState,
          source: event.source ?? "desktop-core",
          reason: event.reason ?? "state_governor_apply",
        });
        const audioState = stateEngine.getAudioState(snapshot);
        const uiShellMode =
          snapshot.sessionState === SESSION_STATES.EXAM_RUNNING_CONFIRMED
            ? "ExamShellLayout"
            : [
                  SESSION_STATES.STARTING_EXAM_SESSION,
                  SESSION_STATES.ENTERING_KIOSK,
                  SESSION_STATES.EXAM_EXIT_REQUESTED,
                  SESSION_STATES.EXAM_EXITING,
                ].includes(snapshot.sessionState)
              ? "AtomicLoadingScreen"
              : "AppLayout";
        console.log("[STATE_TRACE]", {
          from: previousSnapshot.sessionState,
          to: snapshot.sessionState,
          source: event.source ?? "desktop-core",
          timestamp: new Date().toISOString(),
          governorId: stateGovernorId,
          kioskFlag: snapshot.kioskActive,
          overlayFlag: snapshot.overlayActive,
          audioState,
          inputLock: Boolean(
            snapshot.uiInteractionLocked ||
              snapshot.stateTransitionLock ||
              [
                SESSION_STATES.STARTING_EXAM_SESSION,
                SESSION_STATES.ENTERING_KIOSK,
                SESSION_STATES.RECOVERY_REQUIRED,
                SESSION_STATES.EXAM_EXIT_REQUESTED,
                SESSION_STATES.EXAM_EXITING,
              ].includes(snapshot.sessionState),
          ),
          uiShellMode,
        });
        console.log("[AUDIO_OVERLAY_SYNC]", {
          audioState,
          overlayState: snapshot.overlayActive
            ? "NATIVE_OVERLAY_ACTIVE"
            : "NATIVE_OVERLAY_HIDDEN",
          expected: snapshot.sessionState,
        });
      }
      emitRuntimeChanged();
    },
  });
  // Compatibility view for existing runtime code. The governor owns the
  // snapshot; this proxy is read-only and always resolves to its latest value.
  const runtimeSnapshot = stateEngine.readonlySnapshot;

  function isDemoStaticMode() {
    return activeExamMode === DEMO_STATIC_EXAM_MODE;
  }

  const sidecarTransport = createSidecarTransport({
    onEvent(event) {
      logDesktopCore(
        `Received core event: ${event?.event ?? "UNKNOWN"}`,
        event?.data ?? null,
      );
      if (event?.event === "RUST_CORE_READY") {
        updateSnapshot({
          nativeCoreConnected: true,
          coreVersion:
            typeof event?.data?.coreVersion === "string"
              ? event.data.coreVersion
              : runtimeSnapshot.coreVersion,
          lastCoreHeartbeat:
            typeof event?.timestamp === "number" ? event.timestamp : Date.now(),
          errorCode: null,
        });
      }
    },
    onExit(exitInfo) {
      logDesktopCore("Rust sidecar exited", exitInfo ?? null);
      stopRuntimeMonitorLoop();
      if (isDemoStaticMode() || isStateLocked(runtimeSnapshot.sessionState)) {
        examGuardTracer?.recordLoop?.({
          action: "watchdog_reset_disabled",
          decision: "ignored",
          state: runtimeSnapshot.sessionState,
          reason: isDemoStaticMode()
            ? "demo_static_sidecar_exit_does_not_reset_session"
            : "active_exam_state_lock_sidecar_exit_does_not_restore",
        });
        updateSnapshot(
          {
            nativeCoreConnected: false,
            lastCoreHeartbeat: null,
            errorCode: CORE_ERROR_CODES.CORE_NOT_CONNECTED,
          },
          { reason: "sidecar_exit_locked" },
        );
        logDesktopCore("State lock ignored sidecar exit restore during active exam", {
          sessionState: runtimeSnapshot.sessionState,
        });
        return;
      }

      // V10.9X: ENTERING_KIOSK watchdog grace — do NOT reset state for 10s
      if (
        runtimeSnapshot.sessionState === SESSION_STATES.ENTERING_KIOSK &&
        enteringKioskSince !== null &&
        Date.now() - enteringKioskSince < ENTERING_KIOSK_WATCHDOG_GRACE_MS
      ) {
        examGuardTracer?.recordLoop?.({
          action: "watchdog_reset_disabled",
          decision: "grace",
          state: runtimeSnapshot.sessionState,
          reason: "entering_kiosk_watchdog_grace_period",
        });
        updateSnapshot(
          {
            nativeCoreConnected: false,
            lastCoreHeartbeat: null,
            errorCode: CORE_ERROR_CODES.CORE_NOT_CONNECTED,
          },
          { reason: "sidecar_exit_entering_kiosk_grace" },
        );
        logDesktopCore("Watchdog grace: ENTERING_KIOSK sidecar exit does not reset state", {
          sessionState: runtimeSnapshot.sessionState,
          graceRemainingMs: ENTERING_KIOSK_WATCHDOG_GRACE_MS - (Date.now() - enteringKioskSince),
        });
        return;
      }

      // V10.9X: exitInProgress — do NOT reset state, do NOT force IDLE, do NOT re-trigger kiosk
      if (runtimeSnapshot.exitInProgress) {
        examGuardTracer?.recordLoop?.({
          action: "watchdog_reset_disabled",
          decision: "ignored",
          state: runtimeSnapshot.sessionState,
          reason: "exit_in_progress_sidecar_exit_does_not_reset",
        });
        updateSnapshot(
          {
            nativeCoreConnected: false,
            lastCoreHeartbeat: null,
            errorCode: CORE_ERROR_CODES.CORE_NOT_CONNECTED,
          },
          { reason: "sidecar_exit_during_exit_flow" },
        );
        logDesktopCore("exitInProgress: sidecar exit does not reset state", {
          sessionState: runtimeSnapshot.sessionState,
        });
        return;
      }
      if (protectionController) {
        void protectionController.restoreExamProtection().catch((error) => {
          console.error(
            "[desktop-core] Failed to restore desktop protection after sidecar exit",
            error,
          );
        });
      }
      updateSnapshot({
        nativeCoreConnected: false,
        safeExamMode: false,
        kioskHandoffCompleted: false,
        coreVersion: null,
        sessionState: SESSION_STATES.INIT,
        lastCoreHeartbeat: null,
        examProtectionActive: false,
        protectionDryRun: false,
        kioskActive: false,
        overlayActive: false,
        taskbarHidden: false,
        keyboardHookActive: false,
        focusLockActive: false,
        inputHookActive: false,
        mouseHookActive: false,
        focusHookActive: false,
        clipboardListenerActive: false,
        overlayHealActive: false,
        captureHealActive: false,
        captureProtectionActive: false,
        captureProtectionStatus: "inactive",
        electronContentProtectionActive: false,
        rustOverlayCaptureProtectionActive: false,
        captureProtectionBestEffort: false,
        runtimeMonitorActive: false,
        activeMonitorCount: 0,
        blackOverlayCount: 0,
        lastRuntimeEventAt: null,
        errorCode: CORE_ERROR_CODES.CORE_NOT_CONNECTED,
      });
    },
  });
  function buildProtectionStatusResponseData(extra = {}) {
    return {
      sessionState: runtimeSnapshot.sessionState,
      protectionStatus: {
        examProtectionActive: runtimeSnapshot.examProtectionActive,
        protectionDryRun: runtimeSnapshot.protectionDryRun,
        kioskActive: runtimeSnapshot.kioskActive,
        overlayActive: runtimeSnapshot.overlayActive,
        taskbarHidden: runtimeSnapshot.taskbarHidden,
        keyboardHookActive: runtimeSnapshot.keyboardHookActive,
        focusLockActive: runtimeSnapshot.focusLockActive,
        inputHookActive: runtimeSnapshot.inputHookActive,
        mouseHookActive: runtimeSnapshot.mouseHookActive,
        focusHookActive: runtimeSnapshot.focusHookActive,
        clipboardListenerActive: runtimeSnapshot.clipboardListenerActive,
        overlayHealActive: runtimeSnapshot.overlayHealActive,
        captureHealActive: runtimeSnapshot.captureHealActive,
        captureProtectionActive: runtimeSnapshot.captureProtectionActive,
        captureProtectionStatus: runtimeSnapshot.captureProtectionStatus,
        electronContentProtectionActive:
          runtimeSnapshot.electronContentProtectionActive,
        rustOverlayCaptureProtectionActive:
          runtimeSnapshot.rustOverlayCaptureProtectionActive,
        captureProtectionBestEffort:
          runtimeSnapshot.captureProtectionBestEffort,
        runtimeMonitorActive: runtimeSnapshot.runtimeMonitorActive,
        activeMonitorCount: runtimeSnapshot.activeMonitorCount,
        blackOverlayCount: runtimeSnapshot.blackOverlayCount,
        lastRuntimeEventAt: runtimeSnapshot.lastRuntimeEventAt,
      },
      runtimeRiskLevel: runtimeSnapshot.runtimeRiskLevel,
      runtimeMonitorActive: runtimeSnapshot.runtimeMonitorActive,
      emergencyRestore: runtimeSnapshot.emergencyRestore,
      examMode: activeExamMode,
      audioLockActive: runtimeSnapshot.audioLockActive,
      exitInProgress: runtimeSnapshot.exitInProgress,
      stateTransitionLock: runtimeSnapshot.stateTransitionLock,
      uiInteractionLocked: runtimeSnapshot.uiInteractionLocked,
      stateGovernorId: runtimeSnapshot.stateGovernorId,
      stateGovernorReady: runtimeSnapshot.stateGovernorReady,
      stateGovernorSafeMode: runtimeSnapshot.stateGovernorSafeMode,
      stateGovernorProductionGatePassed:
        runtimeSnapshot.stateGovernorProductionGatePassed,
      stateGovernorSequenceId: runtimeSnapshot.stateGovernorSequenceId,
      stateGovernorLockMode: runtimeSnapshot.stateGovernorLockMode,
      stateGovernorEventQueueLength:
        runtimeSnapshot.stateGovernorEventQueueLength,
      stateGovernorLastValidation: runtimeSnapshot.stateGovernorLastValidation,
      kioskHandoffCompleted: runtimeSnapshot.kioskHandoffCompleted,
      ...extra,
    };
  }

  function recordAudio(event, action, reason) {
    examGuardTracer?.recordAudio?.({
      event,
      processName: "desktop-core",
      action,
      state: runtimeSnapshot.sessionState,
      audioLockActive: runtimeSnapshot.audioLockActive,
      reason,
      source: "desktop-core",
    });
  }

  function setAudioLockActive(nextAudioLockActive, reason) {
    if (runtimeSnapshot.audioLockActive === nextAudioLockActive) {
      recordAudio(
        "AUDIO_LOCK_MAINTAINED",
        nextAudioLockActive ? "audio_lock_already_active" : "audio_lock_already_released",
        reason,
      );
      return runtimeSnapshot;
    }

    const nextSnapshot = updateSnapshot(
      { audioLockActive: nextAudioLockActive },
      {
        allowAudioLockMutation: true,
        reason,
      },
    );
    recordAudio(
      nextAudioLockActive ? "AUDIO_LOCK_ACTIVATED" : "AUDIO_LOCK_RELEASED",
      nextAudioLockActive ? "audioLockActive=true" : "audioLockActive=false",
      reason,
    );
    return nextSnapshot;
  }

  function clearExitFallbackTimers({ invalidate = false } = {}) {
    if (exitAudioRestoreTimer) {
      clearTimeout(exitAudioRestoreTimer);
      exitAudioRestoreTimer = null;
    }
    if (exitForceCleanupTimer) {
      clearTimeout(exitForceCleanupTimer);
      exitForceCleanupTimer = null;
    }
    if (invalidate) {
      exitFlowGeneration += 1;
    }
  }

  function scheduleExitAudioRestore(reason) {
    if (exitAudioRestoreTimer) {
      clearTimeout(exitAudioRestoreTimer);
    }
    const generation = exitFlowGeneration;
    exitAudioRestoreTimer = setTimeout(() => {
      exitAudioRestoreTimer = null;
      if (
        generation !== exitFlowGeneration ||
        runtimeSnapshot.sessionState !== SESSION_STATES.EXAM_EXITING ||
        !runtimeSnapshot.audioLockActive
      ) {
        return;
      }

      setAudioLockActive(false, `${reason}_audio_restore_timeout`);
      recordAudio(
        "AUDIO_LOCK_RELEASED",
        "forceAudioRestoreAfterExitTimeout",
        reason,
      );
    }, EXIT_AUDIO_RESTORE_TIMEOUT_MS);
    exitAudioRestoreTimer.unref?.();
  }

  async function forceExitCleanup(reason, generation = exitFlowGeneration) {
    if (generation !== exitFlowGeneration || !runtimeSnapshot.exitInProgress) {
      return runtimeSnapshot;
    }

    examGuardTracer?.recordLoop?.({
      action: "exit_force_cleanup_timeout",
      decision: "fallback_cleanup",
      state: runtimeSnapshot.sessionState,
      reason,
    });
    logDesktopCore("State governor running fallback exit cleanup", {
      reason,
      sessionState: runtimeSnapshot.sessionState,
    });

    stopRuntimeMonitorLoop();
    markExiting(`${reason}_fallback`);

    if (
      protectionController &&
      (protectionController.hasActiveProtection() ||
        runtimeSnapshot.kioskActive ||
        runtimeSnapshot.examProtectionActive ||
        runtimeSnapshot.overlayActive ||
        runtimeSnapshot.taskbarHidden ||
        runtimeSnapshot.keyboardHookActive ||
        runtimeSnapshot.focusLockActive)
    ) {
      try {
        const visualPatch = await protectionController.restoreExamProtection();
        governorPatch(
          {
            ...visualPatch,
            runtimeMonitorActive: false,
            kioskHandoffCompleted: false,
          },
          `${reason}_visual_restore_fallback`,
          {
            allowAudioLockMutation: true,
            allowLockedStateOverride: true,
          },
        );
      } catch (error) {
        logDesktopCore("Fallback exit cleanup visual restore failed", {
          reason,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    activeExamMode = null;
    markExited(`${reason}_fallback`);
    return runtimeSnapshot;
  }

  function scheduleExitForceCleanup(reason) {
    if (exitForceCleanupTimer) {
      clearTimeout(exitForceCleanupTimer);
    }
    const generation = exitFlowGeneration;
    exitForceCleanupTimer = setTimeout(() => {
      exitForceCleanupTimer = null;
      void forceExitCleanup(`${reason}_force_cleanup_timeout`, generation);
    }, EXIT_FORCE_CLEANUP_TIMEOUT_MS);
    exitForceCleanupTimer.unref?.();
  }

  function governorPatch(patch, reason, extra = {}) {
    return updateSnapshot(
      {
        stateGovernorId,
        stateGovernorReady: stateGovernorValidation.passed,
        stateGovernorSafeMode: stateGovernorValidation.safeMode,
        stateGovernorProductionGatePassed: stateGovernorValidation.passed,
        stateGovernorLastValidation: stateGovernorValidation,
        ...patch,
      },
      {
        allowExitFlowMutation: true,
        governorScope: GOVERNOR_EVENT_SCOPES.EXIT_FLOW,
        ...extra,
        reason,
      },
    );
  }

  function beginExitConfirmation(reason) {
    if (runtimeSnapshot.exitInProgress) {
      return createCoreSuccessResponse(`state-governor-${Date.now()}`, {
        duplicate: true,
        exitInProgress: true,
        sessionState: runtimeSnapshot.sessionState,
        stateTransitionLock: runtimeSnapshot.stateTransitionLock,
        uiInteractionLocked: runtimeSnapshot.uiInteractionLocked,
        reason: "duplicate_exit_confirmation_ignored",
      });
    }

    exitPreviousSessionState = runtimeSnapshot.sessionState;
    examGuardTracer?.recordLoop?.({
      action: "state_governor_exit_confirmation_opened",
      decision: "observe_only",
      state: runtimeSnapshot.sessionState,
      reason: `${reason}_modal_does_not_mutate_state`,
    });
    return null;
  }

  function cancelExitConfirmation(reason) {
    if (!exitPreviousSessionState && !runtimeSnapshot.exitInProgress) {
      examGuardTracer?.recordLoop?.({
        action: "state_governor_exit_confirmation_cancelled",
        decision: "noop",
        state: runtimeSnapshot.sessionState,
        reason: `${reason}_no_pending_exit_state`,
      });
      return;
    }

    const previousState = exitPreviousSessionState ?? runtimeSnapshot.sessionState;
    exitPreviousSessionState = null;
    clearExitFallbackTimers({ invalidate: true });
    governorPatch(
      {
        exitInProgress: false,
        stateTransitionLock: false,
        uiInteractionLocked: false,
        sessionState: previousState,
      },
      reason,
      { governorUnlockAfterApply: true },
    );
    examGuardTracer?.recordLoop?.({
      action: "state_governor_exit_confirmation_cancelled",
      decision: "unlocked",
      state: runtimeSnapshot.sessionState,
      reason,
    });
  }

  function markExitRequested(reason) {
    exitFlowGeneration += 1;
    governorPatch(
      {
        exitInProgress: true,
        stateTransitionLock: true,
        uiInteractionLocked: true,
        sessionState: SESSION_STATES.EXAM_EXIT_REQUESTED,
      },
      reason,
      {
        allowLockedStateOverride: true,
        governorLockMode: GOVERNOR_LOCK_MODES.EXIT,
      },
    );
    stopRuntimeMonitorLoop();
    scheduleExitForceCleanup(reason);
  }

  function markExiting(reason) {
    governorPatch(
      {
        exitInProgress: true,
        stateTransitionLock: true,
        uiInteractionLocked: true,
        sessionState: SESSION_STATES.EXAM_EXITING,
      },
      reason,
      { allowLockedStateOverride: true },
    );
    scheduleExitAudioRestore(reason);
  }

  function markExited(reason) {
    clearExitFallbackTimers({ invalidate: true });
    exitPreviousSessionState = null;
    governorPatch(
      {
        audioLockActive: false,
        exitInProgress: false,
        stateTransitionLock: false,
        uiInteractionLocked: false,
        sessionState: SESSION_STATES.EXITED,
        safeExamMode: false,
        examMode: null,
        kioskHandoffCompleted: false,
        runtimeMonitorActive: false,
      },
      reason,
      {
        allowAudioLockMutation: true,
        allowLockedStateOverride: true,
        governorUnlockAfterApply: true,
      },
    );
    recordAudio("AUDIO_LOCK_RELEASED", "restoreAudio", reason);
  }

  function stopRuntimeMonitorLoop() {
    runtimeMonitorGeneration += 1;
    if (runtimeMonitorTimer) {
      clearInterval(runtimeMonitorTimer);
      runtimeMonitorTimer = null;
    }

    runtimeMonitorTickInFlight = false;
  }

  async function runRuntimeMonitorTick() {
    // V10.9X: GLOBAL PRIORITY OVERRIDE — exitInProgress stops ALL subsystems
    if (runtimeSnapshot.exitInProgress) {
      examGuardTracer?.recordLoop?.({
        action: "monitor_tick",
        decision: "skipped",
        state: runtimeSnapshot.sessionState,
        reason: "state_governor_exit_in_progress",
      });
      stopRuntimeMonitorLoop();
      return;
    }

    // V10.9X: ENTERING_KIOSK is transition only — no polling
    if (runtimeSnapshot.sessionState === SESSION_STATES.ENTERING_KIOSK) {
      examGuardTracer?.recordLoop?.({
        action: "monitor_tick",
        decision: "skipped",
        state: runtimeSnapshot.sessionState,
        reason: "entering_kiosk_transition_only",
      });
      return;
    }

    if (runtimeMonitorTickInFlight || !sidecarTransport.isConnected()) {
      examGuardTracer?.recordLoop?.({
        action: "monitor_tick",
        decision: "skipped",
        state: runtimeSnapshot.sessionState,
        reason: runtimeMonitorTickInFlight
          ? "tick_in_flight"
          : "sidecar_disconnected",
      });
      return;
    }

    if (!isRuntimeMonitorAllowedSessionState(runtimeSnapshot.sessionState)) {
      examGuardTracer?.recordLoop?.({
        action: "monitor_tick",
        decision: "stop",
        state: runtimeSnapshot.sessionState,
        reason: "session_not_allowed",
      });
      logDesktopCore("protectionSkippedBecauseIdle", {
        cmd: "run_runtime_monitor_tick",
        sessionState: runtimeSnapshot.sessionState,
      });
      stopRuntimeMonitorLoop();
      if (runtimeSnapshot.runtimeMonitorActive) {
        updateSnapshot({ runtimeMonitorActive: false });
      }
      return;
    }

    if (!runtimeSnapshot.kioskActive || !runtimeSnapshot.examProtectionActive) {
      examGuardTracer?.recordLoop?.({
        action: "monitor_tick",
        decision: "skipped",
        state: runtimeSnapshot.sessionState,
        reason: "protection_not_active",
      });
      return;
    }

    runtimeMonitorTickInFlight = true;
    const tickGeneration = runtimeMonitorGeneration;

    try {
      const response = await sidecarTransport.request(
        {
          requestId: `runtime-monitor-${Date.now()}`,
          cmd: "run_runtime_monitor_tick",
          payload: {
            windowHandleHex:
              protectionController?.getMainWindowHandleHex?.() ?? null,
            electronContentProtectionActive: Boolean(
              protectionController?.getVisualSnapshotPatch?.()
                .electronContentProtectionActive,
            ),
          },
        },
        {
          timeoutMs: 10_000,
        },
      );
      examGuardTracer?.recordLoop?.({
        action: "monitor_tick",
        decision: response.ok ? "accepted" : "failed",
        state:
          typeof response.data?.sessionState === "string"
            ? response.data.sessionState
            : runtimeSnapshot.sessionState,
        reason: response.error?.message ?? "runtime_monitor_tick",
      });

      if (tickGeneration !== runtimeMonitorGeneration) {
        logDesktopCore(
          "Discarding stale runtime monitor response after lifecycle change",
        );
        return;
      }

      if (!response.ok) {
        logDesktopCore("Runtime monitor tick failed", response.error);

        if (response.error?.code === CORE_ERROR_CODES.CORE_NOT_CONNECTED) {
          stopRuntimeMonitorLoop();
          updateSnapshot({
            nativeCoreConnected: false,
            errorCode: response.error.code,
            runtimeMonitorActive: false,
          });
        }

        return;
      }

      const nextSnapshotPatch = {
        nativeCoreConnected: true,
        errorCode: null,
        lastCoreHeartbeat: Date.now(),
        sessionState:
          typeof response.data?.sessionState === "string"
            ? response.data.sessionState
            : runtimeSnapshot.sessionState,
      };
      applyProtectionSnapshotPatch(
        nextSnapshotPatch,
        response.data?.protectionStatus,
      );
      applyRuntimeFoundationPatch(nextSnapshotPatch, response.data);
      updateSnapshot(nextSnapshotPatch);

      if (response.data?.summary && typeof response.data.summary === "object") {
        logDesktopCore("Runtime monitor tick completed", response.data.summary);
      }

      if (
        Array.isArray(response.data?.logLines) &&
        response.data.logLines.length > 0
      ) {
        for (const line of response.data.logLines) {
          if (!line || typeof line !== "object") {
            continue;
          }

          logger.info("protection", "runtime_monitor_log", {
            code: line.code ?? "UNKNOWN",
            level: line.level ?? "info",
            message: line.message ?? "",
            timestamp: line.timestamp ?? null,
          });
        }
      }
    } catch (error) {
      console.error(
        "[desktop-core] Runtime monitor tick threw unexpectedly",
        error,
      );
    } finally {
      if (tickGeneration === runtimeMonitorGeneration) {
        runtimeMonitorTickInFlight = false;
      }
    }
  }

  function startRuntimeMonitorLoop() {
    if (runtimeMonitorTimer || !sidecarTransport.isConnected()) {
      return;
    }

    if (runtimeSnapshot.sessionState === SESSION_STATES.ENTERING_KIOSK) {
      logDesktopCore("runtimeMonitorDeferredUntilConfirmed", {
        sessionState: runtimeSnapshot.sessionState,
      });
      return;
    }

    if (!isRuntimeMonitorAllowedSessionState(runtimeSnapshot.sessionState)) {
      logDesktopCore("protectionSkippedBecauseIdle", {
        cmd: "startRuntimeMonitorLoop",
        sessionState: runtimeSnapshot.sessionState,
      });
      stopRuntimeMonitorLoop();
      if (runtimeSnapshot.runtimeMonitorActive) {
        updateSnapshot({ runtimeMonitorActive: false });
      }
      return;
    }

    if (!runtimeSnapshot.kioskActive || !runtimeSnapshot.examProtectionActive) {
      return;
    }

    logDesktopCore("protectionActivated", {
      sessionState: runtimeSnapshot.sessionState,
      activeMonitorCount: runtimeSnapshot.activeMonitorCount,
      blackOverlayCount: runtimeSnapshot.blackOverlayCount,
    });

    runtimeMonitorTimer = setInterval(() => {
      void runRuntimeMonitorTick();
    }, PROCESS_WATCH_INTERVAL_MS);
    runtimeMonitorTimer.unref?.();

    void runRuntimeMonitorTick();
  }

  function resolveRestorePayload(data) {
    if (!data || typeof data !== "object") {
      return null;
    }

    if (data.sessionRestore && typeof data.sessionRestore === "object") {
      return data.sessionRestore;
    }

    return data;
  }

  function emitRuntimeChanged() {
    emitter.emit("runtime-changed", stateEngine.getSnapshot());
  }

  function applyProtectionSnapshotPatch(targetPatch, data) {
    if (!data || typeof data !== "object") {
      return targetPatch;
    }

    targetPatch.examProtectionActive = Boolean(data.examProtectionActive);
    targetPatch.protectionDryRun = Boolean(data.protectionDryRun);
    targetPatch.kioskActive = Boolean(data.kioskActive);
    targetPatch.overlayActive = Boolean(data.overlayActive);
    targetPatch.taskbarHidden = Boolean(data.taskbarHidden);
    targetPatch.keyboardHookActive = Boolean(data.keyboardHookActive);
    targetPatch.focusLockActive = Boolean(data.focusLockActive);
    targetPatch.inputHookActive = Boolean(data.inputHookActive);
    targetPatch.mouseHookActive = Boolean(data.mouseHookActive);
    targetPatch.focusHookActive = Boolean(data.focusHookActive);
    targetPatch.clipboardListenerActive = Boolean(data.clipboardListenerActive);
    targetPatch.overlayHealActive = Boolean(data.overlayHealActive);
    targetPatch.captureHealActive = Boolean(data.captureHealActive);
    targetPatch.captureProtectionActive = Boolean(data.captureProtectionActive);
    targetPatch.captureProtectionStatus =
      typeof data.captureProtectionStatus === "string"
        ? data.captureProtectionStatus
        : runtimeSnapshot.captureProtectionStatus;
    targetPatch.electronContentProtectionActive =
      typeof data.electronContentProtectionActive === "boolean"
        ? data.electronContentProtectionActive
        : runtimeSnapshot.electronContentProtectionActive;
    targetPatch.rustOverlayCaptureProtectionActive =
      typeof data.rustOverlayCaptureProtectionActive === "boolean"
        ? data.rustOverlayCaptureProtectionActive
        : runtimeSnapshot.rustOverlayCaptureProtectionActive;
    targetPatch.captureProtectionBestEffort =
      typeof data.captureProtectionBestEffort === "boolean"
        ? data.captureProtectionBestEffort
        : runtimeSnapshot.captureProtectionBestEffort;
    targetPatch.runtimeMonitorActive = Boolean(data.runtimeMonitorActive);
    targetPatch.activeMonitorCount =
      typeof data.activeMonitorCount === "number"
        ? data.activeMonitorCount
        : runtimeSnapshot.activeMonitorCount;
    targetPatch.blackOverlayCount =
      typeof data.blackOverlayCount === "number"
        ? data.blackOverlayCount
        : runtimeSnapshot.blackOverlayCount;
    targetPatch.lastRuntimeEventAt =
      typeof data.lastRuntimeEventAt === "number"
        ? data.lastRuntimeEventAt
        : runtimeSnapshot.lastRuntimeEventAt;
    targetPatch.safeExamMode = Boolean(
      targetPatch.examProtectionActive || targetPatch.kioskActive,
    );

    return targetPatch;
  }

  function applyRuntimeFoundationPatch(targetPatch, data) {
    if (!data || typeof data !== "object") {
      return targetPatch;
    }

    if (data.runtimeTelemetry && typeof data.runtimeTelemetry === "object") {
      targetPatch.runtimeTelemetry = data.runtimeTelemetry;
    }
    if (
      data.runtimeRiskLevel === "normal" ||
      data.runtimeRiskLevel === "elevated"
    ) {
      targetPatch.runtimeRiskLevel = data.runtimeRiskLevel;
    }
    if (data.processWatcher && typeof data.processWatcher === "object") {
      targetPatch.processWatcher = data.processWatcher;
    }
    if (
      data.processWatcherProducer &&
      typeof data.processWatcherProducer === "object"
    ) {
      targetPatch.processWatcherProducer = data.processWatcherProducer;
    }
    if (
      data.runtimeStateEngine &&
      typeof data.runtimeStateEngine === "object"
    ) {
      targetPatch.runtimeStateEngine = data.runtimeStateEngine;
    }
    if (data.emergencyRestore && typeof data.emergencyRestore === "object") {
      targetPatch.emergencyRestore = data.emergencyRestore;
    }
    if (Array.isArray(data.runtimeEvents)) {
      targetPatch.runtimeEvents = data.runtimeEvents.filter(
        (event) => event && typeof event === "object",
      );
    }

    return targetPatch;
  }

  function updateSnapshot(patch, options = {}) {
    const previousSessionState = runtimeSnapshot.sessionState;
    let effectivePatch =
      patch?.sessionState === SESSION_STATES.EXAM_RUNNING
        ? {
            ...patch,
            sessionState: SESSION_STATES.EXAM_RUNNING_CONFIRMED,
          }
        : patch;
    if (patch?.sessionState === SESSION_STATES.EXAM_RUNNING) {
      examGuardTracer?.recordLoop?.({
        action: "atomic_state_canonicalized",
        decision: "EXAM_RUNNING_CONFIRMED",
        state: previousSessionState,
        reason: options.reason ?? "legacy_exam_running_state",
      });
      logDesktopCore("Atomic state engine canonicalized legacy state", {
        from: SESSION_STATES.EXAM_RUNNING,
        to: SESSION_STATES.EXAM_RUNNING_CONFIRMED,
        reason: options.reason ?? "runtime_snapshot_update",
      });
    }
    const requestedSessionState =
      typeof effectivePatch?.sessionState === "string"
        ? effectivePatch.sessionState
        : null;
    const isLockedOverrideBlocked =
      isStateLocked(previousSessionState) &&
      requestedSessionState &&
      !isValidLockedStateForwardTransition(
        previousSessionState,
        requestedSessionState,
      ) &&
      !options.allowLockedStateOverride;

    if (isLockedOverrideBlocked) {
      effectivePatch = { ...patch };
      for (const field of LOCKED_STATE_CRITICAL_FIELDS) {
        if (field in effectivePatch) {
          delete effectivePatch[field];
        }
      }
      effectivePatch.sessionState = previousSessionState;
      effectivePatch.safeExamMode = runtimeSnapshot.safeExamMode;
      effectivePatch.examProtectionActive = runtimeSnapshot.examProtectionActive;
      effectivePatch.kioskActive = runtimeSnapshot.kioskActive;
      effectivePatch.runtimeMonitorActive = runtimeSnapshot.runtimeMonitorActive;
      examGuardTracer?.recordLoop?.({
        action: "locked_state_override_blocked",
        decision: "blocked",
        state: previousSessionState,
        reason: `${options.reason ?? "runtime_snapshot_update"} requested ${requestedSessionState}`,
      });
      logDesktopCore("State lock blocked invalid active exam transition", {
        from: previousSessionState,
        requested: requestedSessionState,
        reason: options.reason ?? "runtime_snapshot_update",
      });
    }

    const exitFlowMutationAllowed = options.allowExitFlowMutation === true;
    if (
      runtimeSnapshot.exitInProgress &&
      !exitFlowMutationAllowed &&
      effectivePatch &&
      typeof effectivePatch === "object"
    ) {
      const guardedPatch = { ...effectivePatch };
      let blocked = false;
      for (const field of LOCKED_STATE_CRITICAL_FIELDS) {
        if (field in guardedPatch) {
          delete guardedPatch[field];
          blocked = true;
        }
      }
      if ("exitInProgress" in guardedPatch) {
        delete guardedPatch.exitInProgress;
        blocked = true;
      }
      if ("stateTransitionLock" in guardedPatch) {
        delete guardedPatch.stateTransitionLock;
        blocked = true;
      }
      if ("uiInteractionLocked" in guardedPatch) {
        delete guardedPatch.uiInteractionLocked;
        blocked = true;
      }
      if (blocked) {
        effectivePatch = guardedPatch;
        examGuardTracer?.recordLoop?.({
          action: "state_governor_exit_lock",
          decision: "blocked",
          state: previousSessionState,
          reason: options.reason ?? "external_state_update_during_exit",
        });
        logDesktopCore("State governor blocked update during exit lock", {
          sessionState: previousSessionState,
          reason: options.reason ?? "runtime_snapshot_update",
        });
      }
    }

    if (
      effectivePatch &&
      Object.prototype.hasOwnProperty.call(effectivePatch, "audioLockActive") &&
      !isAudioLockMutationAllowed(options) &&
      requestedSessionState !== SESSION_STATES.EXAM_RUNNING_CONFIRMED
    ) {
      effectivePatch = { ...effectivePatch };
      delete effectivePatch.audioLockActive;
      examGuardTracer?.recordAudio?.({
        event: "AUDIO_STATE_OVERRIDE_TRIED",
        processName: "desktop-core",
        action: "blocked_audioLockActive_patch",
        state: previousSessionState,
        audioLockActive: runtimeSnapshot.audioLockActive,
        reason: options.reason ?? "runtime_snapshot_update",
        source: "desktop-core",
      });
    }

    if (
      requestedSessionState === SESSION_STATES.EXAM_RUNNING_CONFIRMED
    ) {
      effectivePatch = {
        ...effectivePatch,
        audioLockActive: true,
      };
    }

    const nextSnapshot = createDesktopRuntimeSnapshot({
      ...runtimeSnapshot,
      ...effectivePatch,
      examMode: effectivePatch.examMode ?? activeExamMode,
    });
    const result = stateEngine.apply({
      sequenceId: stateEngine.issueSequenceId(),
      type: options.eventType ?? "RUNTIME_SNAPSHOT_PATCH",
      source: options.source ?? "desktop-core",
      reason: options.reason ?? "runtime_snapshot_update",
      scope:
        options.governorScope ?? GOVERNOR_EVENT_SCOPES.RUNTIME,
      lockMode: options.governorLockMode,
      unlockAfterApply: options.governorUnlockAfterApply === true,
      reduce() {
        return nextSnapshot;
      },
    });
    return result.snapshot;
  }

  function getSnapshot() {
    return stateEngine.getSnapshot();
  }

  function hasRuntimeProtection(snapshot = runtimeSnapshot) {
    const activeLifecycleStates = new Set([
      SESSION_STATES.STARTING_EXAM_SESSION,
      SESSION_STATES.SAVING_DESKTOP_STATE,
      SESSION_STATES.ENTERING_KIOSK,
      SESSION_STATES.EXAM_RUNNING_CONFIRMED,
      SESSION_STATES.PROTECTION_ACTIVE,
      SESSION_STATES.EXIT_REQUESTED,
      SESSION_STATES.EXITING_KIOSK,
      SESSION_STATES.RESTORING_DESKTOP,
    ]);

    return Boolean(
      snapshot.safeExamMode ||
      snapshot.examProtectionActive ||
      snapshot.kioskActive ||
      snapshot.overlayActive ||
      snapshot.taskbarHidden ||
      snapshot.keyboardHookActive ||
      snapshot.focusLockActive ||
      activeLifecycleStates.has(snapshot.sessionState),
    );
  }

  async function restoreVisualProtectionBestEffort(reason, options = {}) {
    stopRuntimeMonitorLoop();
    if (isStateLocked(runtimeSnapshot.sessionState) && !options.allowLockedStateOverride) {
      examGuardTracer?.recordLoop?.({
        action: "restore_visual_best_effort",
        decision: "blocked",
        state: runtimeSnapshot.sessionState,
        reason: "active_exam_state_lock",
      });
      logDesktopCore("State lock blocked best-effort visual restore", {
        reason,
        sessionState: runtimeSnapshot.sessionState,
      });
      return null;
    }

    if (!protectionController?.hasActiveProtection?.()) {
      return null;
    }

    try {
      const visualPatch = await protectionController.restoreExamProtection();
      updateSnapshot({
        ...visualPatch,
        safeExamMode: false,
        kioskHandoffCompleted: false,
        sessionState: SESSION_STATES.IDLE,
        errorCode: null,
      }, {
        allowLockedStateOverride: Boolean(options.allowLockedStateOverride),
        reason: "restore_visual_best_effort",
      });
      logDesktopCore(
        "Local visual protection restored with best-effort fallback",
        { reason },
      );
      return visualPatch;
    } catch (error) {
      console.error(
        "[desktop-core] Failed to restore local visual protection",
        error,
      );
      return null;
    }
  }

  async function teardownExamEnvironment(reason) {
    stopRuntimeMonitorLoop();
    const shouldAskRustToRestore =
      sidecarTransport.isConnected() && hasRuntimeProtection(runtimeSnapshot);
    let restoreResponse = null;

    if (shouldAskRustToRestore) {
      logDesktopCore(
        "Requesting protected session teardown before shutdown/exit",
        {
          reason,
          sessionState: runtimeSnapshot.sessionState,
        },
      );
      restoreResponse = await handleCommand({
        requestId: `desktop-teardown-${Date.now()}`,
        cmd: "force_restore_desktop",
        payload: {
          reason: "application_shutdown",
          detail: reason,
          allowActiveExamRestore: true,
          explicitTermination: true,
        },
      });
    }

    if (!restoreResponse?.ok) {
      await restoreVisualProtectionBestEffort(reason, {
        allowLockedStateOverride: true,
      });
    }

    return restoreResponse;
  }

  async function start() {
    logDesktopCore("Starting Rust sidecar bootstrap...");
    const startResult = await sidecarTransport.start();

    if (!startResult.connected) {
      logDesktopCore("Rust sidecar is not available yet.", {
        errorCode: startResult.errorCode ?? CORE_ERROR_CODES.CORE_NOT_CONNECTED,
        message: startResult.message ?? null,
      });
      updateSnapshot({
        nativeCoreConnected: false,
        safeExamMode: false,
        coreVersion: null,
        sessionState: SESSION_STATES.INIT,
        lastCoreHeartbeat: null,
        examProtectionActive: false,
        protectionDryRun: false,
        kioskActive: false,
        overlayActive: false,
        taskbarHidden: false,
        keyboardHookActive: false,
        focusLockActive: false,
        inputHookActive: false,
        mouseHookActive: false,
        focusHookActive: false,
        clipboardListenerActive: false,
        overlayHealActive: false,
        captureHealActive: false,
        captureProtectionActive: false,
        captureProtectionStatus: "inactive",
        electronContentProtectionActive: false,
        rustOverlayCaptureProtectionActive: false,
        captureProtectionBestEffort: false,
        runtimeMonitorActive: false,
        activeMonitorCount: 0,
        blackOverlayCount: 0,
        lastRuntimeEventAt: null,
        errorCode: startResult.errorCode ?? CORE_ERROR_CODES.CORE_NOT_CONNECTED,
      });

      return runtimeSnapshot;
    }

    logDesktopCore("Rust sidecar spawned.", {
      binaryPath: startResult.binaryPath ?? null,
    });

    logDesktopCore("Sending handshake command: ping");
    const pingResponse = await sidecarTransport.request({
      cmd: "ping",
      payload: {},
    });
    logDesktopCore("Received handshake response: ping", pingResponse);

    logDesktopCore("Sending handshake command: get_core_version");
    const versionResponse = await sidecarTransport.request({
      cmd: "get_core_version",
      payload: {},
    });
    logDesktopCore(
      "Received handshake response: get_core_version",
      versionResponse,
    );

    logDesktopCore("Sending handshake command: get_status");
    const statusResponse = await sidecarTransport.request({
      cmd: "get_status",
      payload: {},
    });
    logDesktopCore("Received handshake response: get_status", statusResponse);

    const initialSnapshotPatch = {
      nativeCoreConnected:
        pingResponse.ok && versionResponse.ok && statusResponse.ok,
      safeExamMode: Boolean(statusResponse.data?.safeExamMode),
      coreVersion:
        versionResponse.ok &&
        typeof versionResponse.data?.coreVersion === "string"
          ? versionResponse.data.coreVersion
          : null,
      sessionState:
        statusResponse.ok &&
        typeof statusResponse.data?.sessionState === "string"
          ? statusResponse.data.sessionState
          : SESSION_STATES.INIT,
      lastCoreHeartbeat:
        pingResponse.ok && typeof pingResponse.data?.bridgeAliveAt === "number"
          ? pingResponse.data.bridgeAliveAt
          : Date.now(),
      precheckCollectedAt:
        statusResponse.ok &&
        typeof statusResponse.data?.precheckCollectedAt === "number"
          ? statusResponse.data.precheckCollectedAt
          : null,
      precheckAvailable: Boolean(statusResponse.data?.precheckAvailable),
      precheckSummary:
        statusResponse.ok &&
        statusResponse.data?.precheckSummary &&
        typeof statusResponse.data.precheckSummary === "object"
          ? statusResponse.data.precheckSummary
          : null,
      precheckStatus:
        statusResponse.ok &&
        typeof statusResponse.data?.precheckStatus === "string"
          ? statusResponse.data.precheckStatus
          : null,
      precheckRiskScore:
        statusResponse.ok &&
        typeof statusResponse.data?.precheckRiskScore === "number"
          ? statusResponse.data.precheckRiskScore
          : null,
      precheckRecommendations:
        statusResponse.ok &&
        Array.isArray(statusResponse.data?.precheckRecommendations)
          ? statusResponse.data.precheckRecommendations.filter(
              (entry) => typeof entry === "string",
            )
          : null,
      preflightCollectedAt:
        statusResponse.ok &&
        typeof statusResponse.data?.preflightCollectedAt === "number"
          ? statusResponse.data.preflightCollectedAt
          : null,
      preflightStatus:
        statusResponse.ok &&
        typeof statusResponse.data?.preflightStatus === "string"
          ? statusResponse.data.preflightStatus
          : null,
      preflightCanEnterExam:
        statusResponse.ok &&
        typeof statusResponse.data?.preflightCanEnterExam === "boolean"
          ? statusResponse.data.preflightCanEnterExam
          : null,
      preflightPrimaryReasonCode:
        statusResponse.ok &&
        typeof statusResponse.data?.preflightPrimaryReasonCode === "string"
          ? statusResponse.data.preflightPrimaryReasonCode
          : null,
      errorCode:
        pingResponse.ok && versionResponse.ok && statusResponse.ok
          ? null
          : (pingResponse.error?.code ??
            versionResponse.error?.code ??
            statusResponse.error?.code ??
            CORE_ERROR_CODES.IPC_FAILURE),
    };
    applyProtectionSnapshotPatch(initialSnapshotPatch, statusResponse.data);
    applyRuntimeFoundationPatch(initialSnapshotPatch, statusResponse.data);
    updateSnapshot(initialSnapshotPatch);

    if (runtimeSnapshot.kioskActive && runtimeSnapshot.examProtectionActive) {
      startRuntimeMonitorLoop();
    }

    logDesktopCore("Runtime snapshot hydrated from Rust sidecar.", {
      nativeCoreConnected: runtimeSnapshot.nativeCoreConnected,
      coreVersion: runtimeSnapshot.coreVersion,
      sessionState: runtimeSnapshot.sessionState,
      lastCoreHeartbeat: runtimeSnapshot.lastCoreHeartbeat,
      errorCode: runtimeSnapshot.errorCode,
    });

    return runtimeSnapshot;
  }

  async function stop() {
    logDesktopCore("Stopping Rust sidecar...");
    stopRuntimeMonitorLoop();
    clearExitFallbackTimers({ invalidate: true });
    if (runtimeSnapshot.audioLockActive) {
      setAudioLockActive(false, "desktop_core_stop_session_destroyed");
    }
    await teardownExamEnvironment(
      "Desktop shell is shutting down and must restore any active exam protection.",
    );
    await sidecarTransport.stop();
  }

  async function handleCommand(request) {
    const requestId =
      request &&
      typeof request.requestId === "string" &&
      request.requestId.trim()
        ? request.requestId
        : `desktop-core-${Date.now()}`;

    if (!request || typeof request !== "object") {
      return createCoreErrorResponse(
        requestId,
        CORE_ERROR_CODES.INVALID_REQUEST,
        "Desktop core request must be an object.",
      );
    }

    if (!isSafeExamCommand(request.cmd)) {
      return createCoreErrorResponse(
        requestId,
        CORE_ERROR_CODES.INVALID_COMMAND,
        `Unsupported desktop core command: ${String(request.cmd)}`,
      );
    }

    if (
      request.cmd === "start_exam_session" &&
      !runtimeSnapshot.stateGovernorProductionGatePassed
    ) {
      return createCoreErrorResponse(
        requestId,
        CORE_ERROR_CODES.PROTECTION_FAILURE,
        "State governor production gate failed. Exam mode is blocked fail-safe.",
      );
    }

    if (request.cmd === "begin_exam_exit_confirmation") {
      const duplicateResponse = beginExitConfirmation(
        request.payload?.reason ?? "ui_exit_confirmation_opened",
      );
      if (duplicateResponse) {
        return {
          ...duplicateResponse,
          requestId,
        };
      }
      return createCoreSuccessResponse(requestId, {
        exitInProgress: runtimeSnapshot.exitInProgress,
        stateTransitionLock: runtimeSnapshot.stateTransitionLock,
        uiInteractionLocked: runtimeSnapshot.uiInteractionLocked,
        sessionState: runtimeSnapshot.sessionState,
        previousSessionState: exitPreviousSessionState,
      });
    }

    if (request.cmd === "cancel_exam_exit_confirmation") {
      cancelExitConfirmation(
        request.payload?.reason ?? "ui_exit_confirmation_cancelled",
      );
      return createCoreSuccessResponse(requestId, {
        exitInProgress: false,
        stateTransitionLock: false,
        uiInteractionLocked: false,
        sessionState: runtimeSnapshot.sessionState,
      });
    }

    const normalizedRequest =
      request.cmd === "start_exam_session" || request.cmd === "enter_kiosk"
        ? {
            ...request,
            payload: {
              ...(request.payload ?? {}),
              windowHandleHex:
                typeof request.payload?.windowHandleHex === "string"
                  ? request.payload.windowHandleHex
                  : (protectionController?.getMainWindowHandleHex?.() ?? null),
            },
          }
        : request;
    const isDemoStaticSessionStart =
      normalizedRequest.cmd === "start_exam_session" &&
      normalizedRequest.payload?.examMode === DEMO_STATIC_EXAM_MODE;
    if (isDemoStaticSessionStart) {
      activeExamMode = DEMO_STATIC_EXAM_MODE;
    }

    const isExplicitActiveExamRestore =
      normalizedRequest.cmd === "exit_exam_session" ||
      normalizedRequest.cmd === "request_emergency_restore" ||
      (normalizedRequest.cmd === "force_restore_desktop" &&
        hasExplicitActiveExamRestoreIntent(normalizedRequest.payload));

    if (
      isExplicitActiveExamRestore &&
      runtimeSnapshot.sessionState === SESSION_STATES.EXITED
    ) {
      examGuardTracer?.recordLoop?.({
        action: normalizedRequest.cmd,
        decision: "idempotent_noop",
        state: runtimeSnapshot.sessionState,
        reason: "atomic_exit_already_completed",
      });
      return createCoreSuccessResponse(requestId, {
        duplicate: true,
        idempotentNoop: true,
        sessionState: SESSION_STATES.EXITED,
        audioLockActive: false,
        exitInProgress: false,
        stateTransitionLock: false,
        uiInteractionLocked: false,
      });
    }

    if (
      normalizedRequest.cmd === "force_restore_desktop" &&
      isStateLocked(runtimeSnapshot.sessionState) &&
      !isExplicitActiveExamRestore
    ) {
      examGuardTracer?.recordLoop?.({
        action: "force_restore_desktop",
        decision: "blocked",
        state: runtimeSnapshot.sessionState,
        reason: "active_exam_state_lock",
      });
      logDesktopCore("State lock blocked force_restore_desktop during active exam", {
        requestId,
        sessionState: runtimeSnapshot.sessionState,
        reason: normalizedRequest.payload?.reason ?? null,
      });
      return createCoreSuccessResponse(requestId, {
        blocked: true,
        lockedNoop: true,
        sessionState: runtimeSnapshot.sessionState,
        reason: "active_exam_state_lock",
        protectionStatus: buildProtectionStatusResponseData().protectionStatus,
      });
    }

    if (normalizedRequest.cmd === "get_protection_status") {
      if (runtimeSnapshot.exitInProgress) {
        stopRuntimeMonitorLoop();
        examGuardTracer?.recordLoop?.({
          action: "protection_status",
          decision: "safe_noop",
          state: runtimeSnapshot.sessionState,
          reason: "state_governor_exit_in_progress",
        });
        return createCoreSuccessResponse(
          requestId,
          buildProtectionStatusResponseData({
            safeNoop: true,
            skipReason: "stateGovernorExitInProgress",
          }),
        );
      }

      if (isDemoStaticMode()) {
        const startedAt = Date.now();
        const demoPatch = {
          nativeCoreConnected: true,
          safeExamMode: true,
          examMode: DEMO_STATIC_EXAM_MODE,
          audioLockActive: true,
          kioskHandoffCompleted: true,
          sessionState: SESSION_STATES.EXAM_RUNNING_CONFIRMED,
          examProtectionActive: true,
          kioskActive: true,
          runtimeMonitorActive: false,
          errorCode: null,
          lastCoreHeartbeat: Date.now(),
        };
        if (
          runtimeSnapshot.sessionState !== SESSION_STATES.EXAM_RUNNING_CONFIRMED ||
          runtimeSnapshot.kioskHandoffCompleted !== true
        ) {
          updateSnapshot(demoPatch, {
            allowAudioLockMutation: true,
            reason: "demo_static_mock_state_stream",
          });
        }
        const response = createCoreSuccessResponse(
          requestId,
          buildProtectionStatusResponseData({
            mocked: true,
            source: "electron-cache",
            skipReason: "demoStaticPollingFreeze",
          }),
        );
        examGuardTracer?.recordIpc?.({
          command: "get_protection_status",
          requestId,
          ok: true,
          state: SESSION_STATES.EXAM_RUNNING_CONFIRMED,
          latencyMs: Date.now() - startedAt,
          source: "electron-cache",
          reason: "demo_static_mock_state_stream",
        });
        return response;
      }

      if (runtimeSnapshot.sessionState === SESSION_STATES.IDLE) {
        stopRuntimeMonitorLoop();
        if (runtimeSnapshot.runtimeMonitorActive) {
          updateSnapshot({ runtimeMonitorActive: false });
        }
        logDesktopCore("protectionSkippedBecauseIdle", {
          cmd: normalizedRequest.cmd,
          sessionState: runtimeSnapshot.sessionState,
        });
        return createCoreSuccessResponse(
          requestId,
          buildProtectionStatusResponseData({
            safeNoop: true,
            skipReason: "protectionSkippedBecauseIdle",
          }),
        );
      }

      if (
        !isProtectionStatusAllowedSessionState(runtimeSnapshot.sessionState)
      ) {
        stopRuntimeMonitorLoop();
        if (runtimeSnapshot.runtimeMonitorActive) {
          updateSnapshot({ runtimeMonitorActive: false });
        }
        logDesktopCore("protectionSkippedBecauseIdle", {
          cmd: normalizedRequest.cmd,
          sessionState: runtimeSnapshot.sessionState,
        });
        return createCoreSuccessResponse(
          requestId,
          buildProtectionStatusResponseData({
            safeNoop: true,
            skipReason: "protectionSkippedBecauseSessionNotReady",
          }),
        );
      }

      const now = Date.now();
      const isPreSession =
        runtimeSnapshot.sessionState !==
        SESSION_STATES.EXAM_RUNNING_CONFIRMED;
      const isEnteringKioskGraceActive =
        runtimeSnapshot.sessionState === SESSION_STATES.ENTERING_KIOSK &&
        enteringKioskSince !== null &&
        now - enteringKioskSince < KIOSK_HANDOFF_GRACE_PERIOD_MS;
      if (isEnteringKioskGraceActive) {
        logDesktopCore("protectionStatusGraceWindowActive", {
          cmd: normalizedRequest.cmd,
          sessionState: runtimeSnapshot.sessionState,
          graceRemainingMs:
            KIOSK_HANDOFF_GRACE_PERIOD_MS - (now - enteringKioskSince),
        });
      }
      if (
        isPreSession &&
        !isEnteringKioskGraceActive &&
        now - lastPreSessionProtectionStatusAt <
          PRE_SESSION_PROTECTION_STATUS_DEBOUNCE_MS
      ) {
        logDesktopCore("protectionStatusDebounced", {
          cmd: normalizedRequest.cmd,
          sessionState: runtimeSnapshot.sessionState,
          debounceMs: PRE_SESSION_PROTECTION_STATUS_DEBOUNCE_MS,
        });
        return createCoreSuccessResponse(
          requestId,
          buildProtectionStatusResponseData({
            debounced: true,
            debounceMs: PRE_SESSION_PROTECTION_STATUS_DEBOUNCE_MS,
          }),
        );
      }

      if (isPreSession) {
        lastPreSessionProtectionStatusAt = now;
      }
    }

    const category =
      normalizedRequest.cmd === "get_protection_status" ||
      normalizedRequest.cmd === "run_runtime_monitor_tick"
        ? "protection"
        : normalizedRequest.cmd === "start_exam_session" ||
            normalizedRequest.cmd === "run_preflight"
          ? "session"
          : "application";

    if (isExplicitActiveExamRestore) {
      markExitRequested(`${normalizedRequest.cmd}_confirmed_by_ui`);
    }

    const rustPayload =
      isDemoStaticSessionStart && normalizedRequest.payload
        ? Object.fromEntries(
            Object.entries(normalizedRequest.payload).filter(
              ([key]) => key !== "examMode",
            ),
          )
        : (normalizedRequest.payload ?? {});

    logger.info(
      category,
      `Forwarding command to Rust: ${normalizedRequest.cmd}`,
      { payload: rustPayload },
    );
    const rustRequestStartedAt = Date.now();
    const response = await sidecarTransport.request(
      {
        requestId,
        cmd: normalizedRequest.cmd,
        payload: rustPayload,
      },
      {
        timeoutMs:
          normalizedRequest.cmd === "preflight_kill" ||
          normalizedRequest.cmd === "run_preflight" ||
          normalizedRequest.cmd === "start_exam_session" ||
          normalizedRequest.cmd === "request_emergency_restore" ||
          // Creating the isolated desktop spawns an Electron process, which can
          // take longer than the default handshake timeout.
          normalizedRequest.cmd === "create_exam_desktop"
            ? 15000
            : normalizedRequest.cmd === "exit_exam_session" ||
                normalizedRequest.cmd === "force_restore_desktop"
              ? EXIT_RUST_ACK_TIMEOUT_MS
            : undefined,
      },
    );
    examGuardTracer?.recordIpc?.({
      command: normalizedRequest.cmd,
      requestId,
      ok: response.ok,
      state:
        typeof response.data?.sessionState === "string"
          ? response.data.sessionState
          : runtimeSnapshot.sessionState,
      latencyMs: Date.now() - rustRequestStartedAt,
      source: "rust",
      reason: response.error?.message ?? null,
    });

    if (!response.ok) {
      if (isExplicitActiveExamRestore) {
        await forceExitCleanup(`${normalizedRequest.cmd}_rust_no_ack`, exitFlowGeneration);
        return createCoreSuccessResponse(requestId, {
          fallback: true,
          rustAck: false,
          reason: response.error?.message ?? "Rust exit command did not acknowledge.",
          sessionState: runtimeSnapshot.sessionState,
          audioLockActive: runtimeSnapshot.audioLockActive,
          exitInProgress: runtimeSnapshot.exitInProgress,
          stateTransitionLock: runtimeSnapshot.stateTransitionLock,
          uiInteractionLocked: runtimeSnapshot.uiInteractionLocked,
          ...buildProtectionStatusResponseData(),
        });
      }

      updateSnapshot({
        nativeCoreConnected:
          response.error?.code !== CORE_ERROR_CODES.CORE_NOT_CONNECTED &&
          response.error?.code !== CORE_ERROR_CODES.IPC_FAILURE,
        errorCode: response.error?.code ?? CORE_ERROR_CODES.IPC_FAILURE,
      });

      logDesktopCore(
        `Rust command failed: ${normalizedRequest.cmd}`,
        response.error,
      );
      return response;
    }

    if (
      response.data &&
      typeof response.data === "object" &&
      response.data.sessionState === SESSION_STATES.EXAM_RUNNING
    ) {
      response.data.sessionState = SESSION_STATES.EXAM_RUNNING_CONFIRMED;
    }

    const nextSnapshotPatch = {
      nativeCoreConnected: true,
      errorCode: null,
      lastCoreHeartbeat: Date.now(),
    };

    if (
      normalizedRequest.cmd === "get_core_version" &&
      typeof response.data?.coreVersion === "string"
    ) {
      nextSnapshotPatch.coreVersion = response.data.coreVersion;
    }

    if (
      normalizedRequest.cmd === "get_status" &&
      response.data &&
      typeof response.data === "object"
    ) {
      nextSnapshotPatch.safeExamMode = Boolean(response.data.safeExamMode);
      nextSnapshotPatch.coreVersion =
        typeof response.data.coreVersion === "string"
          ? response.data.coreVersion
          : runtimeSnapshot.coreVersion;
      nextSnapshotPatch.sessionState =
        typeof response.data.sessionState === "string"
          ? response.data.sessionState
          : runtimeSnapshot.sessionState;
      nextSnapshotPatch.lastCoreHeartbeat =
        typeof response.data.lastCoreHeartbeat === "number"
          ? response.data.lastCoreHeartbeat
          : Date.now();
      nextSnapshotPatch.precheckCollectedAt =
        typeof response.data.precheckCollectedAt === "number"
          ? response.data.precheckCollectedAt
          : runtimeSnapshot.precheckCollectedAt;
      nextSnapshotPatch.precheckAvailable = Boolean(
        response.data.precheckAvailable,
      );
      nextSnapshotPatch.precheckSummary =
        response.data.precheckSummary &&
        typeof response.data.precheckSummary === "object"
          ? response.data.precheckSummary
          : runtimeSnapshot.precheckSummary;
      nextSnapshotPatch.precheckStatus =
        typeof response.data.precheckStatus === "string"
          ? response.data.precheckStatus
          : runtimeSnapshot.precheckStatus;
      nextSnapshotPatch.precheckRiskScore =
        typeof response.data.precheckRiskScore === "number"
          ? response.data.precheckRiskScore
          : runtimeSnapshot.precheckRiskScore;
      nextSnapshotPatch.precheckRecommendations = Array.isArray(
        response.data.precheckRecommendations,
      )
        ? response.data.precheckRecommendations.filter(
            (entry) => typeof entry === "string",
          )
        : runtimeSnapshot.precheckRecommendations;
      nextSnapshotPatch.preflightCollectedAt =
        typeof response.data.preflightCollectedAt === "number"
          ? response.data.preflightCollectedAt
          : runtimeSnapshot.preflightCollectedAt;
      nextSnapshotPatch.preflightStatus =
        typeof response.data.preflightStatus === "string"
          ? response.data.preflightStatus
          : runtimeSnapshot.preflightStatus;
      nextSnapshotPatch.preflightCanEnterExam =
        typeof response.data.preflightCanEnterExam === "boolean"
          ? response.data.preflightCanEnterExam
          : runtimeSnapshot.preflightCanEnterExam;
      nextSnapshotPatch.preflightPrimaryReasonCode =
        typeof response.data.preflightPrimaryReasonCode === "string"
          ? response.data.preflightPrimaryReasonCode
          : runtimeSnapshot.preflightPrimaryReasonCode;
      applyProtectionSnapshotPatch(nextSnapshotPatch, response.data);
      applyRuntimeFoundationPatch(nextSnapshotPatch, response.data);
    }

    if (
      normalizedRequest.cmd === "ping" &&
      typeof response.data?.sessionState === "string"
    ) {
      nextSnapshotPatch.sessionState = response.data.sessionState;
    }

    if (
      normalizedRequest.cmd === "collect_precheck_snapshot" &&
      response.data &&
      typeof response.data === "object"
    ) {
      nextSnapshotPatch.precheckCollectedAt =
        typeof response.data.collectedAt === "number"
          ? response.data.collectedAt
          : Date.now();
      nextSnapshotPatch.precheckAvailable = true;
      nextSnapshotPatch.precheckSummary =
        response.data.summary && typeof response.data.summary === "object"
          ? response.data.summary
          : null;
    }

    if (
      normalizedRequest.cmd === "collect_precheck_report" &&
      response.data &&
      typeof response.data === "object"
    ) {
      nextSnapshotPatch.precheckCollectedAt =
        typeof response.data.collectedAt === "number"
          ? response.data.collectedAt
          : Date.now();
      nextSnapshotPatch.precheckAvailable = true;
      nextSnapshotPatch.precheckSummary =
        response.data.snapshot?.summary &&
        typeof response.data.snapshot.summary === "object"
          ? response.data.snapshot.summary
          : null;
      nextSnapshotPatch.precheckStatus =
        typeof response.data.evaluation?.status === "string"
          ? response.data.evaluation.status
          : null;
      nextSnapshotPatch.precheckRiskScore =
        typeof response.data.evaluation?.totalRiskScore === "number"
          ? response.data.evaluation.totalRiskScore
          : null;
      nextSnapshotPatch.precheckRecommendations = Array.isArray(
        response.data.evaluation?.secondaryRecommendations,
      )
        ? response.data.evaluation.secondaryRecommendations.filter(
            (entry) => typeof entry === "string",
          )
        : null;
      nextSnapshotPatch.preflightCollectedAt = null;
      nextSnapshotPatch.preflightStatus = null;
      nextSnapshotPatch.preflightCanEnterExam = null;
      nextSnapshotPatch.preflightPrimaryReasonCode = null;
    }

    if (
      normalizedRequest.cmd === "run_preflight" &&
      response.data &&
      typeof response.data === "object"
    ) {
      nextSnapshotPatch.precheckCollectedAt =
        typeof response.data.report?.collectedAt === "number"
          ? response.data.report.collectedAt
          : Date.now();
      nextSnapshotPatch.precheckAvailable = true;
      nextSnapshotPatch.precheckSummary =
        response.data.report?.snapshot?.summary &&
        typeof response.data.report.snapshot.summary === "object"
          ? response.data.report.snapshot.summary
          : runtimeSnapshot.precheckSummary;
      nextSnapshotPatch.precheckStatus =
        typeof response.data.report?.evaluation?.status === "string"
          ? response.data.report.evaluation.status
          : runtimeSnapshot.precheckStatus;
      nextSnapshotPatch.precheckRiskScore =
        typeof response.data.report?.evaluation?.totalRiskScore === "number"
          ? response.data.report.evaluation.totalRiskScore
          : runtimeSnapshot.precheckRiskScore;
      nextSnapshotPatch.precheckRecommendations = Array.isArray(
        response.data.report?.evaluation?.secondaryRecommendations,
      )
        ? response.data.report.evaluation.secondaryRecommendations.filter(
            (entry) => typeof entry === "string",
          )
        : runtimeSnapshot.precheckRecommendations;
      nextSnapshotPatch.preflightCollectedAt =
        typeof response.data.collectedAt === "number"
          ? response.data.collectedAt
          : Date.now();
      nextSnapshotPatch.preflightStatus =
        typeof response.data.decision?.status === "string"
          ? response.data.decision.status
          : null;
      nextSnapshotPatch.preflightCanEnterExam =
        typeof response.data.decision?.canEnterExam === "boolean"
          ? response.data.decision.canEnterExam
          : null;
      nextSnapshotPatch.preflightPrimaryReasonCode =
        typeof response.data.decision?.primaryReasonCode === "string"
          ? response.data.decision.primaryReasonCode
          : null;
    }

    if (
      normalizedRequest.cmd === "start_exam_session" &&
      response.data &&
      typeof response.data === "object"
    ) {
      setAudioLockActive(true, "start_exam_session_accepted");
      nextSnapshotPatch.sessionState =
        typeof response.data.sessionState === "string"
          ? response.data.sessionState
          : runtimeSnapshot.sessionState;
      nextSnapshotPatch.examMode = activeExamMode;
      nextSnapshotPatch.audioLockActive = true;
      nextSnapshotPatch.kioskHandoffCompleted = false;
      response.data.audioLockActive = true;
      applyProtectionSnapshotPatch(
        nextSnapshotPatch,
        response.data.protectionStatus,
      );
      applyRuntimeFoundationPatch(nextSnapshotPatch, response.data);

      // VS-02: cache the exit-password hash from the server's session start response
      // so the exit gate stays closed even if the network is unreachable.
      const sessionCtx = response.data?.sessionContext;
      const exitHash = sessionCtx && typeof sessionCtx === "object"
        ? sessionCtx.exitPasswordHash
        : undefined;
      if (exitHash) {
        cacheExitPasswordHash(sessionCtx.sessionId ?? "", exitHash);
      }

      if (!response.data?.sessionContext?.dryRun && protectionController) {
        const windowHandleHex =
          typeof request.payload?.windowHandleHex === "string"
            ? normalizedRequest.payload.windowHandleHex
            : (protectionController.getMainWindowHandleHex?.() ?? null);

        try {
          const visualPatch = await protectionController.enterExamProtection({
            useOverlayFallback: false,
          });
          Object.assign(nextSnapshotPatch, visualPatch);

          const enterKioskStartedAt = Date.now();
          const kioskResponse = await sidecarTransport.request(
            {
              requestId: `${requestId}-enter-kiosk`,
              cmd: "enter_kiosk",
              payload: {
                sessionId:
                  typeof response.data?.sessionContext?.sessionId === "string"
                    ? response.data.sessionContext.sessionId
                    : null,
                windowHandleHex,
                electronContentProtectionActive: Boolean(
                  visualPatch.electronContentProtectionActive,
                ),
              },
            },
            {
              timeoutMs: NATIVE_KIOSK_COMMAND_TIMEOUT_MS,
            },
          );
          examGuardTracer?.recordIpc?.({
            command: "kiosk_handoff",
            requestId: `${requestId}-enter-kiosk`,
            ok: kioskResponse.ok,
            state:
              typeof kioskResponse.data?.sessionState === "string"
                ? kioskResponse.data.sessionState
                : runtimeSnapshot.sessionState,
            latencyMs: Date.now() - enterKioskStartedAt,
            source: "rust",
            reason: "enter_kiosk",
          });

          if (!kioskResponse.ok) {
            await protectionController.restoreExamProtection();
            await sidecarTransport
              .request({
                requestId: `${requestId}-rollback`,
                cmd: "force_restore_desktop",
                payload: {
                  reason:
                    "Visual kiosk activation failed and required a forced rollback.",
                },
              })
              .catch(() => null);
            updateSnapshot({
              ...nextSnapshotPatch,
              audioLockActive: false,
              examProtectionActive: false,
              kioskActive: false,
              overlayActive: false,
              blackOverlayCount: 0,
              errorCode:
                kioskResponse.error?.code ??
                CORE_ERROR_CODES.PROTECTION_FAILURE,
            }, {
              allowAudioLockMutation: true,
              reason: "start_exam_session_enter_kiosk_failed_safe_restore",
            });
            recordAudio(
              "AUDIO_LOCK_RELEASED",
              "start_failure_safe_restore",
              "enter_kiosk_failed_before_room_confirmed",
            );
            logger.logProtectionFailure(
              "Rust enter_kiosk failed after visual apply",
              kioskResponse.error,
              runtimeSnapshot.sessionState,
              [], // prohibited processes
              [], // scans
              kioskResponse.requestId,
              kioskResponse,
            );
            return kioskResponse;
          }

          if (kioskResponse.data && typeof kioskResponse.data === "object") {
            nextSnapshotPatch.sessionState =
              typeof kioskResponse.data.sessionState === "string"
                ? kioskResponse.data.sessionState
                : nextSnapshotPatch.sessionState;
            applyProtectionSnapshotPatch(
              nextSnapshotPatch,
              kioskResponse.data.protectionStatus,
            );
            if (
              Array.isArray(response.data.logLines) &&
              Array.isArray(kioskResponse.data.logLines)
            ) {
              response.data.logLines = [
                ...response.data.logLines,
                ...kioskResponse.data.logLines,
              ];
            }
          }

          const interactionPatch =
            await protectionController.enterInteractionProtection({
              skipKeyboardGuard: Boolean(
                kioskResponse.data?.protectionStatus?.keyboardHookActive,
              ),
              skipFocusGuard: Boolean(
                kioskResponse.data?.protectionStatus?.focusLockActive,
              ),
            });
          Object.assign(nextSnapshotPatch, interactionPatch);

          if (isDemoStaticMode()) {
            nextSnapshotPatch.examMode = DEMO_STATIC_EXAM_MODE;
            nextSnapshotPatch.runtimeMonitorActive = false;
            updateSnapshot({
              ...nextSnapshotPatch,
              sessionState: SESSION_STATES.ENTERING_KIOSK,
            }, {
              allowAudioLockMutation: true,
              reason: "demo_static_entering_kiosk_bridge",
            });
            examGuardTracer?.recordLoop?.({
              action: "watchdog_reset_disabled",
              decision: "demo_static",
              state: SESSION_STATES.ENTERING_KIOSK,
              reason: "disableWatchdogReset_disableIDLEFallback",
            });
            await waitForDelay(DEMO_STATIC_CONFIRM_DELAY_MS);
            nextSnapshotPatch.sessionState =
              SESSION_STATES.EXAM_RUNNING_CONFIRMED;
            nextSnapshotPatch.examProtectionActive = true;
            nextSnapshotPatch.kioskActive = true;
            nextSnapshotPatch.safeExamMode = true;
            nextSnapshotPatch.runtimeMonitorActive = false;
            nextSnapshotPatch.examMode = DEMO_STATIC_EXAM_MODE;
            nextSnapshotPatch.kioskHandoffCompleted = true;
            if (response.data && typeof response.data === "object") {
              response.data.kioskHandoffCompleted = true;
              response.data.examMode = DEMO_STATIC_EXAM_MODE;
              if (Array.isArray(response.data.logLines)) {
                response.data.logLines = [
                  ...response.data.logLines,
                  {
                    timestamp: Date.now(),
                    level: "success",
                    code: "DEMO_STATIC_AUTO_CONFIRM",
                    message:
                      "DEMO_STATIC bridged ENTERING_KIOSK to EXAM_RUNNING_CONFIRMED without Rust final ACK.",
                  },
                ];
              }
            }
            updateSnapshot(nextSnapshotPatch, {
              allowAudioLockMutation: true,
              reason: "demo_static_auto_confirm",
            });
            examGuardTracer?.recordIpc?.({
              command: "EXAM_RUNNING_CONFIRMED emit",
              requestId: `${requestId}-demo-static-confirm`,
              ok: true,
              state: SESSION_STATES.EXAM_RUNNING_CONFIRMED,
              latencyMs: DEMO_STATIC_CONFIRM_DELAY_MS,
              source: "electron",
              reason: "demo_static_auto_bridge",
            });
            if (response.data && typeof response.data === "object") {
              response.data.sessionState = runtimeSnapshot.sessionState;
            }
            logDesktopCore("DEMO_STATIC session auto-confirmed", {
              requestId,
              sessionState: runtimeSnapshot.sessionState,
            });
            return response;
          }

          // --- Visual kiosk handoff: soft-fail with retry ---
          // Attempt notify_visual_kiosk_ready up to 2 times with 5s timeout.
          // On failure: log warning and proceed (do NOT trigger PROTECTION_FAILURE).
          const HANDOFF_TIMEOUT_MS = 5000;
          const HANDOFF_MAX_ATTEMPTS = 2;
          let kioskHandoffCompleted = false;

          for (let attempt = 1; attempt <= HANDOFF_MAX_ATTEMPTS; attempt++) {
            try {
              const handoffStartedAt = Date.now();
              const handoffResponse = await Promise.race([
                sidecarTransport.request(
                  {
                    requestId: `${requestId}-notify-handoff-${attempt}`,
                    cmd: "notify_visual_kiosk_ready",
                    payload: {
                      sessionId:
                        typeof response.data?.sessionContext?.sessionId ===
                        "string"
                          ? response.data.sessionContext.sessionId
                          : null,
                    },
                  },
                  {
                    timeoutMs: HANDOFF_TIMEOUT_MS,
                  },
                ),
                new Promise((_, reject) =>
                  setTimeout(
                    () =>
                      reject(
                        new Error(
                          `Chuyển giao chế độ phòng thi quá thời gian chờ (${HANDOFF_TIMEOUT_MS}ms, lần ${attempt}).`,
                        ),
                      ),
                    HANDOFF_TIMEOUT_MS + 500,
                  ),
                ),
              ]);
              examGuardTracer?.recordIpc?.({
                command: "kiosk_handoff",
                requestId: `${requestId}-notify-handoff-${attempt}`,
                ok: handoffResponse.ok,
                state:
                  typeof handoffResponse.data?.sessionState === "string"
                    ? handoffResponse.data.sessionState
                    : nextSnapshotPatch.sessionState,
                latencyMs: Date.now() - handoffStartedAt,
                source: "rust",
                reason: `notify_visual_kiosk_ready_attempt_${attempt}`,
              });

              if (handoffResponse.ok) {
                kioskHandoffCompleted = true;
                if (
                  handoffResponse.data &&
                  typeof handoffResponse.data === "object"
                ) {
                  nextSnapshotPatch.sessionState =
                    typeof handoffResponse.data.sessionState === "string"
                      ? handoffResponse.data.sessionState
                      : nextSnapshotPatch.sessionState;
                  applyProtectionSnapshotPatch(
                    nextSnapshotPatch,
                    handoffResponse.data.protectionStatus,
                  );
                  if (
                    Array.isArray(response.data.logLines) &&
                    Array.isArray(handoffResponse.data.logLines)
                  ) {
                    response.data.logLines = [
                      ...response.data.logLines,
                      ...handoffResponse.data.logLines,
                    ];
                  }
                }
                break;
              } else {
                // IPC returned an error (e.g. unsupported command, state mismatch)
                const errMsg =
                  handoffResponse.error?.message ?? "Unknown error";
                const errCode = handoffResponse.error?.code ?? "UNKNOWN";
                logger.warn(
                  "session",
                  `Kiosk handoff attempt ${attempt} failed: [${errCode}] ${errMsg}`,
                );
                if (attempt < HANDOFF_MAX_ATTEMPTS) {
                  await new Promise((r) => setTimeout(r, 800));
                }
              }
            } catch (handoffError) {
              examGuardTracer?.recordIpc?.({
                command: "kiosk_handoff",
                requestId: `${requestId}-notify-handoff-${attempt}`,
                ok: false,
                state: nextSnapshotPatch.sessionState,
                latencyMs: HANDOFF_TIMEOUT_MS,
                source: "rust",
                reason:
                  handoffError instanceof Error
                    ? handoffError.message
                    : String(handoffError),
              });
              logger.warn(
                "session",
                `Kiosk handoff attempt ${attempt} exception: ${handoffError instanceof Error ? handoffError.message : handoffError}`,
              );
              if (attempt < HANDOFF_MAX_ATTEMPTS) {
                await new Promise((r) => setTimeout(r, 800));
              }
            }
          }

          if (!kioskHandoffCompleted) {
            nextSnapshotPatch.kioskHandoffCompleted = false;
            // Soft-fail: log warning but do NOT roll back or trigger PROTECTION_FAILURE.
            // The session continues in ENTERING_KIOSK state — protection is still active.
            logger.warn(
              "session",
              "Chuyển giao chế độ phòng thi thất bại sau tất cả các lần thử. " +
                "Phiên thi tiếp tục với trạng thái ENTERING_KIOSK. " +
                "Bảo vệ vẫn đang hoạt động.",
            );
            if (response.data && typeof response.data === "object") {
              response.data.kioskHandoffCompleted = false;
            }
          } else {
            logger.info("session", "[Telemetry] kiosk_handoff_completed");
            nextSnapshotPatch.kioskHandoffCompleted = true;
            if (response.data && typeof response.data === "object") {
              response.data.kioskHandoffCompleted = true;
            }
            logger.info("session", "[Telemetry] exam_running_set");
          }

          updateSnapshot(nextSnapshotPatch);
          startRuntimeMonitorLoop();

          // Patch the response with the final settled session state so the
          // renderer doesn't rely on async snapshot propagation via RUNTIME_CHANGED.
          // Without this, the renderer receives the original Rust response
          // (sessionState: "STARTING_EXAM_SESSION") and must poll getSnapshot()
          // which depends on async IPC — creating a race condition.
          if (response.data && typeof response.data === "object") {
            response.data.sessionState = runtimeSnapshot.sessionState;
          }
        } catch (error) {
          stopRuntimeMonitorLoop();
          await protectionController.restoreExamProtection().catch(() => null);
          setAudioLockActive(false, "start_exam_session_visual_apply_failed_safe_restore");
          await sidecarTransport
            .request({
              requestId: `${requestId}-rollback`,
              cmd: "force_restore_desktop",
              payload: {
                reason:
                  "Visual kiosk apply failed before Rust could enter kiosk mode.",
              },
            })
            .catch(() => null);
          logger.logProtectionFailure(
            "Visual kiosk apply failed",
            { error: error instanceof Error ? error.message : error },
            runtimeSnapshot.sessionState,
            [],
            [],
            requestId,
            null,
          );
          return createCoreErrorResponse(
            requestId,
            CORE_ERROR_CODES.PROTECTION_FAILURE,
            error instanceof Error
              ? error.message
              : "Failed to apply visual kiosk protection.",
          );
        }
      }
    }

    if (
      (normalizedRequest.cmd === "exit_exam_session" ||
        normalizedRequest.cmd === "force_restore_desktop" ||
        normalizedRequest.cmd === "request_emergency_restore") &&
      response.data &&
      typeof response.data === "object"
    ) {
      stopRuntimeMonitorLoop();
      activeExamMode = null;
      nextSnapshotPatch.examMode = null;
      markExiting(`${normalizedRequest.cmd}_rust_ack`);
      nextSnapshotPatch.audioLockActive = runtimeSnapshot.audioLockActive;
      nextSnapshotPatch.kioskHandoffCompleted = false;
      response.data.audioLockActive = runtimeSnapshot.audioLockActive;
      const restoreData = resolveRestorePayload(response.data);
      const shouldRestoreVisualProtection = Boolean(
        protectionController &&
        (protectionController.hasActiveProtection() ||
          runtimeSnapshot.kioskActive ||
          runtimeSnapshot.examProtectionActive ||
          runtimeSnapshot.overlayActive ||
          runtimeSnapshot.taskbarHidden ||
          runtimeSnapshot.keyboardHookActive ||
          runtimeSnapshot.focusLockActive),
      );

      if (shouldRestoreVisualProtection) {
        logDesktopCore("Restoring visual protection after exit command", {
          cmd: normalizedRequest.cmd,
          snapshot: {
            examProtectionActive: runtimeSnapshot.examProtectionActive,
            kioskActive: runtimeSnapshot.kioskActive,
            overlayActive: runtimeSnapshot.overlayActive,
            taskbarHidden: runtimeSnapshot.taskbarHidden,
            keyboardHookActive: runtimeSnapshot.keyboardHookActive,
            focusLockActive: runtimeSnapshot.focusLockActive,
          },
          controllerHasActiveProtection:
            protectionController?.hasActiveProtection?.() ?? false,
        });
        const visualPatch = await protectionController.restoreExamProtection();
        Object.assign(nextSnapshotPatch, visualPatch);
      }

      nextSnapshotPatch.sessionState = SESSION_STATES.EXAM_EXITING;
      nextSnapshotPatch.runtimeRiskLevel = "normal";
      applyProtectionSnapshotPatch(
        nextSnapshotPatch,
        restoreData?.protectionStatus,
      );
      applyRuntimeFoundationPatch(nextSnapshotPatch, response.data);
      nextSnapshotPatch.sessionState = SESSION_STATES.EXITED;
      nextSnapshotPatch.audioLockActive = false;
      nextSnapshotPatch.exitInProgress = false;
      nextSnapshotPatch.stateTransitionLock = false;
      nextSnapshotPatch.uiInteractionLocked = false;
      response.data.sessionState = SESSION_STATES.EXITED;
      response.data.audioLockActive = false;
      recordAudio(
        "AUDIO_LOCK_RELEASED",
        "restoreAudio",
        `${normalizedRequest.cmd}_exit_flow_reached_exited`,
      );
    }

    if (
      normalizedRequest.cmd === "get_protection_status" &&
      response.data &&
      typeof response.data === "object"
    ) {
      nextSnapshotPatch.sessionState =
        typeof response.data.sessionState === "string"
          ? response.data.sessionState
          : runtimeSnapshot.sessionState;
      applyProtectionSnapshotPatch(
        nextSnapshotPatch,
        response.data.protectionStatus,
      );
      applyRuntimeFoundationPatch(nextSnapshotPatch, response.data);
      if (protectionController) {
        Object.assign(
          nextSnapshotPatch,
          protectionController.getVisualSnapshotPatch(),
        );
      }
    }

    if (
      normalizedRequest.cmd === "run_runtime_monitor_tick" &&
      response.data &&
      typeof response.data === "object"
    ) {
      nextSnapshotPatch.sessionState =
        typeof response.data.sessionState === "string"
          ? response.data.sessionState
          : runtimeSnapshot.sessionState;
      applyProtectionSnapshotPatch(
        nextSnapshotPatch,
        response.data.protectionStatus,
      );
      applyRuntimeFoundationPatch(nextSnapshotPatch, response.data);
    }

    const updatedSnapshot = updateSnapshot(nextSnapshotPatch, {
      allowLockedStateOverride: isExplicitActiveExamRestore,
      allowAudioLockMutation:
        normalizedRequest.cmd === "start_exam_session" ||
        isExplicitActiveExamRestore,
      allowExitFlowMutation: isExplicitActiveExamRestore,
      governorScope: isExplicitActiveExamRestore
        ? GOVERNOR_EVENT_SCOPES.EXIT_FLOW
        : GOVERNOR_EVENT_SCOPES.RUNTIME,
      governorUnlockAfterApply:
        isExplicitActiveExamRestore &&
        nextSnapshotPatch.sessionState === SESSION_STATES.EXITED,
      reason: normalizedRequest.cmd,
    });
    if (
      isExplicitActiveExamRestore &&
      updatedSnapshot.sessionState === SESSION_STATES.EXITED
    ) {
      clearExitFallbackTimers({ invalidate: true });
      exitPreviousSessionState = null;
    }

    if (
      normalizedRequest.cmd === "get_protection_status" ||
      normalizedRequest.cmd === "run_runtime_monitor_tick"
    ) {
      if (
        runtimeSnapshot.kioskActive &&
        runtimeSnapshot.examProtectionActive &&
        isRuntimeMonitorAllowedSessionState(runtimeSnapshot.sessionState)
      ) {
        startRuntimeMonitorLoop();
      } else {
        stopRuntimeMonitorLoop();
      }
    }

    logDesktopCore(`Rust command completed: ${normalizedRequest.cmd}`, {
      requestId: response.requestId,
      ok: response.ok,
      nativeCoreConnected: runtimeSnapshot.nativeCoreConnected,
      sessionState: runtimeSnapshot.sessionState,
      coreVersion: runtimeSnapshot.coreVersion,
    });
    return response;
  }

  protectionController?.setDisplaySyncHandler?.(async () => {
    const response = await sidecarTransport.request(
      {
        cmd: "sync_display_topology",
        payload: {},
      },
      { timeoutMs: 5000 },
    );

    if (response.ok && response.data && typeof response.data === "object") {
      const topologyPatch = {
        nativeCoreConnected: true,
        errorCode: null,
        lastCoreHeartbeat: Date.now(),
      };
      applyProtectionSnapshotPatch(
        topologyPatch,
        response.data.protectionStatus,
      );
      updateSnapshot(topologyPatch);
      return response.data;
    }

    if (!response.ok) {
      logDesktopCore("Rust display topology sync failed", response.error);
    }

    return response;
  });

  return {
    start,
    stop,
    getSnapshot,
    getAudioState() {
      return stateEngine.getAudioState();
    },
    // Backward-compatible test adapter. Every patch still enters the governor
    // event queue and receives a monotonic sequence id.
    updateSnapshot,
    handleCommand,
    onRuntimeChanged(listener) {
      emitter.on("runtime-changed", listener);
      return () => emitter.off("runtime-changed", listener);
    },
  };
}

module.exports = {
  createDesktopCoreRuntime,
};
