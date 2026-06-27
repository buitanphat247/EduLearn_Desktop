const { EventEmitter } = require("events");

const {
  CORE_ERROR_CODES,
  SESSION_STATES,
  createCoreErrorResponse,
  createCoreSuccessResponse,
  createDesktopRuntimeSnapshot,
  isSafeExamCommand,
} = require("../../shared/contracts/safe-exam");
const { createRustSidecarTransport } = require("./rust-sidecar");

function logDesktopCore(message, details) {
  if (typeof details === "undefined") {
    console.log(`[desktop-core] ${message}`);
    return;
  }

  console.log(`[desktop-core] ${message}`, details);
}

function createDesktopCoreRuntime({
  platform,
  protectionController = null,
  createSidecarTransport = createRustSidecarTransport,
}) {
  const emitter = new EventEmitter();
  const sidecarTransport = createSidecarTransport({
    onEvent(event) {
      logDesktopCore(`Received core event: ${event?.event ?? "UNKNOWN"}`, event?.data ?? null);
      if (event?.event === "RUST_CORE_READY") {
        updateSnapshot({
          nativeCoreConnected: true,
          coreVersion:
            typeof event?.data?.coreVersion === "string" ? event.data.coreVersion : runtimeSnapshot.coreVersion,
          lastCoreHeartbeat: typeof event?.timestamp === "number" ? event.timestamp : Date.now(),
          errorCode: null,
        });
      }
    },
    onExit(exitInfo) {
      logDesktopCore("Rust sidecar exited", exitInfo ?? null);
      if (protectionController) {
        void protectionController.restoreExamProtection().catch((error) => {
          console.error("[desktop-core] Failed to restore desktop protection after sidecar exit", error);
        });
      }
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
        captureProtectionActive: false,
        captureProtectionStatus: "inactive",
        runtimeMonitorActive: false,
        activeMonitorCount: 0,
        blackOverlayCount: 0,
        lastRuntimeEventAt: null,
        errorCode: CORE_ERROR_CODES.CORE_NOT_CONNECTED,
      });
    },
  });
  let runtimeSnapshot = createDesktopRuntimeSnapshot({
    platform,
    sessionState: SESSION_STATES.INIT,
  });

  function emitRuntimeChanged() {
    emitter.emit("runtime-changed", runtimeSnapshot);
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
    targetPatch.captureProtectionActive = Boolean(data.captureProtectionActive);
    targetPatch.captureProtectionStatus =
      typeof data.captureProtectionStatus === "string"
        ? data.captureProtectionStatus
        : runtimeSnapshot.captureProtectionStatus;
    targetPatch.runtimeMonitorActive = Boolean(data.runtimeMonitorActive);
    targetPatch.activeMonitorCount =
      typeof data.activeMonitorCount === "number" ? data.activeMonitorCount : runtimeSnapshot.activeMonitorCount;
    targetPatch.blackOverlayCount =
      typeof data.blackOverlayCount === "number" ? data.blackOverlayCount : runtimeSnapshot.blackOverlayCount;
    targetPatch.lastRuntimeEventAt =
      typeof data.lastRuntimeEventAt === "number" ? data.lastRuntimeEventAt : runtimeSnapshot.lastRuntimeEventAt;
    targetPatch.safeExamMode = Boolean(targetPatch.examProtectionActive || targetPatch.kioskActive);

    return targetPatch;
  }

  function updateSnapshot(patch) {
    runtimeSnapshot = createDesktopRuntimeSnapshot({
      ...runtimeSnapshot,
      ...patch,
    });
    emitRuntimeChanged();
    return runtimeSnapshot;
  }

  function getSnapshot() {
    return runtimeSnapshot;
  }

  function hasRuntimeProtection(snapshot = runtimeSnapshot) {
    const activeLifecycleStates = new Set([
      SESSION_STATES.STARTING_EXAM_SESSION,
      SESSION_STATES.SAVING_DESKTOP_STATE,
      SESSION_STATES.ENTERING_KIOSK,
      SESSION_STATES.PROTECTION_ACTIVE,
      SESSION_STATES.EXAM_RUNNING,
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

  async function restoreVisualProtectionBestEffort(reason) {
    if (!protectionController?.hasActiveProtection?.()) {
      return null;
    }

    try {
      const visualPatch = await protectionController.restoreExamProtection();
      updateSnapshot({
        ...visualPatch,
        safeExamMode: false,
        sessionState: SESSION_STATES.IDLE,
        errorCode: null,
      });
      logDesktopCore("Local visual protection restored with best-effort fallback", { reason });
      return visualPatch;
    } catch (error) {
      console.error("[desktop-core] Failed to restore local visual protection", error);
      return null;
    }
  }

  async function teardownExamEnvironment(reason) {
    const shouldAskRustToRestore = sidecarTransport.isConnected() && hasRuntimeProtection(runtimeSnapshot);
    let restoreResponse = null;

    if (shouldAskRustToRestore) {
      logDesktopCore("Requesting protected session teardown before shutdown/exit", {
        reason,
        sessionState: runtimeSnapshot.sessionState,
      });
      restoreResponse = await handleCommand({
        requestId: `desktop-teardown-${Date.now()}`,
        cmd: "force_restore_desktop",
        payload: { reason },
      });
    }

    if (!restoreResponse?.ok) {
      await restoreVisualProtectionBestEffort(reason);
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
        captureProtectionActive: false,
        captureProtectionStatus: "inactive",
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
    logDesktopCore("Received handshake response: get_core_version", versionResponse);

    logDesktopCore("Sending handshake command: get_status");
    const statusResponse = await sidecarTransport.request({
      cmd: "get_status",
      payload: {},
    });
    logDesktopCore("Received handshake response: get_status", statusResponse);

    const initialSnapshotPatch = {
      nativeCoreConnected: pingResponse.ok && versionResponse.ok && statusResponse.ok,
      safeExamMode: Boolean(statusResponse.data?.safeExamMode),
      coreVersion:
        versionResponse.ok && typeof versionResponse.data?.coreVersion === "string"
          ? versionResponse.data.coreVersion
          : null,
      sessionState:
        statusResponse.ok && typeof statusResponse.data?.sessionState === "string"
          ? statusResponse.data.sessionState
          : SESSION_STATES.INIT,
      lastCoreHeartbeat:
        pingResponse.ok && typeof pingResponse.data?.bridgeAliveAt === "number"
          ? pingResponse.data.bridgeAliveAt
          : Date.now(),
      precheckCollectedAt:
        statusResponse.ok && typeof statusResponse.data?.precheckCollectedAt === "number"
          ? statusResponse.data.precheckCollectedAt
          : null,
      precheckAvailable: Boolean(statusResponse.data?.precheckAvailable),
      precheckSummary:
        statusResponse.ok && statusResponse.data?.precheckSummary && typeof statusResponse.data.precheckSummary === "object"
          ? statusResponse.data.precheckSummary
          : null,
      precheckStatus:
        statusResponse.ok && typeof statusResponse.data?.precheckStatus === "string"
          ? statusResponse.data.precheckStatus
          : null,
      precheckRiskScore:
        statusResponse.ok && typeof statusResponse.data?.precheckRiskScore === "number"
          ? statusResponse.data.precheckRiskScore
          : null,
      precheckRecommendations:
        statusResponse.ok && Array.isArray(statusResponse.data?.precheckRecommendations)
          ? statusResponse.data.precheckRecommendations.filter((entry) => typeof entry === "string")
          : null,
      preflightCollectedAt:
        statusResponse.ok && typeof statusResponse.data?.preflightCollectedAt === "number"
          ? statusResponse.data.preflightCollectedAt
          : null,
      preflightStatus:
        statusResponse.ok && typeof statusResponse.data?.preflightStatus === "string"
          ? statusResponse.data.preflightStatus
          : null,
      preflightCanEnterExam:
        statusResponse.ok && typeof statusResponse.data?.preflightCanEnterExam === "boolean"
          ? statusResponse.data.preflightCanEnterExam
          : null,
      preflightPrimaryReasonCode:
        statusResponse.ok && typeof statusResponse.data?.preflightPrimaryReasonCode === "string"
          ? statusResponse.data.preflightPrimaryReasonCode
          : null,
      errorCode:
        pingResponse.ok && versionResponse.ok && statusResponse.ok
          ? null
          : pingResponse.error?.code ??
            versionResponse.error?.code ??
            statusResponse.error?.code ??
            CORE_ERROR_CODES.IPC_FAILURE,
    };
    applyProtectionSnapshotPatch(initialSnapshotPatch, statusResponse.data);
    updateSnapshot(initialSnapshotPatch);

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
    await teardownExamEnvironment("Desktop shell is shutting down and must restore any active exam protection.");
    await sidecarTransport.stop();
  }

  async function handleCommand(request) {
    const requestId =
      request && typeof request.requestId === "string" && request.requestId.trim()
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

    logDesktopCore(`Forwarding command to Rust: ${request.cmd}`);
    const response = await sidecarTransport.request(
      {
        requestId,
        cmd: request.cmd,
        payload: request.payload ?? {},
      },
      {
        timeoutMs:
          request.cmd === "run_preflight" || request.cmd === "start_exam_session" ? 15000 : undefined,
      },
    );

    if (!response.ok) {
      updateSnapshot({
        nativeCoreConnected:
          response.error?.code !== CORE_ERROR_CODES.CORE_NOT_CONNECTED &&
          response.error?.code !== CORE_ERROR_CODES.IPC_FAILURE,
        errorCode: response.error?.code ?? CORE_ERROR_CODES.IPC_FAILURE,
      });

      logDesktopCore(`Rust command failed: ${request.cmd}`, response.error);
      return response;
    }

    const nextSnapshotPatch = {
      nativeCoreConnected: true,
      errorCode: null,
      lastCoreHeartbeat: Date.now(),
    };

    if (request.cmd === "get_core_version" && typeof response.data?.coreVersion === "string") {
      nextSnapshotPatch.coreVersion = response.data.coreVersion;
    }

    if (request.cmd === "get_status" && response.data && typeof response.data === "object") {
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
      nextSnapshotPatch.precheckAvailable = Boolean(response.data.precheckAvailable);
      nextSnapshotPatch.precheckSummary =
        response.data.precheckSummary && typeof response.data.precheckSummary === "object"
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
      nextSnapshotPatch.precheckRecommendations = Array.isArray(response.data.precheckRecommendations)
        ? response.data.precheckRecommendations.filter((entry) => typeof entry === "string")
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
    }

    if (request.cmd === "ping" && typeof response.data?.sessionState === "string") {
      nextSnapshotPatch.sessionState = response.data.sessionState;
    }

    if (request.cmd === "collect_precheck_snapshot" && response.data && typeof response.data === "object") {
      nextSnapshotPatch.precheckCollectedAt =
        typeof response.data.collectedAt === "number" ? response.data.collectedAt : Date.now();
      nextSnapshotPatch.precheckAvailable = true;
      nextSnapshotPatch.precheckSummary =
        response.data.summary && typeof response.data.summary === "object" ? response.data.summary : null;
    }

    if (request.cmd === "collect_precheck_report" && response.data && typeof response.data === "object") {
      nextSnapshotPatch.precheckCollectedAt =
        typeof response.data.collectedAt === "number" ? response.data.collectedAt : Date.now();
      nextSnapshotPatch.precheckAvailable = true;
      nextSnapshotPatch.precheckSummary =
        response.data.snapshot?.summary && typeof response.data.snapshot.summary === "object"
          ? response.data.snapshot.summary
          : null;
      nextSnapshotPatch.precheckStatus =
        typeof response.data.evaluation?.status === "string" ? response.data.evaluation.status : null;
      nextSnapshotPatch.precheckRiskScore =
        typeof response.data.evaluation?.totalRiskScore === "number"
          ? response.data.evaluation.totalRiskScore
          : null;
      nextSnapshotPatch.precheckRecommendations = Array.isArray(response.data.evaluation?.secondaryRecommendations)
        ? response.data.evaluation.secondaryRecommendations.filter((entry) => typeof entry === "string")
        : null;
      nextSnapshotPatch.preflightCollectedAt = null;
      nextSnapshotPatch.preflightStatus = null;
      nextSnapshotPatch.preflightCanEnterExam = null;
      nextSnapshotPatch.preflightPrimaryReasonCode = null;
    }

    if (request.cmd === "run_preflight" && response.data && typeof response.data === "object") {
      nextSnapshotPatch.precheckCollectedAt =
        typeof response.data.report?.collectedAt === "number"
          ? response.data.report.collectedAt
          : Date.now();
      nextSnapshotPatch.precheckAvailable = true;
      nextSnapshotPatch.precheckSummary =
        response.data.report?.snapshot?.summary && typeof response.data.report.snapshot.summary === "object"
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
        ? response.data.report.evaluation.secondaryRecommendations.filter((entry) => typeof entry === "string")
        : runtimeSnapshot.precheckRecommendations;
      nextSnapshotPatch.preflightCollectedAt =
        typeof response.data.collectedAt === "number" ? response.data.collectedAt : Date.now();
      nextSnapshotPatch.preflightStatus =
        typeof response.data.decision?.status === "string" ? response.data.decision.status : null;
      nextSnapshotPatch.preflightCanEnterExam =
        typeof response.data.decision?.canEnterExam === "boolean" ? response.data.decision.canEnterExam : null;
      nextSnapshotPatch.preflightPrimaryReasonCode =
        typeof response.data.decision?.primaryReasonCode === "string"
          ? response.data.decision.primaryReasonCode
          : null;
    }

    if (request.cmd === "start_exam_session" && response.data && typeof response.data === "object") {
      nextSnapshotPatch.sessionState =
        typeof response.data.sessionState === "string" ? response.data.sessionState : runtimeSnapshot.sessionState;
      applyProtectionSnapshotPatch(nextSnapshotPatch, response.data.protectionStatus);

      if (!response.data?.sessionContext?.dryRun && protectionController) {
        try {
          const visualPatch = await protectionController.enterExamProtection();
          Object.assign(nextSnapshotPatch, visualPatch);

          const kioskResponse = await sidecarTransport.request({
            requestId: `${requestId}-enter-kiosk`,
            cmd: "enter_kiosk",
            payload: {
              sessionId:
                typeof response.data?.sessionContext?.sessionId === "string"
                  ? response.data.sessionContext.sessionId
                  : null,
            },
          });

          if (!kioskResponse.ok) {
            await protectionController.restoreExamProtection();
            await sidecarTransport.request({
              requestId: `${requestId}-rollback`,
              cmd: "force_restore_desktop",
              payload: {
                reason: "Visual kiosk activation failed and required a forced rollback.",
              },
            }).catch(() => null);
            updateSnapshot({
              ...nextSnapshotPatch,
              examProtectionActive: false,
              kioskActive: false,
              overlayActive: false,
              blackOverlayCount: 0,
              errorCode: kioskResponse.error?.code ?? CORE_ERROR_CODES.PROTECTION_FAILURE,
            });
            logDesktopCore("Rust enter_kiosk failed after visual apply", kioskResponse.error);
            return kioskResponse;
          }

          if (kioskResponse.data && typeof kioskResponse.data === "object") {
            nextSnapshotPatch.sessionState =
              typeof kioskResponse.data.sessionState === "string"
                ? kioskResponse.data.sessionState
                : nextSnapshotPatch.sessionState;
            applyProtectionSnapshotPatch(nextSnapshotPatch, kioskResponse.data.protectionStatus);
            if (Array.isArray(response.data.logLines) && Array.isArray(kioskResponse.data.logLines)) {
              response.data.logLines = [...response.data.logLines, ...kioskResponse.data.logLines];
            }
          }

          const interactionPatch = await protectionController.enterInteractionProtection({
            // Rust now owns the low-level keyboard hook when kiosk entry succeeds.
            // Electron keeps only the focus/UI fallback path unless native input
            // protection is unavailable.
            skipKeyboardGuard: Boolean(kioskResponse.data?.protectionStatus?.keyboardHookActive),
          });
          Object.assign(nextSnapshotPatch, interactionPatch);
        } catch (error) {
          await protectionController.restoreExamProtection().catch(() => null);
          await sidecarTransport.request({
            requestId: `${requestId}-rollback`,
            cmd: "force_restore_desktop",
            payload: {
              reason: "Visual kiosk apply failed before Rust could enter kiosk mode.",
            },
          }).catch(() => null);
          logDesktopCore("Visual kiosk apply failed", error);
          return createCoreErrorResponse(
            requestId,
            CORE_ERROR_CODES.PROTECTION_FAILURE,
            error instanceof Error ? error.message : "Failed to apply visual kiosk protection.",
          );
        }
      }
    }

    if (
      (request.cmd === "exit_exam_session" || request.cmd === "force_restore_desktop") &&
      response.data &&
      typeof response.data === "object"
    ) {
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
          cmd: request.cmd,
          snapshot: {
            examProtectionActive: runtimeSnapshot.examProtectionActive,
            kioskActive: runtimeSnapshot.kioskActive,
            overlayActive: runtimeSnapshot.overlayActive,
            taskbarHidden: runtimeSnapshot.taskbarHidden,
            keyboardHookActive: runtimeSnapshot.keyboardHookActive,
            focusLockActive: runtimeSnapshot.focusLockActive,
          },
          controllerHasActiveProtection: protectionController?.hasActiveProtection?.() ?? false,
        });
        const visualPatch = await protectionController.restoreExamProtection();
        Object.assign(nextSnapshotPatch, visualPatch);
      }

      nextSnapshotPatch.sessionState =
        typeof response.data.sessionState === "string" ? response.data.sessionState : SESSION_STATES.IDLE;
      applyProtectionSnapshotPatch(nextSnapshotPatch, response.data.protectionStatus);
    }

    if (request.cmd === "get_protection_status" && response.data && typeof response.data === "object") {
      nextSnapshotPatch.sessionState =
        typeof response.data.sessionState === "string" ? response.data.sessionState : runtimeSnapshot.sessionState;
      applyProtectionSnapshotPatch(nextSnapshotPatch, response.data.protectionStatus);
      if (protectionController) {
        Object.assign(nextSnapshotPatch, protectionController.getVisualSnapshotPatch());
      }
    }

    updateSnapshot(nextSnapshotPatch);
    logDesktopCore(`Rust command completed: ${request.cmd}`, {
      requestId: response.requestId,
      ok: response.ok,
      nativeCoreConnected: runtimeSnapshot.nativeCoreConnected,
      sessionState: runtimeSnapshot.sessionState,
      coreVersion: runtimeSnapshot.coreVersion,
    });
    return response;
  }

  return {
    start,
    stop,
    getSnapshot,
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
