const { contextBridge, ipcRenderer } = require("electron");
const {
  DESKTOP_CORE_CHANNELS,
  RUNTIME_CHANGED_EVENT,
  SESSION_STATES,
  createDesktopRuntimeSnapshot,
} = require("./contracts/safe-exam");
const { TRACE_CHANNEL } = require("./exam-guard-trace");

let runtimeSnapshot = createDesktopRuntimeSnapshot({
  platform: process.platform,
});
let commandCounter = 0;

function applyRuntimeSnapshot(snapshot) {
  const incomingGovernorId =
    typeof snapshot?.stateGovernorId === "string"
      ? snapshot.stateGovernorId
      : null;
  const incomingSequenceId =
    typeof snapshot?.stateGovernorSequenceId === "number"
      ? snapshot.stateGovernorSequenceId
      : null;
  const isSameGovernor =
    incomingGovernorId !== null &&
    incomingGovernorId === runtimeSnapshot.stateGovernorId;

  if (
    isSameGovernor &&
    (incomingSequenceId === null ||
      incomingSequenceId <= runtimeSnapshot.stateGovernorSequenceId)
  ) {
    ipcRenderer.send(TRACE_CHANNEL, {
      kind: "electron_loop",
      action: "renderer_snapshot_discarded",
      decision: "stale",
      state: runtimeSnapshot.sessionState,
      reason: `incoming_sequence=${String(incomingSequenceId)} current_sequence=${runtimeSnapshot.stateGovernorSequenceId}`,
    });
    return runtimeSnapshot;
  }

  const previousSessionState = runtimeSnapshot.sessionState;
  runtimeSnapshot = createDesktopRuntimeSnapshot({
    ...runtimeSnapshot,
    ...(snapshot || {}),
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
    runtimeSnapshot.stateGovernorSequenceId ?? 0,
  );
  document.documentElement.dataset.stateGovernorLockMode =
    runtimeSnapshot.stateGovernorLockMode ?? "";
  document.documentElement.dataset.lastCoreHeartbeat = runtimeSnapshot.lastCoreHeartbeat
    ? String(runtimeSnapshot.lastCoreHeartbeat)
    : "";
  document.documentElement.dataset.precheckCollectedAt = runtimeSnapshot.precheckCollectedAt
    ? String(runtimeSnapshot.precheckCollectedAt)
    : "";
  document.documentElement.dataset.precheckAvailable = runtimeSnapshot.precheckAvailable ? "true" : "false";
  document.documentElement.dataset.precheckSummary = runtimeSnapshot.precheckSummary
    ? JSON.stringify(runtimeSnapshot.precheckSummary)
    : "";
  document.documentElement.dataset.precheckStatus = runtimeSnapshot.precheckStatus ?? "";
  document.documentElement.dataset.precheckRiskScore =
    typeof runtimeSnapshot.precheckRiskScore === "number" ? String(runtimeSnapshot.precheckRiskScore) : "";
  document.documentElement.dataset.precheckRecommendations = Array.isArray(runtimeSnapshot.precheckRecommendations)
    ? JSON.stringify(runtimeSnapshot.precheckRecommendations)
    : "";
  document.documentElement.dataset.preflightCollectedAt = runtimeSnapshot.preflightCollectedAt
    ? String(runtimeSnapshot.preflightCollectedAt)
    : "";
  document.documentElement.dataset.preflightStatus = runtimeSnapshot.preflightStatus ?? "";
  document.documentElement.dataset.preflightCanEnterExam =
    typeof runtimeSnapshot.preflightCanEnterExam === "boolean"
      ? String(runtimeSnapshot.preflightCanEnterExam)
      : "";
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
  document.documentElement.dataset.electronContentProtectionActive =
    runtimeSnapshot.electronContentProtectionActive ? "true" : "false";
  document.documentElement.dataset.rustOverlayCaptureProtectionActive =
    runtimeSnapshot.rustOverlayCaptureProtectionActive ? "true" : "false";
  document.documentElement.dataset.captureProtectionBestEffort =
    runtimeSnapshot.captureProtectionBestEffort ? "true" : "false";
  document.documentElement.dataset.runtimeMonitorActive = runtimeSnapshot.runtimeMonitorActive ? "true" : "false";
  document.documentElement.dataset.activeMonitorCount = String(runtimeSnapshot.activeMonitorCount ?? 0);
  document.documentElement.dataset.blackOverlayCount = String(runtimeSnapshot.blackOverlayCount ?? 0);
  document.documentElement.dataset.lastRuntimeEventAt = runtimeSnapshot.lastRuntimeEventAt
    ? String(runtimeSnapshot.lastRuntimeEventAt)
    : "";
  document.documentElement.dataset.coreErrorCode = runtimeSnapshot.errorCode ?? "";
  document.documentElement.dataset.guardHealth = JSON.stringify(runtimeSnapshot.guardHealth ?? {});

  if (
    typeof previousSessionState === "string" &&
    previousSessionState !== runtimeSnapshot.sessionState
  ) {
    const audioState =
      runtimeSnapshot.sessionState === SESSION_STATES.EXAM_EXITING ||
      runtimeSnapshot.sessionState === SESSION_STATES.EXITED
        ? "RESTORE"
        : runtimeSnapshot.exitInProgress ||
            runtimeSnapshot.sessionState === SESSION_STATES.ENTERING_KIOSK
          ? "HOLD"
          : runtimeSnapshot.audioLockActive
            ? "MUTE"
            : "RESTORE";
    const uiShellMode =
      runtimeSnapshot.sessionState === SESSION_STATES.EXAM_RUNNING_CONFIRMED
        ? "ExamShellLayout"
            : [
              SESSION_STATES.STARTING_EXAM_SESSION,
              SESSION_STATES.ENTERING_KIOSK,
              SESSION_STATES.EXAM_EXIT_REQUESTED,
              SESSION_STATES.EXAM_EXITING,
            ].includes(runtimeSnapshot.sessionState)
          ? "AtomicLoadingScreen"
          : "AppLayout";
    console.log("[STATE_TRACE]", {
      from: previousSessionState,
      to: runtimeSnapshot.sessionState,
      source: "preload-governor-snapshot",
      timestamp: new Date().toISOString(),
      governorId: runtimeSnapshot.stateGovernorId,
      kioskFlag: runtimeSnapshot.kioskActive,
      overlayFlag: runtimeSnapshot.overlayActive,
      audioState,
      inputLock: Boolean(
        runtimeSnapshot.uiInteractionLocked ||
          runtimeSnapshot.stateTransitionLock ||
          [
            SESSION_STATES.STARTING_EXAM_SESSION,
            SESSION_STATES.ENTERING_KIOSK,
            SESSION_STATES.RECOVERY_REQUIRED,
            SESSION_STATES.EXAM_EXIT_REQUESTED,
            SESSION_STATES.EXAM_EXITING,
          ].includes(runtimeSnapshot.sessionState),
      ),
      uiShellMode,
    });
    ipcRenderer.send(TRACE_CHANNEL, {
      kind: "state_trace",
      from: previousSessionState,
      to: runtimeSnapshot.sessionState,
      source: "preload",
      reason: "runtime_snapshot_applied",
    });
  }

  window.dispatchEvent(
    new CustomEvent(RUNTIME_CHANGED_EVENT, {
      detail: runtimeSnapshot,
    }),
  );
  return runtimeSnapshot;
}

function buildCommandRequest(command) {
  commandCounter += 1;

  return {
    requestId:
      typeof command?.requestId === "string" && command.requestId.trim()
        ? command.requestId
        : `renderer-${Date.now()}-${commandCounter}`,
    cmd: command?.cmd,
    payload: command?.payload ?? {},
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
  },
});

contextBridge.exposeInMainWorld("desktopCore", {
  getRuntimeSnapshot: () => ipcRenderer.invoke(DESKTOP_CORE_CHANNELS.GET_RUNTIME_SNAPSHOT),
  request: (command) => ipcRenderer.invoke(DESKTOP_CORE_CHANNELS.REQUEST, buildCommandRequest(command)),
  startExamSession: (payload) =>
    ipcRenderer
      .invoke(
        DESKTOP_CORE_CHANNELS.REQUEST,
        buildCommandRequest({
          cmd: "start_exam_session",
          payload,
        }),
      )
      .then(async (response) => {
        if (response?.ok) {
          const governedSnapshot = await ipcRenderer.invoke(
            DESKTOP_CORE_CHANNELS.GET_RUNTIME_SNAPSHOT,
          );
          applyRuntimeSnapshot(governedSnapshot);
        }
        return response;
      }),
  exitExamSession: (payload) =>
    ipcRenderer.invoke(
      DESKTOP_CORE_CHANNELS.REQUEST,
      buildCommandRequest({
        cmd: "exit_exam_session",
        payload,
      }),
    ),
  forceRestoreDesktop: () =>
    ipcRenderer.invoke(
      DESKTOP_CORE_CHANNELS.REQUEST,
      buildCommandRequest({
        cmd: "force_restore_desktop",
      }),
    ),
  getProtectionStatus: () =>
    ipcRenderer.invoke(
      DESKTOP_CORE_CHANNELS.REQUEST,
      buildCommandRequest({
        cmd: "get_protection_status",
      }),
    ),
  loadExamPolicy: (payload) =>
    ipcRenderer.invoke(
      DESKTOP_CORE_CHANNELS.REQUEST,
      buildCommandRequest({
        cmd: "load_policy",
        payload,
      }),
    ),
  getPolicyStatus: () =>
    ipcRenderer.invoke(
      DESKTOP_CORE_CHANNELS.REQUEST,
      buildCommandRequest({
        cmd: "get_policy_status",
      }),
    ),
});

contextBridge.exposeInMainWorld("desktopOAuth", {
  openExternal: (url) => ipcRenderer.invoke("desktop-oauth:open-external", url),
  getPendingCallback: () => ipcRenderer.invoke("desktop-oauth:get-pending"),
  onCallback: (handler) => {
    const listener = (_event, payload) => handler(payload);
    ipcRenderer.on("desktop-oauth:callback", listener);
    return () => ipcRenderer.removeListener("desktop-oauth:callback", listener);
  },
});

contextBridge.exposeInMainWorld("examGuardTrace", {
  log: (payload) => ipcRenderer.send(TRACE_CHANNEL, payload),
});

// ─── V10.9X: Input Hardening State Sets ─────────────────────────────────────
// ENTERING_KIOSK = TRANSITION ONLY → blocks ALL input (no UI access)
// EXAM_RUNNING_CONFIRMED = MASTER STATE → allows single-key input only
// Legacy EXAM_RUNNING and every non-confirmed lifecycle state block all input.
// ─────────────────────────────────────────────────────────────────────────────
const ACTIVE_INPUT_LOCK_STATES = new Set([
  SESSION_STATES.STARTING_EXAM_SESSION,
  SESSION_STATES.ENTERING_KIOSK,
  SESSION_STATES.EXAM_RUNNING_CONFIRMED,
  SESSION_STATES.EXAM_RUNNING,
  SESSION_STATES.RECOVERY_REQUIRED,
]);

// States that allow single-key typing (the exam content states)
const SINGLE_KEY_ALLOWED_STATES = new Set([
  SESSION_STATES.EXAM_RUNNING_CONFIRMED,
]);

// States where ALL input is blocked (transition states, not exam content)
const FULL_INPUT_BLOCK_STATES = new Set([
  SESSION_STATES.STARTING_EXAM_SESSION,
  SESSION_STATES.ENTERING_KIOSK,
  SESSION_STATES.EXAM_RUNNING,
  SESSION_STATES.RECOVERY_REQUIRED,
]);
const pressedKeys = new Set();
let mediaPatchInstalled = false;
let mediaObserverInstalled = false;

function tracePreloadLoop(action, decision, reason, extra = {}) {
  ipcRenderer.send(TRACE_CHANNEL, {
    kind: "electron_loop",
    action,
    decision,
    state: runtimeSnapshot.sessionState,
    reason,
    source: "preload",
    ...extra,
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
    ...extra,
  });
}

function isMediaLocked() {
  if (
    runtimeSnapshot.sessionState === SESSION_STATES.EXAM_EXITING ||
    runtimeSnapshot.sessionState === SESSION_STATES.EXITED
  ) {
    return false;
  }
  return Boolean(
    runtimeSnapshot.sessionState ===
      SESSION_STATES.EXAM_RUNNING_CONFIRMED ||
      (runtimeSnapshot.audioLockActive && runtimeSnapshot.exitInProgress),
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
      processName: element.tagName,
    });
    tracePreloadLoop("audio_block_event", "blocked", reason, {
      tagName: element.tagName,
    });
  } catch (error) {
    tracePreloadLoop("audio_block_event", "failed", reason, {
      error: error instanceof Error ? error.message : String(error),
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
    subtree: true,
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
        // Unsupported actions are ignored by Chromium on some platforms.
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
  ipcRenderer
    .invoke(DESKTOP_CORE_CHANNELS.GET_RUNTIME_SNAPSHOT)
    .then((snapshot) => {
      applyRuntimeSnapshot(snapshot);
      applyMediaLock("snapshot_hydrated");
    })
    .catch((error) => {
      console.error("[desktop] Failed to hydrate core runtime snapshot", error);
    });
  console.log("Electron preload ready");
});

// ─── V10.9X: Input Hardening and Lock System (Full Block) ────────────────────
// ALL key combos (2+ keys), modifiers (Ctrl/Alt/Shift/Win), function keys
// (F1-F12), and multi-key sequences are BLOCKED.
// ONLY single-key input (key.length === 1, no modifiers) is ALLOWED.
// ENTERING_KIOSK = blocks ALL input (transition only, no UI access)
// exitInProgress = blocks ALL input (exit UI only)
// ─────────────────────────────────────────────────────────────────────────────
function keyEventId(event) {
  return event.code || event.key || "unknown";
}

function isFunctionKey(event) {
  return /^F\d{1,2}$/.test(event.key);
}

function isWinKey(event) {
  return event.key === "Meta" || event.key === "OS" || event.code === "MetaLeft" || event.code === "MetaRight";
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
    pressedKeyCount: pressedKeys.size,
  });
  if (event.type === "keydown") {
    console.warn(`[InputBlockedEvent] ${reason}: ${event.key}`);
  }
}

const filterInputEvent = (event) => {
  const state = runtimeSnapshot.sessionState;
  const isActiveSession = ACTIVE_INPUT_LOCK_STATES.has(state);

  // ── V10.9X: GLOBAL PRIORITY OVERRIDE ──
  // If exitInProgress, block ALL input (exit UI only)
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

  // ── V10.9X: ENTERING_KIOSK + transition states = FULL INPUT BLOCK ──
  // These are transition-only states. No UI access, no input allowed.
  if (FULL_INPUT_BLOCK_STATES.has(state)) {
    blockInputEvent(event, `state_${state}_blocks_all_input`);
    if (event.type === "keyup") {
      pressedKeys.delete(keyEventId(event));
    }
    return;
  }

  // EXAM_RUNNING_CONFIRMED is the only state that permits single-key input.
  // This is the master exam content state. Only single-key input is allowed.
  if (SINGLE_KEY_ALLOWED_STATES.has(state)) {
    // Block Win key always
    if (isWinKey(event)) {
      blockInputEvent(event, "win_key_blocked");
      if (event.type === "keyup") {
        pressedKeys.delete(keyEventId(event));
      }
      return;
    }

    // Block ALL modifier combos (Ctrl+*, Alt+*, Shift+*, Meta+*)
    const isModifierPressed = event.ctrlKey || event.altKey || event.metaKey || event.shiftKey;
    if (isModifierPressed) {
      blockInputEvent(event, "modifier_key_combination");
      if (event.type === "keyup") {
        pressedKeys.delete(keyEventId(event));
      }
      return;
    }

    // Block multi-key chords (2+ keys held simultaneously)
    const isMultiKeyChord = event.type === "keydown" && pressedKeys.size > 1;
    if (isMultiKeyChord) {
      blockInputEvent(event, "multi_key_chord");
      if (event.type === "keyup") {
        pressedKeys.delete(keyEventId(event));
      }
      return;
    }

    // Block function keys (F1-F12)
    if (isFunctionKey(event)) {
      blockInputEvent(event, "function_key_blocked");
      if (event.type === "keyup") {
        pressedKeys.delete(keyEventId(event));
      }
      return;
    }

    // ALLOW ONLY single-key input (key.length === 1, no modifiers)
    const isSingleKey = typeof event.key === "string" && event.key.length === 1;
    if (!isSingleKey) {
      blockInputEvent(event, "non_single_character_key");
      if (event.type === "keyup") {
        pressedKeys.delete(keyEventId(event));
      }
      return;
    }

    // Single key allowed — pass through
    if (event.type === "keyup") {
      pressedKeys.delete(keyEventId(event));
    }
    return;
  }

  // Fallback: any other active session state blocks all input
  blockInputEvent(event, `state_${state}_blocks_all_input`);
  if (event.type === "keyup") {
    pressedKeys.delete(keyEventId(event));
  }
};

window.addEventListener("keydown", filterInputEvent, true);
window.addEventListener("keypress", filterInputEvent, true);
window.addEventListener("keyup", filterInputEvent, true);
