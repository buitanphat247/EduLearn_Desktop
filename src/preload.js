const { contextBridge, ipcRenderer } = require("electron");
const {
  DESKTOP_CORE_CHANNELS,
  RUNTIME_CHANGED_EVENT,
  SESSION_STATES,
  createDesktopRuntimeSnapshot,
} = require("../../shared/contracts/safe-exam");

let runtimeSnapshot = createDesktopRuntimeSnapshot({
  platform: process.platform,
});
let commandCounter = 0;

function applyRuntimeSnapshot(snapshot) {
  runtimeSnapshot = createDesktopRuntimeSnapshot({
    ...runtimeSnapshot,
    ...(snapshot || {}),
  });

  document.documentElement.dataset.runtime = runtimeSnapshot.runtime;
  document.documentElement.dataset.shell = runtimeSnapshot.shell;
  document.documentElement.dataset.desktop = runtimeSnapshot.isDesktop ? "true" : "false";
  document.documentElement.dataset.safeExamMode = runtimeSnapshot.safeExamMode ? "true" : "false";
  document.documentElement.dataset.nativeCoreConnected = runtimeSnapshot.nativeCoreConnected ? "true" : "false";
  document.documentElement.dataset.runtimePlatform = runtimeSnapshot.platform;
  document.documentElement.dataset.coreVersion = runtimeSnapshot.coreVersion ?? "";
  document.documentElement.dataset.sessionState = runtimeSnapshot.sessionState ?? SESSION_STATES.INIT;
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
  document.documentElement.dataset.runtimeMonitorActive = runtimeSnapshot.runtimeMonitorActive ? "true" : "false";
  document.documentElement.dataset.activeMonitorCount = String(runtimeSnapshot.activeMonitorCount ?? 0);
  document.documentElement.dataset.blackOverlayCount = String(runtimeSnapshot.blackOverlayCount ?? 0);
  document.documentElement.dataset.lastRuntimeEventAt = runtimeSnapshot.lastRuntimeEventAt
    ? String(runtimeSnapshot.lastRuntimeEventAt)
    : "";
  document.documentElement.dataset.coreErrorCode = runtimeSnapshot.errorCode ?? "";

  window.dispatchEvent(
    new CustomEvent(RUNTIME_CHANGED_EVENT, {
      detail: runtimeSnapshot,
    }),
  );
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
  get nativeCoreConnected() {
    return runtimeSnapshot.nativeCoreConnected;
  },
  get coreVersion() {
    return runtimeSnapshot.coreVersion;
  },
  get sessionState() {
    return runtimeSnapshot.sessionState;
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
  onRuntimeChanged: (handler) => {
    const listener = (_event, payload) => handler(payload);
    ipcRenderer.on(DESKTOP_CORE_CHANNELS.RUNTIME_CHANGED, listener);
    return () => ipcRenderer.removeListener(DESKTOP_CORE_CHANNELS.RUNTIME_CHANGED, listener);
  },
});

contextBridge.exposeInMainWorld("desktopCore", {
  getRuntimeSnapshot: () => ipcRenderer.invoke(DESKTOP_CORE_CHANNELS.GET_RUNTIME_SNAPSHOT),
  request: (command) => ipcRenderer.invoke(DESKTOP_CORE_CHANNELS.REQUEST, buildCommandRequest(command)),
  startExamSession: (payload) =>
    ipcRenderer.invoke(
      DESKTOP_CORE_CHANNELS.REQUEST,
      buildCommandRequest({
        cmd: "start_exam_session",
        payload,
      }),
    ),
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

window.addEventListener("DOMContentLoaded", () => {
  applyRuntimeSnapshot(runtimeSnapshot);
  ipcRenderer.on(DESKTOP_CORE_CHANNELS.RUNTIME_CHANGED, (_event, snapshot) => {
    applyRuntimeSnapshot(snapshot);
  });
  ipcRenderer
    .invoke(DESKTOP_CORE_CHANNELS.GET_RUNTIME_SNAPSHOT)
    .then((snapshot) => {
      applyRuntimeSnapshot(snapshot);
    })
    .catch((error) => {
      console.error("[desktop] Failed to hydrate core runtime snapshot", error);
    });
  console.log("Electron preload ready");
});
