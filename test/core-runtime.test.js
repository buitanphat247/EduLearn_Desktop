const test = require("node:test");
const assert = require("node:assert/strict");

const { createDesktopCoreRuntime } = require("../src/core-runtime");
const {
  createDesktopRuntimeSnapshot,
  isSafeExamCommand,
  SESSION_STATES,
} = require("../src/contracts/safe-exam");

function createTransportHarness({
  runtimeTickDeferred = null,
  exitExamResponse = null,
  startExamResponse = null,
  startExamProcessPolicy = [],
  startExamRuntimeRiskLevel = "normal",
  notifyVisualKioskReadyResponse = null,
} = {}) {
  const requests = [];
  const requestOptions = [];
  const stopCalls = [];
  let callbacks = null;

  const transport = {
    async start() {
      callbacks?.onEvent?.({
        event: "RUST_CORE_READY",
        timestamp: 1_782_600_000_000,
        data: {
          coreVersion: "0.0.1",
          sessionState: SESSION_STATES.INIT,
        },
      });

      return {
        connected: true,
        binaryPath: "C:\\fake\\rust-core.exe",
      };
    },
    async request(request, options = {}) {
      requests.push(request);
      requestOptions.push({ cmd: request.cmd, options });

      switch (request.cmd) {
        case "ping":
          return {
            requestId: request.requestId ?? "ping",
            ok: true,
            data: {
              bridgeAliveAt: 1_782_600_000_010,
              nativeCoreConnected: true,
              pong: true,
              sessionState: SESSION_STATES.INIT,
              source: "rust-core",
            },
            error: null,
          };
        case "get_core_version":
          return {
            requestId: request.requestId ?? "version",
            ok: true,
            data: {
              coreVersion: "0.0.1",
              nativeCoreConnected: true,
            },
            error: null,
          };
        case "get_status":
          return {
            requestId: request.requestId ?? "status",
            ok: true,
            data: {
              coreVersion: "0.0.1",
              safeExamMode: false,
              sessionState: SESSION_STATES.INIT,
              lastCoreHeartbeat: 1_782_600_000_020,
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
              activeMonitorCount: 1,
              blackOverlayCount: 0,
              lastRuntimeEventAt: null,
            },
            error: null,
          };
        case "force_restore_desktop":
        case "request_emergency_restore":
          return {
            requestId: request.requestId ?? "restore",
            ok: true,
            data: {
              decision: {
                accepted: true,
                state: "accepted",
                reason: "Emergency restore request accepted.",
                correlationId: "correlation-1",
              },
              sessionState: SESSION_STATES.IDLE,
              emergencyRestore: {
                emergencyRestoreWidgetVisible: false,
                emergencyRestoreWidgetState: "completed",
                lastEmergencyRestoreRequestAt: 1_782_600_000_055,
                lastEmergencyRestoreResult: "completed",
                emergencyRestoreAttemptCount: 1,
                emergencyRestoreLastError: null,
                widgetId: "widget-1",
                correlationId: "correlation-1",
                requireHoldMs: 2000,
              },
              protectionStatus: {
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
                activeMonitorCount: 1,
                blackOverlayCount: 0,
                lastRuntimeEventAt: null,
              },
            },
            error: null,
          };
        case "exit_exam_session":
          if (exitExamResponse) {
            return exitExamResponse;
          }
          return {
            requestId: request.requestId ?? "exit",
            ok: true,
            data: {
              sessionState: SESSION_STATES.IDLE,
              protectionStatus: {
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
                activeMonitorCount: 1,
                blackOverlayCount: 0,
                lastRuntimeEventAt: null,
              },
            },
            error: null,
          };
        case "preflight_kill":
          return {
            requestId: request.requestId ?? "preflight-kill",
            ok: true,
            data: {
              allClear: true,
              killedCount: 1,
              remainingCount: 0,
              killedNames: ["OBS.exe"],
              remainingNames: [],
              retryCount: 0,
              attemptCount: 1,
              failures: [],
              actions: [],
              hardBlockedProcesses: [],
              terminateRequiredProcesses: [],
              continueWithAuditProcesses: [],
              isolateAndProtectProcesses: [],
              warnings: [],
              runtimeRiskLevel: "normal",
            },
            error: null,
          };
        case "get_protection_status":
          return {
            requestId: request.requestId ?? "protection-status",
            ok: true,
            data: {
              sessionState: SESSION_STATES.STARTING_EXAM_SESSION,
              activeSessionId: "session-1",
              desktopStateCaptured: true,
              protectionStatus: {
                examProtectionActive: false,
                protectionDryRun: false,
                kioskActive: false,
                overlayActive: false,
                taskbarHidden: false,
                keyboardHookActive: false,
                focusLockActive: false,
                captureProtectionActive: false,
                captureProtectionStatus: "pending",
                runtimeMonitorActive: false,
                activeMonitorCount: 1,
                blackOverlayCount: 0,
                lastRuntimeEventAt: null,
              },
              runtimeRiskLevel: "normal",
              runtimeEvents: [],
              emergencyRestore: {
                emergencyRestoreWidgetVisible: false,
                emergencyRestoreWidgetState: "hidden",
                lastEmergencyRestoreRequestAt: null,
                lastEmergencyRestoreResult: null,
                emergencyRestoreAttemptCount: 0,
                emergencyRestoreLastError: null,
                widgetId: null,
                correlationId: null,
                requireHoldMs: 2000,
              },
            },
            error: null,
          };
        case "load_policy":
          return {
            requestId: request.requestId ?? "load-policy",
            ok: true,
            data: {
              source: "signed",
              keyId: "primary",
              digestSha256: "abc123",
              policy: {
                policyVersion: "exam-2026-v1",
                examId: "exam-1",
              },
            },
            error: null,
          };
        case "get_policy_status":
          return {
            requestId: request.requestId ?? "policy-status",
            ok: true,
            data: {
              source: "signed",
              keyId: "primary",
              digestSha256: "abc123",
            },
            error: null,
          };
        case "run_runtime_monitor_tick":
          if (runtimeTickDeferred) {
            await runtimeTickDeferred.promise;
          }
          return {
            requestId: request.requestId ?? "runtime-monitor",
            ok: true,
            data: {
              sessionState: SESSION_STATES.EXAM_RUNNING,
              protectionStatus: {
                examProtectionActive: true,
                protectionDryRun: false,
                kioskActive: true,
                overlayActive: true,
                taskbarHidden: true,
                keyboardHookActive: true,
                focusLockActive: true,
                captureProtectionActive: false,
                captureProtectionStatus: "exclude-from-capture",
                runtimeMonitorActive: true,
                activeMonitorCount: 2,
                blackOverlayCount: 1,
                lastRuntimeEventAt: 1_782_600_000_050,
              },
              summary: {
                totalProcessCount: 120,
                monitorCount: 2,
                remoteSignalCount: 1,
                screenCaptureSignalCount: 1,
                vmSignalCount: 0,
              },
              processWatcher: {
                source: "Wmi",
                eventCount: 2,
                remediationCount: 1,
                ignoredCount: 1,
                maxDetectionLatencyMs: 125,
                ignoredReasons: ["process-not-prohibited-by-policy"],
              },
              processWatcherProducer: {
                selectedSource: "Polling",
                eventDriven: false,
                fallbackReason: "No native process event producer is available.",
                health: "healthy-fallback",
                producerState: "fallback",
                fallbackActive: true,
                heartbeatAtMs: 1_782_600_000_046,
                activeSinceMs: 1_782_600_000_000,
                failureCount: 3,
                recoveryAttemptCount: 1,
                retryCount: 1,
                queueDepth: 0,
                drainedEventCount: 2,
                droppedEventCount: 0,
                producerLatencyMs: 12,
                eventsLostCount: 0,
                buffersLostCount: 0,
                realtimeBuffersLostCount: 0,
                callbackLatencyMicros: 18,
                producerRestartCount: 1,
                parseErrorCount: 0,
                lastFailure: "ETW unavailable.",
                unavailableProducers: [{ source: "Etw", reason: "ETW unavailable." }],
              },
              runtimeStateEngine: {
                runtimeVersion: "10.8",
                runtimeState: "fallback",
                producerState: {
                  Polling: {
                    source: "Polling",
                    health: "healthy-fallback",
                    queueDepth: 0,
                    droppedEvents: 0,
                  },
                },
                queueState: {
                  capacity: 512,
                  depth: 0,
                  droppedEvents: 0,
                  backpressureActive: false,
                },
                healthState: "healthy",
                synchronizationState: {
                  duplicateEventCount: 1,
                  lateEventCount: 0,
                  outOfOrderEventCount: 0,
                  pidReuseCount: 0,
                  exitBeforeCreateCount: 0,
                  mergeCount: 2,
                },
                processIdentityCount: 2,
                activeProcessCount: 1,
                remediationStatus: "idle",
                reconciliationCount: 120,
                recoveryCount: 0,
                droppedEvents: 0,
              },
              runtimeTelemetry: {
                runtimeLatencyMs: 34,
                runtimeTickDurationMs: 34,
                watcherLatencyMs: 125,
                processClassificationTimeMs: 4,
                remediationTimeMs: 8,
                guardRestartCount: 1,
                watchdogRestartCount: 0,
                eventQueueLength: 3,
                runtimeHealth: "healthy",
              },
              runtimeEvents: [
                {
                  eventId: 1,
                  kind: "ProcessCreated",
                  severity: "info",
                  timestamp: 1_782_600_000_045,
                  detail: "obs64.exe pid 42 observed by process watcher.",
                  metadata: {
                    pid: "42",
                    name: "obs64.exe",
                  },
                },
              ],
              logLines: [
                {
                  timestamp: 1_782_600_000_040,
                  level: "warn",
                  code: "SCREEN_CAPTURE_SIGNAL",
                  message: "OBS.exe is still visible in the runtime scan.",
                },
              ],
            },
            error: null,
          };
        case "start_exam_session":
          if (startExamResponse) {
            return startExamResponse;
          }
          return {
            requestId: request.requestId ?? "start-session",
            ok: true,
            data: {
              startedAt: 1_782_600_000_030,
              sessionState: SESSION_STATES.STARTING_EXAM_SESSION,
              sessionContext: {
                sessionId: "session-1",
                examId: "exam-1",
                roomCode: null,
                startedAt: 1_782_600_000_030,
                dryRun: false,
              },
              desktopState: {
                capturedAt: 1_782_600_000_030,
                monitorCount: 1,
                taskbarVisible: true,
                startMenuVisible: false,
                foregroundWindowTitle: "EduLearn",
              },
              protectionStatus: {
                examProtectionActive: true,
                protectionDryRun: false,
                kioskActive: false,
                overlayActive: false,
                taskbarHidden: false,
                keyboardHookActive: false,
                focusLockActive: false,
                captureProtectionActive: false,
                captureProtectionStatus: "inactive",
                runtimeMonitorActive: false,
                activeMonitorCount: 1,
                blackOverlayCount: 0,
                lastRuntimeEventAt: null,
              },
              runtimeRiskLevel: startExamRuntimeRiskLevel,
              processPolicy: startExamProcessPolicy,
              logLines: [],
            },
            error: null,
          };
        case "enter_kiosk":
          return {
            requestId: request.requestId ?? "enter-kiosk",
            ok: true,
            data: {
              sessionState: SESSION_STATES.ENTERING_KIOSK,
              protectionStatus: {
                examProtectionActive: true,
                protectionDryRun: false,
                kioskActive: true,
                overlayActive: false,
                taskbarHidden: true,
                keyboardHookActive: true,
                focusLockActive: true,
                inputHookActive: true,
                mouseHookActive: true,
                focusHookActive: true,
                clipboardListenerActive: true,
                overlayHealActive: true,
                captureHealActive: true,
                captureProtectionActive: true,
                captureProtectionStatus: "electron-content-protection-active",
                electronContentProtectionActive: true,
                rustOverlayCaptureProtectionActive: false,
                captureProtectionBestEffort: true,
                runtimeMonitorActive: true,
                activeMonitorCount: 1,
                blackOverlayCount: 0,
                lastRuntimeEventAt: 1_782_600_000_040,
              },
              logLines: [],
            },
            error: null,
          };
        case "notify_visual_kiosk_ready":
          if (notifyVisualKioskReadyResponse) {
            return notifyVisualKioskReadyResponse;
          }
          return {
            requestId: request.requestId ?? "notify-visual-kiosk-ready",
            ok: true,
            data: {
              sessionState: SESSION_STATES.EXAM_RUNNING_CONFIRMED,
              protectionStatus: {
                examProtectionActive: true,
                protectionDryRun: false,
                kioskActive: true,
                overlayActive: false,
                taskbarHidden: true,
                keyboardHookActive: true,
                focusLockActive: true,
                inputHookActive: true,
                mouseHookActive: true,
                focusHookActive: true,
                clipboardListenerActive: true,
                overlayHealActive: true,
                captureHealActive: true,
                captureProtectionActive: true,
                captureProtectionStatus: "electron-content-protection-active",
                electronContentProtectionActive: true,
                rustOverlayCaptureProtectionActive: false,
                captureProtectionBestEffort: true,
                runtimeMonitorActive: true,
                activeMonitorCount: 1,
                blackOverlayCount: 0,
                lastRuntimeEventAt: 1_782_600_000_041,
              },
              logLines: [],
            },
            error: null,
          };
        default:
          throw new Error(`Unexpected command in test harness: ${request.cmd}`);
      }
    },
    async stop() {
      stopCalls.push("stop");
    },
    isConnected() {
      return true;
    },
  };

  return {
    createSidecarTransport(nextCallbacks) {
      callbacks = nextCallbacks;
      return transport;
    },
    requests,
    requestOptions,
    stopCalls,
  };
}

function createDeferred() {
  let resolve;
  const promise = new Promise((nextResolve) => {
    resolve = nextResolve;
  });
  return { promise, resolve };
}

test("safe exam contract accepts audit commands and normalizes audit health", () => {
  assert.equal(isSafeExamCommand("request_emergency_restore"), true);
  assert.equal(isSafeExamCommand("get_audit_status"), true);
  assert.equal(isSafeExamCommand("verify_audit_chain"), true);
  assert.equal(isSafeExamCommand("drain_audit_upload_batch"), true);
  assert.equal(isSafeExamCommand("ack_audit_upload_batch"), true);
  assert.equal(isSafeExamCommand("record_audit_upload_failure"), true);
  assert.equal(isSafeExamCommand("sign_audit_upload"), true);

  const snapshot = createDesktopRuntimeSnapshot({
    runtime: "electron",
    audit: {
      auditEnabled: true,
      auditHealth: "healthy",
      auditQueueDepth: 4,
      pendingUploads: 3,
      failedUploads: 1,
      lastSuccessfulUpload: 1_782_600_000_000,
      lastFailure: "server offline",
      hashChainStatus: "valid",
      syncLatencyMs: 42,
    },
    emergencyRestore: {
      emergencyRestoreWidgetVisible: true,
      emergencyRestoreWidgetState: "visible",
      lastEmergencyRestoreRequestAt: 1_782_600_000_000,
      lastEmergencyRestoreResult: "accepted",
      emergencyRestoreAttemptCount: 1,
      emergencyRestoreLastError: null,
      widgetId: "widget-1",
      correlationId: "correlation-1",
      requireHoldMs: 2000,
    },
  });

  assert.equal(snapshot.audit.auditEnabled, true);
  assert.equal(snapshot.audit.auditHealth, "healthy");
  assert.equal(snapshot.audit.pendingUploads, 3);
  assert.equal(snapshot.audit.hashChainStatus, "valid");
  assert.equal(snapshot.emergencyRestore.emergencyRestoreWidgetVisible, true);
  assert.equal(snapshot.emergencyRestore.emergencyRestoreWidgetState, "visible");
});

test("desktop core runtime hydrates its snapshot from the Rust handshake", async () => {
  const harness = createTransportHarness();
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
  });

  await runtime.start();
  const snapshot = runtime.getSnapshot();

  assert.equal(snapshot.nativeCoreConnected, true);
  assert.equal(snapshot.coreVersion, "0.0.1");
  assert.equal(snapshot.sessionState, SESSION_STATES.INIT);
  assert.equal(snapshot.platform, "win32");
  assert.equal(snapshot.safeExamMode, false);
});

test("desktop core runtime requests a forced restore before stopping an active protected session", async () => {
  const harness = createTransportHarness();
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
  });

  await runtime.start();
  runtime.updateSnapshot({
    nativeCoreConnected: true,
    sessionState: SESSION_STATES.EXAM_RUNNING,
    kioskActive: true,
    overlayActive: true,
    taskbarHidden: true,
    keyboardHookActive: true,
    runtimeRiskLevel: "elevated",
  });

  await runtime.stop();

  assert.equal(harness.requests.some((request) => request.cmd === "force_restore_desktop"), true);
  assert.deepEqual(harness.stopCalls, ["stop"]);
});

test("desktop core runtime restores local visual protection after an exit command", async () => {
  const harness = createTransportHarness();
  let restoreCalls = 0;
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
    protectionController: {
      hasActiveProtection() {
        return true;
      },
      async restoreExamProtection() {
        restoreCalls += 1;
        return {
          examProtectionActive: false,
          kioskActive: false,
          overlayActive: false,
          taskbarHidden: false,
          keyboardHookActive: false,
          focusLockActive: false,
          blackOverlayCount: 0,
        };
      },
      getVisualSnapshotPatch() {
        return {
          examProtectionActive: true,
          overlayActive: true,
          kioskActive: true,
        };
      },
    },
  });

  await runtime.start();
  runtime.updateSnapshot({
    sessionState: SESSION_STATES.EXAM_RUNNING,
    audioLockActive: true,
    examProtectionActive: true,
    kioskActive: true,
    overlayActive: true,
    taskbarHidden: true,
    keyboardHookActive: true,
    runtimeRiskLevel: "elevated",
  }, {
    allowAudioLockMutation: true,
  });

  const response = await runtime.handleCommand({
    cmd: "exit_exam_session",
    payload: {
      sessionId: "ses-1",
      reason: "User exited from the room shell.",
    },
  });

  assert.equal(response.ok, true);
  assert.equal(restoreCalls, 1);
  assert.equal(runtime.getSnapshot().sessionState, SESSION_STATES.EXITED);
  assert.equal(runtime.getSnapshot().audioLockActive, false);
  assert.equal(runtime.getSnapshot().overlayActive, false);
  assert.equal(runtime.getSnapshot().keyboardHookActive, false);
  assert.equal(runtime.getSnapshot().runtimeRiskLevel, "normal");
});

test("desktop core runtime treats emergency restore as a trusted restore command", async () => {
  const harness = createTransportHarness();
  let restoreCalls = 0;
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
    protectionController: {
      hasActiveProtection() {
        return true;
      },
      async restoreExamProtection() {
        restoreCalls += 1;
        return {
          examProtectionActive: false,
          kioskActive: false,
          overlayActive: false,
          taskbarHidden: false,
          keyboardHookActive: false,
          focusLockActive: false,
          blackOverlayCount: 0,
        };
      },
      getVisualSnapshotPatch() {
        return {
          examProtectionActive: true,
          kioskActive: true,
        };
      },
    },
  });

  await runtime.start();
  runtime.updateSnapshot({
    sessionState: SESSION_STATES.EXAM_RUNNING,
    examProtectionActive: true,
    kioskActive: true,
    keyboardHookActive: true,
  });

  const response = await runtime.handleCommand({
    cmd: "request_emergency_restore",
    payload: {
      sessionId: "session-1",
      examId: "exam-1",
      runtimeId: "runtime-1",
      reason: "user_emergency_widget",
      widgetId: "widget-1",
      requestedAt: 1_782_600_000_055,
      desktopIsolationActive: false,
      kioskActive: true,
      correlationId: "correlation-1",
      nonce: "nonce-1",
    },
  });

  assert.equal(response.ok, true);
  assert.equal(restoreCalls, 1);
  assert.equal(runtime.getSnapshot().sessionState, SESSION_STATES.EXITED);
  assert.equal(runtime.getSnapshot().emergencyRestore.emergencyRestoreWidgetState, "completed");
});

test("desktop core runtime hydrates the snapshot from a runtime monitor tick", async () => {
  const harness = createTransportHarness();
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
  });

  await runtime.start();

  const response = await runtime.handleCommand({
    cmd: "run_runtime_monitor_tick",
    payload: {
      windowHandleHex: "0x123",
    },
  });

  assert.equal(response.ok, true);
  assert.equal(runtime.getSnapshot().runtimeMonitorActive, true);
  assert.equal(runtime.getSnapshot().captureProtectionStatus, "exclude-from-capture");
  assert.equal(runtime.getSnapshot().activeMonitorCount, 2);
  assert.equal(runtime.getSnapshot().blackOverlayCount, 1);
  assert.equal(runtime.getSnapshot().processWatcher.source, "Wmi");
  assert.equal(runtime.getSnapshot().processWatcher.maxDetectionLatencyMs, 125);
  assert.equal(runtime.getSnapshot().processWatcherProducer.selectedSource, "Polling");
  assert.equal(runtime.getSnapshot().processWatcherProducer.producerState, "fallback");
  assert.equal(runtime.getSnapshot().processWatcherProducer.retryCount, 1);
  assert.equal(runtime.getSnapshot().processWatcherProducer.callbackLatencyMicros, 18);
  assert.equal(runtime.getSnapshot().processWatcherProducer.producerRestartCount, 1);
  assert.equal(runtime.getSnapshot().processWatcherProducer.unavailableProducers.length, 1);
  assert.equal(runtime.getSnapshot().runtimeStateEngine.runtimeVersion, "10.8");
  assert.equal(runtime.getSnapshot().runtimeStateEngine.processIdentityCount, 2);
  assert.equal(
    runtime.getSnapshot().runtimeStateEngine.synchronizationState.duplicateEventCount,
    1,
  );
  assert.equal(runtime.getSnapshot().runtimeTelemetry.runtimeHealth, "healthy");
  assert.equal(runtime.getSnapshot().runtimeEvents[0].kind, "ProcessCreated");
  const runtimeRequest = harness.requests.find(
    (request) => request.cmd === "run_runtime_monitor_tick",
  );
  assert.equal(runtimeRequest.payload.windowHandleHex, "0x123");
});

test("desktop core runtime forwards preflight process remediation", async () => {
  const harness = createTransportHarness();
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
  });

  await runtime.start();
  const response = await runtime.handleCommand({
    cmd: "preflight_kill",
    payload: {},
  });

  assert.equal(response.ok, true);
  assert.equal(response.data.allClear, true);
  assert.deepEqual(response.data.killedNames, ["OBS.exe"]);
  assert.equal(
    harness.requests.some((request) => request.cmd === "preflight_kill"),
    true,
  );
});

test("desktop core runtime forwards signed policy load without rewriting its envelope", async () => {
  const harness = createTransportHarness();
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
  });
  const envelope = {
    algorithm: "Ed25519",
    keyId: "primary",
    policy: {
      policyVersion: "exam-2026-v1",
      examId: "exam-1",
    },
    signature: "signed-value",
  };

  await runtime.start();
  const response = await runtime.handleCommand({
    cmd: "load_policy",
    payload: {
      examId: "exam-1",
      envelope,
    },
  });

  assert.equal(response.ok, true);
  const request = harness.requests.find((entry) => entry.cmd === "load_policy");
  assert.deepEqual(request.payload.envelope, envelope);
});

test("desktop core runtime gives native enter_kiosk a long timeout", async () => {
  const harness = createTransportHarness();
  let visualRestored = false;
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
    protectionController: {
      getMainWindowHandleHex() {
        return "0x1234";
      },
      getVisualSnapshotPatch() {
        return {
          electronContentProtectionActive: true,
          captureProtectionBestEffort: true,
          kioskActive: true,
          overlayActive: false,
          activeMonitorCount: 1,
          blackOverlayCount: 0,
        };
      },
      async enterExamProtection() {
        return {
          examProtectionActive: true,
          kioskActive: true,
          electronContentProtectionActive: true,
          captureProtectionBestEffort: true,
        };
      },
      async enterInteractionProtection() {
        return {
          keyboardHookActive: true,
          focusLockActive: true,
          examProtectionActive: true,
          kioskActive: true,
        };
      },
      async restoreExamProtection() {
        visualRestored = true;
        return {
          examProtectionActive: false,
          kioskActive: false,
        };
      },
      hasActiveProtection() {
        return false;
      },
    },
  });

  await runtime.start();
  const response = await runtime.handleCommand({
    cmd: "start_exam_session",
    payload: {
      sessionId: "session-1",
      examId: "exam-1",
      dryRun: false,
    },
  });

  assert.equal(response.ok, true);
  assert.equal(visualRestored, false);
  assert.equal(runtime.getSnapshot().audioLockActive, true);
  assert.equal(
    [
      SESSION_STATES.EXAM_RUNNING_CONFIRMED,
      SESSION_STATES.EXAM_RUNNING,
    ].includes(runtime.getSnapshot().sessionState),
    true,
  );
  assert.equal(runtime.getSnapshot().kioskHandoffCompleted, true);
  assert.equal(response.data.sessionState, SESSION_STATES.EXAM_RUNNING_CONFIRMED);
  assert.equal(response.data.audioLockActive, true);
  assert.equal(response.data.kioskHandoffCompleted, true);
  const enterKiosk = harness.requestOptions.find((entry) => entry.cmd === "enter_kiosk");
  assert.equal(enterKiosk.options.timeoutMs, 30_000);
});

test("desktop core runtime accepts start when Rust allows continue-and-audit processes", async () => {
  const allowedProcess = {
    pid: 42,
    name: "remoting_host.exe",
    executablePath: null,
    creationTimeMs: 1,
    category: "remote-control",
    action: "continueAndAudit",
    severity: "high",
    allowExamStart: true,
    attemptTerminate: false,
    auditRequired: true,
  };
  const harness = createTransportHarness({
    startExamProcessPolicy: [allowedProcess],
    startExamRuntimeRiskLevel: "elevated",
  });
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
  });

  await runtime.start();
  const response = await runtime.handleCommand({
    cmd: "start_exam_session",
    payload: { sessionId: "session-1", examId: "exam-1", dryRun: false },
  });

  assert.equal(response.ok, true);
  assert.equal(response.data.runtimeRiskLevel, "elevated");
  assert.equal(response.data.processPolicy[0].action, "continueAndAudit");
});

test("desktop core runtime keeps ENTERING_KIOSK blocked when handoff confirmation is missing", async () => {
  const harness = createTransportHarness({
    notifyVisualKioskReadyResponse: {
      requestId: "notify-visual-kiosk-ready",
      ok: false,
      data: null,
      error: {
        code: "PROTECTION_FAILURE",
        message: "Visual kiosk handoff timed out.",
      },
    },
  });
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
    protectionController: {
      getMainWindowHandleHex() {
        return "0x1234";
      },
      getVisualSnapshotPatch() {
        return {
          electronContentProtectionActive: true,
          captureProtectionBestEffort: true,
        };
      },
      async enterExamProtection() {
        return {
          examProtectionActive: true,
          kioskActive: true,
          electronContentProtectionActive: true,
        };
      },
      async enterInteractionProtection() {
        return {
          keyboardHookActive: true,
          focusLockActive: true,
          examProtectionActive: true,
          kioskActive: true,
        };
      },
      async restoreExamProtection() {
        return {
          examProtectionActive: false,
          kioskActive: false,
        };
      },
      hasActiveProtection() {
        return true;
      },
    },
  });

  await runtime.start();
  const response = await runtime.handleCommand({
    cmd: "start_exam_session",
    payload: { sessionId: "session-1", examId: "exam-1", dryRun: false },
  });

  assert.equal(response.ok, true);
  assert.equal(runtime.getSnapshot().sessionState, SESSION_STATES.ENTERING_KIOSK);
  assert.equal(runtime.getSnapshot().audioLockActive, true);
  assert.equal(runtime.getSnapshot().kioskHandoffCompleted, false);
  assert.equal(response.data.sessionState, SESSION_STATES.ENTERING_KIOSK);
  assert.equal(response.data.audioLockActive, true);
  assert.equal(response.data.kioskHandoffCompleted, false);
});

test("desktop core runtime auto-confirms DEMO_STATIC without Rust final ACK", async () => {
  const traceEvents = [];
  const harness = createTransportHarness({
    notifyVisualKioskReadyResponse: {
      requestId: "notify-visual-kiosk-ready",
      ok: false,
      data: null,
      error: {
        code: "PROTECTION_FAILURE",
        message: "This response should not be used in DEMO_STATIC.",
      },
    },
  });
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
    examGuardTracer: {
      recordIpc(event) {
        traceEvents.push({ kind: "ipc", ...event });
      },
      recordLoop(event) {
        traceEvents.push({ kind: "loop", ...event });
      },
      recordStateTransition(event) {
        traceEvents.push({ kind: "state", ...event });
      },
    },
    protectionController: {
      getMainWindowHandleHex() {
        return "0x1234";
      },
      getVisualSnapshotPatch() {
        return {
          electronContentProtectionActive: true,
          captureProtectionBestEffort: true,
        };
      },
      async enterExamProtection() {
        return {
          examProtectionActive: true,
          kioskActive: true,
          electronContentProtectionActive: true,
        };
      },
      async enterInteractionProtection() {
        return {
          keyboardHookActive: true,
          focusLockActive: true,
          examProtectionActive: true,
          kioskActive: true,
        };
      },
      async restoreExamProtection() {
        return {
          examProtectionActive: false,
          kioskActive: false,
        };
      },
      hasActiveProtection() {
        return true;
      },
    },
  });

  await runtime.start();
  const response = await runtime.handleCommand({
    cmd: "start_exam_session",
    payload: {
      sessionId: "session-1",
      examId: "exam-1",
      dryRun: false,
      examMode: "DEMO_STATIC",
    },
  });

  assert.equal(response.ok, true);
  assert.equal(runtime.getSnapshot().examMode, "DEMO_STATIC");
  assert.equal(runtime.getSnapshot().sessionState, SESSION_STATES.EXAM_RUNNING_CONFIRMED);
  assert.equal(runtime.getSnapshot().audioLockActive, true);
  assert.equal(runtime.getSnapshot().kioskHandoffCompleted, true);
  assert.equal(response.data.sessionState, SESSION_STATES.EXAM_RUNNING_CONFIRMED);
  assert.equal(response.data.audioLockActive, true);
  assert.equal(response.data.kioskHandoffCompleted, true);
  assert.equal(
    harness.requests.some((request) => request.cmd === "notify_visual_kiosk_ready"),
    false,
  );
  assert.equal(
    harness.requests.find((request) => request.cmd === "start_exam_session").payload.examMode,
    undefined,
  );
  assert.equal(
    traceEvents.some(
      (event) =>
        event.command === "EXAM_RUNNING_CONFIRMED emit" &&
        event.state === SESSION_STATES.EXAM_RUNNING_CONFIRMED,
    ),
    true,
  );

  const requestsBeforeStatus = harness.requests.length;
  const statusResponse = await runtime.handleCommand({
    cmd: "get_protection_status",
    payload: {},
  });

  assert.equal(statusResponse.ok, true);
  assert.equal(statusResponse.data.mocked, true);
  assert.equal(statusResponse.data.sessionState, SESSION_STATES.EXAM_RUNNING_CONFIRMED);
  assert.equal(statusResponse.data.audioLockActive, true);
  assert.equal(statusResponse.data.kioskHandoffCompleted, true);
  assert.equal(harness.requests.length, requestsBeforeStatus);
});

test("desktop core runtime blocks non-explicit force restore while exam is active", async () => {
  const harness = createTransportHarness();
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
  });

  await runtime.start();
  runtime.updateSnapshot({
    sessionState: SESSION_STATES.EXAM_RUNNING_CONFIRMED,
    safeExamMode: true,
    examProtectionActive: true,
    kioskActive: true,
    keyboardHookActive: true,
  });

  const requestsBeforeRestore = harness.requests.length;
  const response = await runtime.handleCommand({
    cmd: "force_restore_desktop",
    payload: {},
  });

  assert.equal(response.ok, true);
  assert.equal(response.data.lockedNoop, true);
  assert.equal(runtime.getSnapshot().sessionState, SESSION_STATES.EXAM_RUNNING_CONFIRMED);
  assert.equal(runtime.getSnapshot().examProtectionActive, true);
  assert.equal(runtime.getSnapshot().kioskActive, true);
  assert.equal(harness.requests.length, requestsBeforeRestore);
});

test("desktop core runtime state lock blocks snapshot rollback after confirmation", async () => {
  const harness = createTransportHarness();
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
  });

  await runtime.start();
  runtime.updateSnapshot({
    sessionState: SESSION_STATES.EXAM_RUNNING_CONFIRMED,
    audioLockActive: true,
    safeExamMode: true,
    examProtectionActive: true,
    kioskActive: true,
    keyboardHookActive: true,
  }, {
    allowAudioLockMutation: true,
  });

  runtime.updateSnapshot({
    sessionState: SESSION_STATES.IDLE,
    audioLockActive: false,
    safeExamMode: false,
    examProtectionActive: false,
    kioskActive: false,
    keyboardHookActive: false,
  });

  assert.equal(runtime.getSnapshot().sessionState, SESSION_STATES.EXAM_RUNNING_CONFIRMED);
  assert.equal(runtime.getSnapshot().audioLockActive, true);
  assert.equal(runtime.getSnapshot().safeExamMode, true);
  assert.equal(runtime.getSnapshot().examProtectionActive, true);
  assert.equal(runtime.getSnapshot().kioskActive, true);
  assert.equal(runtime.getSnapshot().keyboardHookActive, true);
});

test("desktop core runtime canonicalizes legacy running state and broadcasts a cloneable snapshot", async () => {
  const harness = createTransportHarness();
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
  });
  let broadcastSnapshot = null;
  const unsubscribe = runtime.onRuntimeChanged((snapshot) => {
    broadcastSnapshot = snapshot;
  });

  await runtime.start();
  runtime.updateSnapshot({
    sessionState: SESSION_STATES.EXAM_RUNNING,
    kioskHandoffCompleted: true,
  });

  assert.equal(
    runtime.getSnapshot().sessionState,
    SESSION_STATES.EXAM_RUNNING_CONFIRMED,
  );
  assert.equal(
    broadcastSnapshot.sessionState,
    SESSION_STATES.EXAM_RUNNING_CONFIRMED,
  );
  assert.doesNotThrow(() => structuredClone(broadcastSnapshot));
  unsubscribe();
});

test("desktop core runtime keeps room snapshot stable while exit confirmation modal is open", async () => {
  const harness = createTransportHarness();
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
  });

  await runtime.start();
  runtime.updateSnapshot({
    sessionState: SESSION_STATES.EXAM_RUNNING,
    audioLockActive: true,
    safeExamMode: true,
    examProtectionActive: true,
    kioskActive: true,
  }, {
    allowAudioLockMutation: true,
  });

  const beginResponse = await runtime.handleCommand({
    cmd: "begin_exam_exit_confirmation",
    payload: { reason: "test_modal_open" },
  });

  assert.equal(beginResponse.ok, true);
  assert.equal(beginResponse.data.exitInProgress, false);
  assert.equal(beginResponse.data.stateTransitionLock, false);
  assert.equal(beginResponse.data.uiInteractionLocked, false);
  assert.equal(
    runtime.getSnapshot().sessionState,
    SESSION_STATES.EXAM_RUNNING_CONFIRMED,
  );
  assert.equal(runtime.getSnapshot().exitInProgress, false);
  assert.equal(runtime.getSnapshot().stateTransitionLock, false);
  assert.equal(runtime.getSnapshot().uiInteractionLocked, false);
  assert.equal(runtime.getSnapshot().stateGovernorLockMode, null);
  assert.equal(runtime.getAudioState(), "MUTE");

  runtime.updateSnapshot({
    sessionState: SESSION_STATES.IDLE,
    safeExamMode: false,
    examProtectionActive: false,
    kioskActive: false,
  });

  assert.equal(
    runtime.getSnapshot().sessionState,
    SESSION_STATES.EXAM_RUNNING_CONFIRMED,
  );
  assert.equal(runtime.getSnapshot().examProtectionActive, true);

  const cancelResponse = await runtime.handleCommand({
    cmd: "cancel_exam_exit_confirmation",
    payload: { reason: "test_modal_cancel" },
  });

  assert.equal(cancelResponse.ok, true);
  assert.equal(
    runtime.getSnapshot().sessionState,
    SESSION_STATES.EXAM_RUNNING_CONFIRMED,
  );
  assert.equal(runtime.getSnapshot().exitInProgress, false);
  assert.equal(runtime.getSnapshot().stateTransitionLock, false);
  assert.equal(runtime.getSnapshot().uiInteractionLocked, false);
  assert.equal(runtime.getSnapshot().audioLockActive, true);
  assert.equal(runtime.getSnapshot().stateGovernorLockMode, null);
});

test("desktop core runtime governor exits through requested exiting and exited without IDLE rollback", async () => {
  const harness = createTransportHarness();
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
  });

  await runtime.start();
  runtime.updateSnapshot({
    sessionState: SESSION_STATES.EXAM_RUNNING,
    audioLockActive: true,
    safeExamMode: true,
    examProtectionActive: true,
    kioskActive: true,
    keyboardHookActive: true,
  }, {
    allowAudioLockMutation: true,
  });

  await runtime.handleCommand({
    cmd: "begin_exam_exit_confirmation",
    payload: { reason: "test_modal_open" },
  });

  const response = await runtime.handleCommand({
    cmd: "exit_exam_session",
    payload: {
      sessionId: "session-1",
      reason: "user_exit",
    },
  });

  assert.equal(response.ok, true);
  assert.equal(runtime.getSnapshot().sessionState, SESSION_STATES.EXITED);
  assert.equal(runtime.getSnapshot().exitInProgress, false);
  assert.equal(runtime.getSnapshot().stateTransitionLock, false);
  assert.equal(runtime.getSnapshot().uiInteractionLocked, false);
  assert.equal(runtime.getSnapshot().audioLockActive, false);
  assert.equal(runtime.getSnapshot().stateGovernorLockMode, null);
  assert.equal(runtime.getAudioState(), "RESTORE");
  assert.equal(response.data.sessionState, SESSION_STATES.EXITED);
  assert.equal(response.data.audioLockActive, false);

  const exitRequestsBeforeDuplicate = harness.requests.filter(
    (request) => request.cmd === "force_restore_desktop",
  ).length;
  const duplicateResponse = await runtime.handleCommand({
    cmd: "force_restore_desktop",
    payload: {
      reason: "user_exit",
      explicitExit: true,
      userInitiated: true,
    },
  });
  const exitRequestsAfterDuplicate = harness.requests.filter(
    (request) => request.cmd === "force_restore_desktop",
  ).length;

  assert.equal(duplicateResponse.ok, true);
  assert.equal(duplicateResponse.data.idempotentNoop, true);
  assert.equal(runtime.getSnapshot().sessionState, SESSION_STATES.EXITED);
  assert.equal(exitRequestsAfterDuplicate, exitRequestsBeforeDuplicate);
});

test("desktop core runtime force-cleans exit when Rust does not acknowledge", async () => {
  const harness = createTransportHarness({
    exitExamResponse: {
      requestId: "exit-timeout",
      ok: false,
      data: null,
      error: {
        code: "IPC_FAILURE",
        message: "Rust sidecar timed out while exiting.",
      },
    },
  });
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
  });

  await runtime.start();
  runtime.updateSnapshot({
    sessionState: SESSION_STATES.EXAM_RUNNING,
    audioLockActive: true,
    safeExamMode: true,
    examProtectionActive: true,
    kioskActive: true,
  }, {
    allowAudioLockMutation: true,
  });

  await runtime.handleCommand({
    cmd: "begin_exam_exit_confirmation",
    payload: { reason: "test_modal_open" },
  });

  const response = await runtime.handleCommand({
    cmd: "exit_exam_session",
    payload: {
      sessionId: "session-1",
      reason: "user_exit_timeout",
    },
  });

  assert.equal(response.ok, true);
  assert.equal(response.data.fallback, true);
  assert.equal(response.data.rustAck, false);
  assert.equal(runtime.getSnapshot().sessionState, SESSION_STATES.EXITED);
  assert.equal(runtime.getSnapshot().exitInProgress, false);
  assert.equal(runtime.getSnapshot().stateTransitionLock, false);
  assert.equal(runtime.getSnapshot().uiInteractionLocked, false);
  assert.equal(runtime.getSnapshot().audioLockActive, false);
  assert.equal(
    harness.requestOptions.find((entry) => entry.cmd === "exit_exam_session")
      ?.options.timeoutMs,
    5_000,
  );
});

test("desktop core runtime preserves hard-block start failure from Rust", async () => {
  const harness = createTransportHarness({
    startExamResponse: {
      requestId: "start-hard-block",
      ok: false,
      data: null,
      error: {
        code: "PROTECTION_FAILURE",
        message: "Protected exam session is blocked by windbg.exe.",
      },
    },
  });
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
  });

  await runtime.start();
  const response = await runtime.handleCommand({
    cmd: "start_exam_session",
    payload: { sessionId: "session-1", examId: "exam-1", dryRun: false },
  });

  assert.equal(response.ok, false);
  assert.equal(response.error.code, "PROTECTION_FAILURE");
  assert.equal(runtime.getSnapshot().kioskActive, false);
});

test("desktop core runtime discards a late monitor tick after exam restore", async () => {
  const runtimeTickDeferred = createDeferred();
  const harness = createTransportHarness({ runtimeTickDeferred });
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
    protectionController: {
      getMainWindowHandleHex() {
        return "0x1234";
      },
      getVisualSnapshotPatch() {
        return {
          electronContentProtectionActive: true,
          captureProtectionBestEffort: true,
        };
      },
      async enterExamProtection() {
        return {
          examProtectionActive: true,
          kioskActive: true,
          electronContentProtectionActive: true,
        };
      },
      async enterInteractionProtection() {
        return {
          keyboardHookActive: true,
          focusLockActive: true,
          examProtectionActive: true,
          kioskActive: true,
        };
      },
      async restoreExamProtection() {
        return {
          examProtectionActive: false,
          kioskActive: false,
          overlayActive: false,
          taskbarHidden: false,
          keyboardHookActive: false,
          focusLockActive: false,
        };
      },
      hasActiveProtection() {
        return true;
      },
    },
  });

  await runtime.start();
  const startResponse = await runtime.handleCommand({
    cmd: "start_exam_session",
    payload: {
      sessionId: "session-1",
      examId: "exam-1",
      dryRun: false,
    },
  });
  assert.equal(startResponse.ok, true);

  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(
    harness.requests.some((request) => request.cmd === "run_runtime_monitor_tick"),
    true,
  );

  const exitResponse = await runtime.handleCommand({
    cmd: "exit_exam_session",
    payload: {
      sessionId: "session-1",
      reason: "Regression test restore.",
    },
  });
  assert.equal(exitResponse.ok, true);
  assert.equal(runtime.getSnapshot().sessionState, SESSION_STATES.EXITED);

  runtimeTickDeferred.resolve();
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(runtime.getSnapshot().sessionState, SESSION_STATES.EXITED);
  assert.equal(runtime.getSnapshot().examProtectionActive, false);
  assert.equal(runtime.getSnapshot().kioskActive, false);
});

test("desktop core runtime returns SAFE_NOOP for protection status while idle", async () => {
  const harness = createTransportHarness();
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
  });

  await runtime.start();
  runtime.updateSnapshot({
    sessionState: SESSION_STATES.IDLE,
    examProtectionActive: true,
    kioskActive: true,
    runtimeMonitorActive: true,
  });

  const requestsBeforeStatus = harness.requests.length;
  const response = await runtime.handleCommand({
    cmd: "get_protection_status",
    payload: {},
  });

  assert.equal(response.ok, true);
  assert.equal(response.data.safeNoop, true);
  assert.equal(response.data.skipReason, "protectionSkippedBecauseIdle");
  assert.equal(response.data.sessionState, SESSION_STATES.IDLE);
  assert.equal(harness.requests.length, requestsBeforeStatus);

  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(
    harness.requests.some((request) => request.cmd === "run_runtime_monitor_tick"),
    false,
  );
});

test("desktop core runtime blocks protection polling before atomic confirmation", async () => {
  const harness = createTransportHarness();
  const runtime = createDesktopCoreRuntime({
    platform: "win32",
    createSidecarTransport: harness.createSidecarTransport,
  });

  await runtime.start();
  runtime.updateSnapshot({
    sessionState: SESSION_STATES.STARTING_EXAM_SESSION,
  });

  const firstResponse = await runtime.handleCommand({
    cmd: "get_protection_status",
    payload: {},
  });
  const protectionStatusRequestsAfterFirstCall = harness.requests.filter(
    (request) => request.cmd === "get_protection_status",
  ).length;

  const secondResponse = await runtime.handleCommand({
    cmd: "get_protection_status",
    payload: {},
  });
  const protectionStatusRequestsAfterSecondCall = harness.requests.filter(
    (request) => request.cmd === "get_protection_status",
  ).length;

  assert.equal(firstResponse.ok, true);
  assert.equal(firstResponse.data.debounced, undefined);
  assert.equal(
    firstResponse.data.skipReason,
    "protectionSkippedBecauseSessionNotReady",
  );
  assert.equal(protectionStatusRequestsAfterFirstCall, 0);
  assert.equal(secondResponse.ok, true);
  assert.equal(
    secondResponse.data.skipReason,
    "protectionSkippedBecauseSessionNotReady",
  );
  assert.equal(protectionStatusRequestsAfterSecondCall, 0);
});
