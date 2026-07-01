const test = require("node:test");
const assert = require("node:assert/strict");

const { createDesktopCoreRuntime } = require("../src/core-runtime");
const { SESSION_STATES } = require("../src/contracts/safe-exam");

function createTransportHarness({ runtimeTickDeferred = null } = {}) {
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
          return {
            requestId: request.requestId ?? "restore",
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
        case "exit_exam_session":
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
              logLines: [],
            },
            error: null,
          };
        case "enter_kiosk":
          return {
            requestId: request.requestId ?? "enter-kiosk",
            ok: true,
            data: {
              sessionState: SESSION_STATES.EXAM_RUNNING,
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
    examProtectionActive: true,
    kioskActive: true,
    overlayActive: true,
    taskbarHidden: true,
    keyboardHookActive: true,
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
  assert.equal(runtime.getSnapshot().sessionState, SESSION_STATES.IDLE);
  assert.equal(runtime.getSnapshot().overlayActive, false);
  assert.equal(runtime.getSnapshot().keyboardHookActive, false);
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
  const enterKiosk = harness.requestOptions.find((entry) => entry.cmd === "enter_kiosk");
  assert.equal(enterKiosk.options.timeoutMs, 30_000);
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
  assert.equal(runtime.getSnapshot().sessionState, SESSION_STATES.IDLE);

  runtimeTickDeferred.resolve();
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(runtime.getSnapshot().sessionState, SESSION_STATES.IDLE);
  assert.equal(runtime.getSnapshot().examProtectionActive, false);
  assert.equal(runtime.getSnapshot().kioskActive, false);
});
