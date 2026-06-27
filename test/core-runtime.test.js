const test = require("node:test");
const assert = require("node:assert/strict");

const { createDesktopCoreRuntime } = require("../src/core-runtime");
const { SESSION_STATES } = require("../../shared/contracts/safe-exam");

function createTransportHarness() {
  const requests = [];
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
    async request(request) {
      requests.push(request);

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
    stopCalls,
  };
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
