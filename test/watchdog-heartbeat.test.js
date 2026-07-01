const test = require("node:test");
const assert = require("node:assert/strict");

const { createWatchdogHeartbeat } = require("../src/watchdog-heartbeat");

function createMemoryFs() {
  const files = new Map();
  return {
    files,
    mkdirSync() {},
    writeFileSync(filePath, value) {
      files.set(filePath, value);
    },
    readFileSync(filePath) {
      return files.get(filePath) ?? "";
    },
    renameSync(source, target) {
      files.set(target, files.get(source));
      files.delete(source);
    },
    rmSync(filePath) {
      files.delete(filePath);
    },
  };
}

test("watchdog heartbeat writes an atomic authenticated runtime record", () => {
  const fsImpl = createMemoryFs();
  const heartbeatPath = "C:\\temp\\heartbeat.json";
  fsImpl.files.set("C:\\app\\electron.exe", "electron-binary");
  const heartbeat = createWatchdogHeartbeat({
    heartbeatPath,
    token: "a".repeat(64),
    challenge: "b".repeat(64),
    getRuntimeSnapshot: () => ({
      nativeCoreConnected: true,
      sessionState: "EXAM_RUNNING",
      activeSessionId: "session-1",
    }),
    now: () => 123_456,
    processId: 42,
    processPath: "C:\\app\\electron.exe",
    processStartedAtMs: 120_000,
    fsImpl,
  });

  assert.equal(heartbeat.write(), true);
  assert.equal(fsImpl.files.has(heartbeatPath), true);
  assert.equal(fsImpl.files.has(`${heartbeatPath}.42.tmp`), false);
  assert.equal(fsImpl.files.get("C:\\app\\electron.exe"), "electron-binary");
  const record = JSON.parse(fsImpl.files.get(heartbeatPath));
  assert.equal(record.token, undefined);
  assert.equal(record.version, 2);
  assert.equal(record.sequence, 1);
  assert.equal(record.timestampMs, 123_456);
  assert.equal(record.electronPid, 42);
  assert.equal(record.processPath, "C:\\app\\electron.exe");
  assert.equal(record.processSha256, "600c1466a884d7859023089eec1611879b9621e875903054aa49138f3a4a4d06");
  assert.equal(record.processStartedAtMs, 120_000);
  assert.equal(record.nativeCoreConnected, true);
  assert.equal(record.sessionState, "EXAM_RUNNING");
  assert.equal(record.sessionId, "session-1");
  assert.match(record.challengeResponse, /^[a-f0-9]{64}$/);
});

test("watchdog heartbeat increments sequence and signs each record", () => {
  const fsImpl = createMemoryFs();
  const heartbeatPath = "C:\\temp\\heartbeat.json";
  fsImpl.files.set("C:\\app\\electron.exe", "electron-binary");
  let now = 123_456;
  const heartbeat = createWatchdogHeartbeat({
    heartbeatPath,
    token: "a".repeat(64),
    challenge: "b".repeat(64),
    getRuntimeSnapshot: () => ({
      nativeCoreConnected: true,
      sessionState: "EXAM_RUNNING",
    }),
    now: () => now,
    processId: 42,
    processPath: "C:\\app\\electron.exe",
    processStartedAtMs: 120_000,
    fsImpl,
  });

  assert.equal(heartbeat.write(), true);
  const first = JSON.parse(fsImpl.files.get(heartbeatPath));
  now += 1_000;
  assert.equal(heartbeat.write(), true);
  const second = JSON.parse(fsImpl.files.get(heartbeatPath));

  assert.equal(first.sequence, 1);
  assert.equal(second.sequence, 2);
  assert.notEqual(first.challengeResponse, second.challengeResponse);
});

test("watchdog heartbeat stays disabled without a sufficiently strong challenge", () => {
  const fsImpl = createMemoryFs();
  const heartbeat = createWatchdogHeartbeat({
    heartbeatPath: "C:\\temp\\heartbeat.json",
    token: "a".repeat(64),
    challenge: "short",
    fsImpl,
  });

  assert.equal(heartbeat.isConfigured(), false);
  assert.equal(heartbeat.start(), false);
  assert.equal(heartbeat.write(), false);
  assert.equal(fsImpl.files.size, 0);
});

test("watchdog heartbeat stays disabled without a sufficiently strong token", () => {
  const fsImpl = createMemoryFs();
  const heartbeat = createWatchdogHeartbeat({
    heartbeatPath: "C:\\temp\\heartbeat.json",
    token: "short",
    challenge: "b".repeat(64),
    fsImpl,
  });

  assert.equal(heartbeat.isConfigured(), false);
  assert.equal(heartbeat.start(), false);
  assert.equal(heartbeat.write(), false);
  assert.equal(fsImpl.files.size, 0);
});
