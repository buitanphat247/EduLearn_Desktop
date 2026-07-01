"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const DEFAULT_HEARTBEAT_INTERVAL_MS = 1000;

function createWatchdogHeartbeat({
  heartbeatPath = process.env.EDULEARN_WATCHDOG_HEARTBEAT_PATH,
  token = process.env.EDULEARN_WATCHDOG_TOKEN,
  challenge = process.env.EDULEARN_WATCHDOG_CHALLENGE,
  getRuntimeSnapshot = () => ({}),
  now = Date.now,
  processId = process.pid,
  processPath = process.execPath,
  processStartedAtMs = Math.max(1, Math.round(Date.now() - process.uptime() * 1000)),
  intervalMs = DEFAULT_HEARTBEAT_INTERVAL_MS,
  fsImpl = fs,
  setIntervalImpl = setInterval,
  clearIntervalImpl = clearInterval,
} = {}) {
  let timer = null;
  let sequence = 0;
  let processSha256 = null;

  function isConfigured() {
    return Boolean(
      typeof heartbeatPath === "string" &&
        heartbeatPath.trim() &&
        typeof token === "string" &&
        token.length >= 32 &&
        typeof challenge === "string" &&
        challenge.length >= 32,
    );
  }

  function buildChallengePayload(record) {
    return [
      `v=${record.version}`,
      `seq=${record.sequence}`,
      `ts=${record.timestampMs}`,
      `pid=${record.electronPid}`,
      `path=${record.processPath}`,
      `sha=${String(record.processSha256).toLowerCase()}`,
      `started=${record.processStartedAtMs}`,
      `native=${record.nativeCoreConnected}`,
      `state=${record.sessionState}`,
      `session=${record.sessionId ?? ""}`,
      `challenge=${challenge}`,
    ].join("|");
  }

  function write() {
    if (!isConfigured()) {
      return false;
    }

    const snapshot = getRuntimeSnapshot() ?? {};
    if (!processSha256 && typeof processPath === "string" && processPath.trim()) {
      processSha256 = crypto.createHash("sha256").update(fsImpl.readFileSync(processPath)).digest("hex");
    }
    const heartbeat = {
      version: 2,
      sequence: ++sequence,
      timestampMs: now(),
      electronPid: processId,
      processPath,
      processSha256,
      processStartedAtMs,
      nativeCoreConnected: Boolean(snapshot.nativeCoreConnected),
      sessionState:
        typeof snapshot.sessionState === "string" ? snapshot.sessionState : "INIT",
      sessionId:
        typeof snapshot.activeSessionId === "string"
          ? snapshot.activeSessionId
          : typeof snapshot.sessionId === "string"
            ? snapshot.sessionId
            : null,
    };
    heartbeat.challengeResponse = crypto
      .createHmac("sha256", token)
      .update(buildChallengePayload(heartbeat))
      .digest("hex");
    const directory = path.dirname(heartbeatPath);
    const tempPath = `${heartbeatPath}.${processId}.tmp`;
    fsImpl.mkdirSync(directory, { recursive: true });
    fsImpl.writeFileSync(tempPath, JSON.stringify(heartbeat), {
      encoding: "utf8",
      flag: "w",
      mode: 0o600,
    });
    fsImpl.renameSync(tempPath, heartbeatPath);
    return true;
  }

  function start() {
    if (!isConfigured() || timer) {
      return false;
    }

    write();
    timer = setIntervalImpl(() => {
      try {
        write();
      } catch (error) {
        console.error("[watchdog] Failed to write heartbeat", error);
      }
    }, intervalMs);
    timer.unref?.();
    return true;
  }

  function stop({ remove = true } = {}) {
    if (timer) {
      clearIntervalImpl(timer);
      timer = null;
    }
    if (remove && isConfigured()) {
      try {
        fsImpl.rmSync(heartbeatPath, { force: true });
      } catch (error) {
        console.warn("[watchdog] Failed to remove heartbeat", error);
      }
    }
  }

  return {
    isConfigured,
    start,
    stop,
    write,
  };
}

module.exports = {
  DEFAULT_HEARTBEAT_INTERVAL_MS,
  createWatchdogHeartbeat,
};
