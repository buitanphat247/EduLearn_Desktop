"use strict";

const fs = require("fs");
const path = require("path");
const { logger, resolveLoggerBaseDir } = require("./logger");
// VS-04: single source of truth for the channel name lives in a dependency-free
// module so the sandboxed preload can import it without this file's fs/logger graph.
const { TRACE_CHANNEL } = require("./contracts/trace-channel");
const MAX_HISTORY = 10;
const RELOAD_LOOP_WINDOW_MS = 10_000;
const RELOAD_LOOP_THRESHOLD = 3;
const IDLE_LOOP_WINDOW_MS = 10_000;
const IDLE_LOOP_THRESHOLD = 3;

function nowIso(timestampMs) {
  return new Date(timestampMs).toISOString();
}

function trimHistory(list) {
  if (list.length > MAX_HISTORY) {
    list.splice(0, list.length - MAX_HISTORY);
  }
}

function createExamGuardTracer({ baseDir = resolveLoggerBaseDir() } = {}) {
  const stateHistory = [];
  const ipcHistory = [];
  const watcherHistory = [];
  const reloadTimestamps = [];
  const idleRollbackTimestamps = [];
  let lastStableState = "INIT";
  let firstFailurePoint = null;
  let rootCauseCategory = null;
  let activeTracePath = null;
  let traceStream = null;

  function ensureTraceStream() {
    if (traceStream) {
      return traceStream;
    }

    const logDir = logger.logDir ?? path.join(baseDir, "logs");
    fs.mkdirSync(logDir, { recursive: true });
    activeTracePath = path.join(logDir, "exam-guard-trace.log");
    traceStream = fs.createWriteStream(activeTracePath, { flags: "a" });
    return traceStream;
  }

  function writeLine(line, payload = null) {
    const stream = ensureTraceStream();
    const rendered = payload ? `${line} ${JSON.stringify(payload)}` : line;
    stream.write(`${rendered}\n`);
    console.log(rendered);
  }

  function markFailure(point, category) {
    if (!firstFailurePoint) {
      firstFailurePoint = point;
    }
    if (!rootCauseCategory) {
      rootCauseCategory = category;
    }
  }

  function emitCriticalLoop(reason) {
    markFailure(reason, reason.includes("watcher") ? "WATCHER" : "RACE CONDITION");
    writeLine("[CRITICAL_LOOP_DETECTED]", {
      reason,
      last10StateChanges: stateHistory.slice(-10),
      last10IpcCalls: ipcHistory.slice(-10),
      last10WatcherEvents: watcherHistory.slice(-10),
    });
  }

  function recordStateTransition({ from, to, source, reason, timestampMs = Date.now() }) {
    const event = {
      from,
      to,
      source,
      reason: reason ?? null,
      timestampMs,
    };
    stateHistory.push(event);
    trimHistory(stateHistory);
    if (to && to !== "IDLE") {
      lastStableState = to;
    }
    if (to === "IDLE" && from && from !== "INIT") {
      idleRollbackTimestamps.push(timestampMs);
      while (
        idleRollbackTimestamps.length > 0 &&
        timestampMs - idleRollbackTimestamps[0] > IDLE_LOOP_WINDOW_MS
      ) {
        idleRollbackTimestamps.shift();
      }
      markFailure(
        `[state_trace] ${from} -> ${to} | ${nowIso(timestampMs)} | ${source} | ${reason ?? "rollback"}`,
        "STATE",
      );
      if (idleRollbackTimestamps.length >= IDLE_LOOP_THRESHOLD) {
        emitCriticalLoop("state_idle_toggle_loop");
      }
    }
    writeLine(
      `[state_trace] ${from} -> ${to} | ${nowIso(timestampMs)} | ${source} | ${reason ?? "unspecified"}`,
    );
  }

  function recordIpc({ command, requestId, ok, state, latencyMs, source = "rust", reason = null, timestampMs = Date.now() }) {
    const event = {
      command,
      requestId,
      ok,
      state,
      latencyMs,
      source,
      reason,
      timestampMs,
    };
    ipcHistory.push(event);
    trimHistory(ipcHistory);
    if (ok === false) {
      markFailure(
        `[rust_ipc] ${command} | ${requestId} | ${ok} | ${state} | ${latencyMs}`,
        "IPC",
      );
    }
    writeLine(
      `[rust_ipc] ${command} | ${requestId} | ${ok} | ${state} | ${latencyMs}`,
      { source, reason },
    );
  }

  function recordLoop({ action, decision, state, reason, source = "electron", timestampMs = Date.now() }) {
    if (action === "renderer_reload_triggered") {
      reloadTimestamps.push(timestampMs);
      while (
        reloadTimestamps.length > 0 &&
        timestampMs - reloadTimestamps[0] > RELOAD_LOOP_WINDOW_MS
      ) {
        reloadTimestamps.shift();
      }
      if (reloadTimestamps.length > RELOAD_LOOP_THRESHOLD) {
        emitCriticalLoop("watcher_renderer_reload_loop");
      }
      markFailure(
        `[electron_loop] tick | ${action} | ${decision} | ${state} | ${reason}`,
        "WATCHER",
      );
    }
    writeLine(
      `[electron_loop] tick | ${action} | ${decision} | ${state} | ${reason}`,
      { source, timestamp: nowIso(timestampMs) },
    );
  }

  function recordPoll({ intervalMs, state, source, response = null, timestampMs = Date.now() }) {
    writeLine(
      `[poll] interval=${intervalMs}ms | state=${state} | source=${source}`,
      { response, timestamp: nowIso(timestampMs) },
    );
  }

  function recordUiGate({ renderAllowed, state, missingFlags, source = "renderer", timestampMs = Date.now() }) {
    if (!renderAllowed && !rootCauseCategory && Array.isArray(missingFlags) && missingFlags.length > 0) {
      markFailure(
        `[ui_gate] render_allowed=${renderAllowed} | ${state} | ${missingFlags.join(",")}`,
        "RENDER",
      );
    }
    writeLine(
      `[ui_gate] render_allowed=${renderAllowed} | ${state} | ${Array.isArray(missingFlags) ? missingFlags.join(",") : String(missingFlags ?? "")}`,
      { source, timestamp: nowIso(timestampMs) },
    );
  }

  function recordWatcher({ path: changedPath, triggerAction, accepted, source = "fs.watch", timestampMs = Date.now() }) {
    const event = {
      path: changedPath,
      triggerAction,
      accepted,
      source,
      timestampMs,
    };
    watcherHistory.push(event);
    trimHistory(watcherHistory);
    writeLine(
      `[watcher] file_changed | ${changedPath} | ${triggerAction} | ${accepted ? "accepted" : "ignored"}`,
      { source, timestamp: nowIso(timestampMs) },
    );
  }

  function recordAudio({
    event,
    processName = "electron",
    action,
    state,
    audioLockActive,
    reason = null,
    source = "audio-guard",
    timestampMs = Date.now(),
  }) {
    writeLine(`[${event}]`, {
      timestamp: nowIso(timestampMs),
      processName,
      action,
      state,
      audioLockActive,
      reason,
      source,
    });
  }

  function ingestRendererTrace(event) {
    if (!event || typeof event !== "object") {
      return;
    }
    switch (event.kind) {
      case "poll":
        recordPoll(event);
        break;
      case "ui_gate":
        recordUiGate(event);
        break;
      case "electron_loop":
        recordLoop(event);
        break;
      case "watcher":
        recordWatcher(event);
        break;
      case "state_trace":
        recordStateTransition(event);
        break;
      case "rust_ipc":
        recordIpc(event);
        break;
      case "audio_guard":
        recordAudio(event);
        break;
      default:
        writeLine("[trace_unknown]", event);
        break;
    }
  }

  function printSummary() {
    writeLine("[exam_guard_trace_summary]", {
      tracePath: activeTracePath,
      lastStableState,
      firstFailurePoint,
      rootCauseCategory: rootCauseCategory ?? "UNKNOWN",
      last10StateChanges: stateHistory.slice(-10),
      last10IpcCalls: ipcHistory.slice(-10),
      last10WatcherEvents: watcherHistory.slice(-10),
    });
  }

  return {
    TRACE_CHANNEL,
    ingestRendererTrace,
    printSummary,
    recordIpc,
    recordAudio,
    recordLoop,
    recordPoll,
    recordStateTransition,
    recordUiGate,
    recordWatcher,
  };
}

module.exports = {
  TRACE_CHANNEL,
  createExamGuardTracer,
};
