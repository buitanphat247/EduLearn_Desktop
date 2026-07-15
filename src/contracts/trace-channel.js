"use strict";

// VS-04: dependency-free source of the exam-guard trace IPC channel name.
// The (sandboxed) preload imports the constant from HERE instead of from
// exam-guard-trace.js, so it never drags that module's fs/path/logger/electron.app
// graph into the preload bundle (none of which is available in a sandboxed preload).
module.exports = { TRACE_CHANNEL: "exam-guard:trace" };
