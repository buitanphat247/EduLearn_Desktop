const test = require("node:test");
const assert = require("node:assert/strict");
const Module = require("module");

// Stub Electron so this module can run in plain Node.
const electronStub = {
  ipcMain: { listenerCount: () => 0, handle: () => {}, on: () => {} },
  shell: { openExternal: async () => true },
  app: { quit: () => {} },
};
const originalLoad = Module._load;
Module._load = function patchedLoad(request, ...rest) {
  if (request === "electron") return electronStub;
  return originalLoad.call(this, request, ...rest);
};

const {
  RENDERER_ALLOWED_COMMANDS,
  MAIN_ONLY_COMMANDS,
  SAFE_EXAM_COMMANDS,
  isSafeExamCommand,
  isRendererAllowedCommand,
  isMainOnlyCommand,
} = require("../src/contracts/safe-exam");

const {
  isRendererAllowedCommand: ipcIsRendererAllowed,
  MAIN_ONLY_COMMANDS: ipcMainOnly,
} = require("../src/ipc");

Module._load = originalLoad;

// ─── Command classification ───────────────────────────────────────────────────

test("MAIN_ONLY commands are NOT in RENDERER_ALLOWED_COMMANDS", () => {
  for (const cmd of ipcMainOnly) {
    assert.equal(
      RENDERER_ALLOWED_COMMANDS.has(cmd),
      false,
      `MAIN_ONLY command '${cmd}' must not be in RENDERER_ALLOWED_COMMANDS`,
    );
  }
});

test("RENDERER_ALLOWED commands are NOT in MAIN_ONLY_COMMANDS", () => {
  for (const cmd of RENDERER_ALLOWED_COMMANDS) {
    assert.equal(
      ipcMainOnly.has(cmd),
      false,
      `RENDERER_ALLOWED command '${cmd}' must not be in MAIN_ONLY_COMMANDS`,
    );
  }
});

test("SAFE_EXAM_COMMANDS is the union of both sets", () => {
  for (const cmd of ipcMainOnly) {
    assert.equal(SAFE_EXAM_COMMANDS.has(cmd), true, `'${cmd}' must be in SAFE_EXAM_COMMANDS`);
  }
  for (const cmd of RENDERER_ALLOWED_COMMANDS) {
    assert.equal(SAFE_EXAM_COMMANDS.has(cmd), true, `'${cmd}' must be in SAFE_EXAM_COMMANDS`);
  }
});

// ─── isRendererAllowedCommand ─────────────────────────────────────────────────

test("isRendererAllowedCommand returns true for renderer-allowed commands", () => {
  for (const cmd of RENDERER_ALLOWED_COMMANDS) {
    assert.equal(
      isRendererAllowedCommand(cmd),
      true,
      `'${cmd}' should be renderer-allowed`,
    );
  }
});

test("isRendererAllowedCommand returns false for main-only commands", () => {
  for (const cmd of ipcMainOnly) {
    assert.equal(
      isRendererAllowedCommand(cmd),
      false,
      `'${cmd}' should not be renderer-allowed`,
    );
  }
});

test("isRendererAllowedCommand returns false for unknown commands", () => {
  assert.equal(isRendererAllowedCommand("delete_everything"), false);
  assert.equal(isRendererAllowedCommand("exec_payload"), false);
  assert.equal(isRendererAllowedCommand(""), false);
  assert.equal(isRendererAllowedCommand(null), false);
  assert.equal(isRendererAllowedCommand(undefined), false);
});

// ─── isMainOnlyCommand ────────────────────────────────────────────────────────

test("isMainOnlyCommand returns true for main-only commands", () => {
  for (const cmd of ipcMainOnly) {
    assert.equal(
      isMainOnlyCommand(cmd),
      true,
      `'${cmd}' should be main-only`,
    );
  }
});

test("isMainOnlyCommand returns false for renderer-allowed commands", () => {
  for (const cmd of RENDERER_ALLOWED_COMMANDS) {
    assert.equal(
      isMainOnlyCommand(cmd),
      false,
      `'${cmd}' should not be main-only`,
    );
  }
});

test("isMainOnlyCommand returns false for unknown commands", () => {
  assert.equal(isMainOnlyCommand("evil_command"), false);
  assert.equal(isMainOnlyCommand(""), false);
  assert.equal(isMainOnlyCommand(null), false);
});

// ─── IPC export parity ─────────────────────────────────────────────────────────

test("ipc.js exports isRendererAllowedCommand matching the contract", () => {
  // Both must reference the same underlying Set to avoid divergence.
  assert.equal(ipcIsRendererAllowed("shutdown"), false);
  assert.equal(ipcIsRendererAllowed("start_exam_session"), true);
  assert.equal(ipcIsRendererAllowed("create_exam_desktop"), false);
  assert.equal(ipcIsRendererAllowed("force_restore_desktop"), true);
});

test("ipc.js MAIN_ONLY_COMMANDS matches the contract MAIN_ONLY_COMMANDS", () => {
  for (const cmd of ipcMainOnly) {
    assert.equal(MAIN_ONLY_COMMANDS.has(cmd), true, `'${cmd}' mismatch`);
  }
  for (const cmd of MAIN_ONLY_COMMANDS) {
    assert.equal(ipcMainOnly.has(cmd), true, `'${cmd}' mismatch`);
  }
});

// ─── Known privileged commands explicitly blocked ──────────────────────────────

test("'shutdown' is main-only (renderer cannot shut down the machine)", () => {
  assert.equal(isMainOnlyCommand("shutdown"), true);
  assert.equal(isRendererAllowedCommand("shutdown"), false);
  assert.equal(isSafeExamCommand("shutdown"), true); // still a known command, just privileged
});

test("'create_exam_desktop' is main-only (only main may create the isolated desktop)", () => {
  assert.equal(isMainOnlyCommand("create_exam_desktop"), true);
  assert.equal(isRendererAllowedCommand("create_exam_desktop"), false);
});

test("'switch_default_desktop' is main-only", () => {
  assert.equal(isMainOnlyCommand("switch_default_desktop"), true);
  assert.equal(isRendererAllowedCommand("switch_default_desktop"), false);
});

test("'activate_input_lockdown' is main-only", () => {
  assert.equal(isMainOnlyCommand("activate_input_lockdown"), true);
  assert.equal(isRendererAllowedCommand("activate_input_lockdown"), false);
});

test("'deactivate_input_lockdown' is main-only", () => {
  assert.equal(isMainOnlyCommand("deactivate_input_lockdown"), true);
  assert.equal(isRendererAllowedCommand("deactivate_input_lockdown"), false);
});

// ─── Known safe commands explicitly allowed ────────────────────────────────────

test("'start_exam_session' is renderer-allowed", () => {
  assert.equal(isRendererAllowedCommand("start_exam_session"), true);
  assert.equal(isMainOnlyCommand("start_exam_session"), false);
});

test("'exit_exam_session' is renderer-allowed", () => {
  assert.equal(isRendererAllowedCommand("exit_exam_session"), true);
  assert.equal(isMainOnlyCommand("exit_exam_session"), false);
});

test("'force_restore_desktop' is renderer-allowed (UI-triggered recovery)", () => {
  assert.equal(isRendererAllowedCommand("force_restore_desktop"), true);
  assert.equal(isMainOnlyCommand("force_restore_desktop"), false);
});

test("'get_protection_status' is renderer-allowed", () => {
  assert.equal(isRendererAllowedCommand("get_protection_status"), true);
});

test("'load_policy' is renderer-allowed", () => {
  assert.equal(isRendererAllowedCommand("load_policy"), true);
});
