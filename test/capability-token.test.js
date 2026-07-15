const test = require("node:test");
const assert = require("node:assert/strict");

const {
  CAPABILITY_TOKEN_ARG_PREFIX,
  EXAM_SHELL_LAUNCH_ARG,
  getCapabilityToken,
  capabilityTokenLaunchArg,
  examShellIdentityLaunchArgs,
  readCapabilityTokenFromArgv,
  isExamShellFromArgv,
  readExamShellIdentityFromArgv,
  verifyCapabilityToken,
} = require("../src/capability-token");

test("VS-04: exam-shell identity round-trips through argv (sandbox-safe delivery)", () => {
  const args = examShellIdentityLaunchArgs("sess-123", "EXAM-9");
  assert.deepEqual(args, [
    "--edulearn-exam-session=sess-123",
    "--edulearn-exam-code=EXAM-9",
  ]);
  const parsed = readExamShellIdentityFromArgv([
    "electron.exe",
    capabilityTokenLaunchArg(),
    ...args,
    "app",
  ]);
  assert.equal(parsed.sessionId, "sess-123");
  assert.equal(parsed.examCode, "EXAM-9");
});

test("VS-04: identity launch args omit empty values; parser returns nulls when absent", () => {
  assert.deepEqual(examShellIdentityLaunchArgs(null, "EXAM-9"), [
    "--edulearn-exam-code=EXAM-9",
  ]);
  assert.deepEqual(examShellIdentityLaunchArgs(undefined, undefined), []);
  const parsed = readExamShellIdentityFromArgv(["electron.exe", "app"]);
  assert.equal(parsed.sessionId, null);
  assert.equal(parsed.examCode, null);
});

test("VS-04: token minting still works after crypto was made a lazy require", () => {
  const token = getCapabilityToken();
  assert.equal(typeof token, "string");
  assert.ok(token.length >= 32);
  assert.equal(verifyCapabilityToken(token), true);
  assert.equal(verifyCapabilityToken("wrong"), false);
});

test("isExamShellFromArgv detects the exam-shell launch marker", () => {
  assert.equal(
    isExamShellFromArgv(["electron.exe", EXAM_SHELL_LAUNCH_ARG, "app"]),
    true,
  );
  assert.equal(isExamShellFromArgv(["electron.exe", "app"]), false);
  assert.equal(isExamShellFromArgv(null), false);
  assert.equal(isExamShellFromArgv(undefined), false);
});

test("getCapabilityToken returns a stable, non-trivial hex secret", () => {
  const a = getCapabilityToken();
  const b = getCapabilityToken();
  assert.equal(a, b, "token must be stable within a process");
  assert.match(a, /^[0-9a-f]{64}$/, "token must be 32 random bytes as hex");
});

test("capabilityTokenLaunchArg embeds the current token", () => {
  const arg = capabilityTokenLaunchArg();
  assert.ok(arg.startsWith(CAPABILITY_TOKEN_ARG_PREFIX));
  assert.equal(arg.slice(CAPABILITY_TOKEN_ARG_PREFIX.length), getCapabilityToken());
});

test("readCapabilityTokenFromArgv round-trips the launch arg", () => {
  const argv = ["electron.exe", "--some-flag", capabilityTokenLaunchArg(), "app"];
  assert.equal(readCapabilityTokenFromArgv(argv), getCapabilityToken());
});

test("readCapabilityTokenFromArgv returns null when absent or invalid input", () => {
  assert.equal(readCapabilityTokenFromArgv(["electron.exe", "app"]), null);
  assert.equal(readCapabilityTokenFromArgv(undefined), null);
  assert.equal(readCapabilityTokenFromArgv(null), null);
});

test("verifyCapabilityToken accepts the real token and rejects everything else", () => {
  assert.equal(verifyCapabilityToken(getCapabilityToken()), true);
  assert.equal(verifyCapabilityToken("wrong-token"), false);
  assert.equal(verifyCapabilityToken(""), false);
  assert.equal(verifyCapabilityToken(null), false);
  assert.equal(verifyCapabilityToken(undefined), false);
  assert.equal(verifyCapabilityToken(123), false);
  // A token of the correct length but wrong content is still rejected.
  const sameLenWrong = "0".repeat(getCapabilityToken().length);
  assert.equal(verifyCapabilityToken(sameLenWrong), false);
});
