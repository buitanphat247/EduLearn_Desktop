"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const { resolveAudioDirective } = require("../src/audio-guard");

test("audio directive holds mute through confirmation and exit request", () => {
  assert.equal(
    resolveAudioDirective({
      sessionState: "EXAM_RUNNING",
      audioLockActive: true,
      exitInProgress: true,
    }, "HOLD"),
    "HOLD",
  );
  assert.equal(
    resolveAudioDirective({
      sessionState: "EXAM_EXIT_REQUESTED",
      audioLockActive: true,
      exitInProgress: true,
    }),
    "HOLD",
  );
});

test("audio directive restores only after exit reaches teardown state", () => {
  assert.equal(
    resolveAudioDirective({
      sessionState: "EXAM_EXITING",
      audioLockActive: true,
      exitInProgress: true,
    }),
    "RESTORE",
  );
  assert.equal(
    resolveAudioDirective({
      sessionState: "EXITED",
      audioLockActive: false,
      exitInProgress: false,
    }),
    "RESTORE",
  );
});
