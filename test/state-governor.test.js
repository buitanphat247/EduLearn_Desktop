"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  GOVERNOR_AUDIO_STATES,
  GOVERNOR_EVENT_SCOPES,
  GOVERNOR_LOCK_MODES,
  createStateGovernor,
} = require("../src/state-governor");

function createGovernor() {
  return createStateGovernor({
    governorId: "governor-test",
    initialSnapshot: {
      sessionState: "IDLE",
      audioLockActive: false,
    },
    normalizeSnapshot(snapshot) {
      return { ...snapshot };
    },
  });
}

test("state governor applies FIFO events and rejects stale sequences", () => {
  const governor = createGovernor();
  const first = governor.apply({
    sequenceId: 1,
    type: "STATE_PATCH",
    patch: { sessionState: "STARTING_EXAM_SESSION" },
  });
  const stale = governor.apply({
    sequenceId: 1,
    type: "STATE_PATCH",
    patch: { sessionState: "IDLE" },
  });
  const second = governor.apply({
    sequenceId: 2,
    type: "STATE_PATCH",
    patch: {
      sessionState: "EXAM_RUNNING_CONFIRMED",
      audioLockActive: true,
    },
  });

  assert.equal(first.accepted, true);
  assert.equal(stale.accepted, false);
  assert.equal(stale.reason, "stale_sequence");
  assert.equal(second.accepted, true);
  assert.equal(
    governor.getSnapshot().sessionState,
    "EXAM_RUNNING_CONFIRMED",
  );
  assert.equal(governor.getSnapshot().stateGovernorSequenceId, 2);
  assert.equal(governor.getAudioState(), GOVERNOR_AUDIO_STATES.MUTE);
});

test("state governor keeps audio frozen during exit request and restores at exiting", () => {
  const governor = createGovernor();

  governor.enqueue({
    type: "EXIT_REQUESTED",
    scope: GOVERNOR_EVENT_SCOPES.EXIT_FLOW,
    lockMode: GOVERNOR_LOCK_MODES.EXIT,
    patch: {
      sessionState: "EXAM_EXIT_REQUESTED",
      audioLockActive: true,
      exitInProgress: true,
    },
  });

  assert.equal(governor.getLockMode(), GOVERNOR_LOCK_MODES.EXIT);
  assert.equal(governor.getAudioState(), GOVERNOR_AUDIO_STATES.HOLD);

  governor.enqueue({
    type: "EXITING",
    scope: GOVERNOR_EVENT_SCOPES.EXIT_FLOW,
    patch: {
      sessionState: "EXAM_EXITING",
      audioLockActive: true,
      exitInProgress: true,
    },
  });

  assert.equal(governor.getAudioState(), GOVERNOR_AUDIO_STATES.RESTORE);

  governor.enqueue({
    type: "EXITED",
    scope: GOVERNOR_EVENT_SCOPES.EXIT_FLOW,
    unlockAfterApply: true,
    patch: {
      sessionState: "EXITED",
      audioLockActive: false,
      exitInProgress: false,
    },
  });

  assert.equal(governor.getLockMode(), null);
  assert.equal(governor.getAudioState(), GOVERNOR_AUDIO_STATES.RESTORE);
});

test("readonly governor view always reflects the latest snapshot", () => {
  const governor = createGovernor();
  const view = governor.readonlySnapshot;

  governor.enqueue({
    type: "STATE_PATCH",
    patch: { sessionState: "PREFLIGHT" },
  });

  assert.equal(view.sessionState, "PREFLIGHT");
  assert.equal(view.stateGovernorSequenceId, 1);
  assert.throws(() => {
    view.sessionState = "IDLE";
  }, TypeError);
});
