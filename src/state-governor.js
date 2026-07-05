"use strict";

const GOVERNOR_LOCK_MODES = Object.freeze({
  EXIT: "EXIT_LOCK",
});

const GOVERNOR_EVENT_SCOPES = Object.freeze({
  EXIT_FLOW: "EXIT_FLOW",
  RUNTIME: "RUNTIME",
});

const GOVERNOR_AUDIO_STATES = Object.freeze({
  HOLD: "HOLD",
  MUTE: "MUTE",
  RESTORE: "RESTORE",
});

const AUDIO_MUTE_STATES = new Set([
  "EXAM_RUNNING_CONFIRMED",
]);

const AUDIO_HOLD_STATES = new Set([
  "ENTERING_KIOSK",
  "EXAM_EXIT_REQUESTED",
]);

const AUDIO_RESTORE_STATES = new Set([
  "EXAM_EXITING",
  "EXITED",
]);

function createReadonlySnapshotView(getSnapshot) {
  return new Proxy(
    {},
    {
      defineProperty() {
        return false;
      },
      deleteProperty() {
        return false;
      },
      get(_target, property) {
        return getSnapshot()[property];
      },
      getOwnPropertyDescriptor(_target, property) {
        const snapshot = getSnapshot();
        if (!Object.prototype.hasOwnProperty.call(snapshot, property)) {
          return undefined;
        }
        return {
          configurable: true,
          enumerable: true,
          value: snapshot[property],
          writable: false,
        };
      },
      has(_target, property) {
        return property in getSnapshot();
      },
      ownKeys() {
        return Reflect.ownKeys(getSnapshot());
      },
      set() {
        return false;
      },
    },
  );
}

function createStateGovernor({
  governorId,
  initialSnapshot,
  normalizeSnapshot,
  onApplied,
}) {
  if (!governorId || typeof governorId !== "string") {
    throw new TypeError("State governor requires a stable governorId.");
  }
  if (!initialSnapshot || typeof initialSnapshot !== "object") {
    throw new TypeError("State governor requires an initial snapshot.");
  }
  if (typeof normalizeSnapshot !== "function") {
    throw new TypeError("State governor requires a snapshot normalizer.");
  }

  let lockMode = null;
  let lastAppliedSequenceId = 0;
  let nextIssuedSequenceId = 1;
  let processing = false;
  let snapshot = normalizeSnapshot({
    ...initialSnapshot,
    stateGovernorId: governorId,
    stateGovernorSequenceId: 0,
    stateGovernorLockMode: null,
    stateGovernorEventQueueLength: 0,
  });
  const eventQueue = [];

  function issueSequenceId() {
    const sequenceId = nextIssuedSequenceId;
    nextIssuedSequenceId += 1;
    return sequenceId;
  }

  function getSnapshot() {
    return snapshot;
  }

  function getAudioState(targetSnapshot = snapshot) {
    const sessionState = targetSnapshot.sessionState;

    if (AUDIO_RESTORE_STATES.has(sessionState)) {
      return GOVERNOR_AUDIO_STATES.RESTORE;
    }
    if (lockMode === GOVERNOR_LOCK_MODES.EXIT) {
      return GOVERNOR_AUDIO_STATES.HOLD;
    }
    if (AUDIO_MUTE_STATES.has(sessionState)) {
      return GOVERNOR_AUDIO_STATES.MUTE;
    }
    if (
      targetSnapshot.audioLockActive ||
      AUDIO_HOLD_STATES.has(sessionState)
    ) {
      return GOVERNOR_AUDIO_STATES.HOLD;
    }
    return GOVERNOR_AUDIO_STATES.RESTORE;
  }

  function reduceEvent(event) {
    const previousSnapshot = snapshot;

    if (event.lockMode !== undefined) {
      lockMode = event.lockMode;
    }

    const reducedSnapshot =
      typeof event.reduce === "function"
        ? event.reduce(previousSnapshot, {
            lockMode,
            scope: event.scope,
          })
        : {
            ...previousSnapshot,
            ...(event.patch ?? {}),
          };

    if (!reducedSnapshot || typeof reducedSnapshot !== "object") {
      throw new TypeError("State governor reducer must return a snapshot.");
    }

    if (event.unlockAfterApply) {
      lockMode = null;
    }

    snapshot = normalizeSnapshot({
      ...reducedSnapshot,
      stateGovernorId: governorId,
      stateGovernorSequenceId: event.sequenceId,
      stateGovernorLockMode: lockMode,
      stateGovernorEventQueueLength: eventQueue.length,
    });
    lastAppliedSequenceId = event.sequenceId;
    onApplied?.({
      event,
      previousSnapshot,
      snapshot,
    });
  }

  function drainQueue() {
    if (processing) {
      return;
    }

    processing = true;
    try {
      while (eventQueue.length > 0) {
        const event = eventQueue.shift();
        if (event.sequenceId <= lastAppliedSequenceId) {
          event.result = {
            accepted: false,
            reason: "stale_sequence",
            snapshot,
          };
          continue;
        }

        reduceEvent(event);
        event.result = {
          accepted: true,
          reason: null,
          snapshot,
        };
      }
    } finally {
      processing = false;
    }
  }

  function apply(event) {
    if (!event || typeof event !== "object") {
      throw new TypeError("State governor event must be an object.");
    }
    if (!Number.isSafeInteger(event.sequenceId) || event.sequenceId <= 0) {
      throw new TypeError(
        "State governor event requires a positive integer sequenceId.",
      );
    }
    if (!event.type || typeof event.type !== "string") {
      throw new TypeError("State governor event requires a type.");
    }
    if (event.sequenceId <= lastAppliedSequenceId) {
      return {
        accepted: false,
        reason: "stale_sequence",
        snapshot,
      };
    }

    nextIssuedSequenceId = Math.max(
      nextIssuedSequenceId,
      event.sequenceId + 1,
    );
    eventQueue.push(event);
    drainQueue();
    return (
      event.result ?? {
        accepted: false,
        reason: "queued",
        snapshot,
      }
    );
  }

  function enqueue({
    type,
    patch,
    reduce,
    reason = null,
    source = "desktop-core",
    scope = GOVERNOR_EVENT_SCOPES.RUNTIME,
    lockMode: requestedLockMode,
    unlockAfterApply = false,
  }) {
    return apply({
      sequenceId: issueSequenceId(),
      type,
      patch,
      reduce,
      reason,
      source,
      scope,
      lockMode: requestedLockMode,
      unlockAfterApply,
    });
  }

  return {
    apply,
    enqueue,
    getAudioState,
    getLockMode() {
      return lockMode;
    },
    getSnapshot,
    issueSequenceId,
    readonlySnapshot: createReadonlySnapshotView(getSnapshot),
  };
}

module.exports = {
  GOVERNOR_AUDIO_STATES,
  GOVERNOR_EVENT_SCOPES,
  GOVERNOR_LOCK_MODES,
  createAtomicStateEngine: createStateGovernor,
  createStateGovernor,
};
