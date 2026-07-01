use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};

pub const EVENT_PROCESS_CREATED: &str = "ProcessCreated";
pub const EVENT_PROCESS_EXITED: &str = "ProcessExited";
pub const EVENT_PRODUCER_CHANGED: &str = "ProducerChanged";
pub const EVENT_PRODUCER_STARTED: &str = "ProducerStarted";
pub const EVENT_PRODUCER_STOPPED: &str = "ProducerStopped";
pub const EVENT_PRODUCER_FAILED: &str = "ProducerFailed";
pub const EVENT_PRODUCER_RECOVERED: &str = "ProducerRecovered";
pub const EVENT_PRODUCER_HEARTBEAT: &str = "ProducerHeartbeat";
pub const EVENT_PRODUCER_UNAVAILABLE: &str = "ProducerUnavailable";
pub const EVENT_PRODUCER_DEGRADED: &str = "ProducerDegraded";
pub const EVENT_GUARD_DEGRADED: &str = "GuardDegraded";
pub const EVENT_GUARD_RESTORED: &str = "GuardRestored";
pub const EVENT_GUARD_RESTARTED: &str = "GuardRestarted";
pub const EVENT_CLIPBOARD_CHANGED: &str = "ClipboardChanged";
pub const EVENT_FOCUS_CHANGED: &str = "FocusChanged";
pub const EVENT_CAPTURE_DETECTED: &str = "CaptureDetected";
pub const EVENT_POLICY_RELOADED: &str = "PolicyReloaded";
pub const EVENT_DESKTOP_CHANGED: &str = "DesktopChanged";
pub const EVENT_DESKTOP_RECOVERED: &str = "DesktopRecovered";
pub const EVENT_RUNTIME_RECOVERED: &str = "RuntimeRecovered";
pub const EVENT_WATCHER_RECOVERED: &str = "WatcherRecovered";
pub const EVENT_RECOVERY_STARTED: &str = "RecoveryStarted";
pub const EVENT_RECOVERY_COMPLETED: &str = "RecoveryCompleted";
pub const EVENT_RECOVERY_FINISHED: &str = "RecoveryFinished";
pub const EVENT_RUNTIME_STOPPED: &str = "RuntimeStopped";
pub const EVENT_RUNTIME_STATE_CHANGED: &str = "RuntimeStateChanged";
pub const EVENT_WATCHDOG_RESTART: &str = "WatchdogRestart";

fn is_known_runtime_event_kind(kind: &str) -> bool {
    matches!(
        kind,
        EVENT_PROCESS_CREATED
            | EVENT_PROCESS_EXITED
            | EVENT_PRODUCER_CHANGED
            | EVENT_PRODUCER_STARTED
            | EVENT_PRODUCER_STOPPED
            | EVENT_PRODUCER_FAILED
            | EVENT_PRODUCER_RECOVERED
            | EVENT_PRODUCER_HEARTBEAT
            | EVENT_PRODUCER_UNAVAILABLE
            | EVENT_PRODUCER_DEGRADED
            | EVENT_GUARD_DEGRADED
            | EVENT_GUARD_RESTORED
            | EVENT_GUARD_RESTARTED
            | EVENT_CLIPBOARD_CHANGED
            | EVENT_FOCUS_CHANGED
            | EVENT_CAPTURE_DETECTED
            | EVENT_POLICY_RELOADED
            | EVENT_DESKTOP_CHANGED
            | EVENT_DESKTOP_RECOVERED
            | EVENT_RUNTIME_RECOVERED
            | EVENT_WATCHER_RECOVERED
            | EVENT_RECOVERY_STARTED
            | EVENT_RECOVERY_COMPLETED
            | EVENT_RECOVERY_FINISHED
            | EVENT_RUNTIME_STOPPED
            | EVENT_RUNTIME_STATE_CHANGED
            | EVENT_WATCHDOG_RESTART
    )
}

const DEFAULT_RUNTIME_EVENT_CAPACITY: usize = 128;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeEvent {
    pub event_id: u64,
    pub kind: String,
    pub severity: String,
    pub timestamp: u64,
    pub detail: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug)]
pub struct RuntimeEventBus {
    capacity: usize,
    next_event_id: u64,
    events: VecDeque<RuntimeEvent>,
    guard_status: BTreeMap<String, String>,
    component_status: BTreeMap<String, String>,
}

impl Default for RuntimeEventBus {
    fn default() -> Self {
        Self::new(DEFAULT_RUNTIME_EVENT_CAPACITY)
    }
}

impl RuntimeEventBus {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            next_event_id: 1,
            events: VecDeque::new(),
            guard_status: BTreeMap::new(),
            component_status: BTreeMap::new(),
        }
    }

    pub fn emit(
        &mut self,
        kind: impl Into<String>,
        severity: impl Into<String>,
        timestamp: u64,
        detail: impl Into<String>,
        metadata: BTreeMap<String, String>,
    ) -> RuntimeEvent {
        let kind = kind.into();
        debug_assert!(is_known_runtime_event_kind(&kind));
        let event = RuntimeEvent {
            event_id: self.next_event_id,
            kind,
            severity: severity.into(),
            timestamp,
            detail: detail.into(),
            metadata,
        };
        self.next_event_id = self.next_event_id.saturating_add(1);
        self.events.push_back(event.clone());
        while self.events.len() > self.capacity {
            self.events.pop_front();
        }
        event
    }

    pub fn record_component_status(
        &mut self,
        component: &str,
        status: &str,
        timestamp: u64,
        detail: impl Into<String>,
    ) -> Option<RuntimeEvent> {
        let previous = self
            .component_status
            .insert(component.to_string(), status.to_string());
        if previous.as_deref() == Some(status) {
            return None;
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("component".to_string(), component.to_string());
        metadata.insert("status".to_string(), status.to_string());
        if let Some(previous) = previous {
            metadata.insert("previousStatus".to_string(), previous);
        }

        Some(self.emit(
            EVENT_PRODUCER_CHANGED,
            "info",
            timestamp,
            detail,
            metadata,
        ))
    }

    pub fn record_guard_health(
        &mut self,
        guard: &str,
        applied: bool,
        active: bool,
        timestamp: u64,
        detail: impl Into<String>,
    ) -> Option<RuntimeEvent> {
        let status = if applied && active {
            "alive"
        } else if active {
            "recovering"
        } else {
            "degraded"
        };
        let previous = self.guard_status.insert(guard.to_string(), status.to_string());

        match (previous.as_deref(), status) {
            (Some("degraded" | "recovering"), "alive") => {
                let mut metadata = BTreeMap::new();
                metadata.insert("guard".to_string(), guard.to_string());
                metadata.insert("status".to_string(), status.to_string());
                Some(self.emit(
                    EVENT_GUARD_RESTORED,
                    "info",
                    timestamp,
                    detail,
                    metadata,
                ))
            }
            (Some("alive"), "degraded" | "recovering") | (None, "degraded" | "recovering") => {
                let mut metadata = BTreeMap::new();
                metadata.insert("guard".to_string(), guard.to_string());
                metadata.insert("status".to_string(), status.to_string());
                Some(self.emit(
                    EVENT_GUARD_DEGRADED,
                    "warn",
                    timestamp,
                    detail,
                    metadata,
                ))
            }
            _ => None,
        }
    }

    pub fn recent_events(&self, limit: usize) -> Vec<RuntimeEvent> {
        let take = limit.min(self.events.len());
        self.events
            .iter()
            .skip(self.events.len().saturating_sub(take))
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }
}

pub fn metadata(entries: &[(&str, String)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_string(), value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        metadata, RuntimeEventBus, EVENT_CAPTURE_DETECTED, EVENT_DESKTOP_CHANGED,
        EVENT_GUARD_DEGRADED, EVENT_GUARD_RESTORED, EVENT_PROCESS_CREATED,
        EVENT_PRODUCER_CHANGED, EVENT_PRODUCER_DEGRADED, EVENT_PRODUCER_HEARTBEAT,
    };

    #[test]
    fn caps_event_queue() {
        let mut bus = RuntimeEventBus::new(2);
        bus.emit(EVENT_PROCESS_CREATED, "info", 1, "one", metadata(&[]));
        bus.emit(EVENT_CAPTURE_DETECTED, "info", 2, "two", metadata(&[]));
        bus.emit(EVENT_DESKTOP_CHANGED, "info", 3, "three", metadata(&[]));

        let events = bus.recent_events(10);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, EVENT_CAPTURE_DETECTED);
        assert_eq!(events[1].kind, EVENT_DESKTOP_CHANGED);
    }

    #[test]
    fn emits_guard_transition_events_without_spam() {
        let mut bus = RuntimeEventBus::new(8);

        let degraded = bus.record_guard_health("mouse", false, false, 10, "mouse failed");
        assert_eq!(degraded.unwrap().kind, EVENT_GUARD_DEGRADED);
        assert!(bus
            .record_guard_health("mouse", false, false, 11, "mouse still failed")
            .is_none());
        let restored = bus.record_guard_health("mouse", true, true, 12, "mouse restored");
        assert_eq!(restored.unwrap().kind, EVENT_GUARD_RESTORED);
    }

    #[test]
    fn emits_component_status_changes_without_spam() {
        let mut bus = RuntimeEventBus::new(8);

        let first = bus
            .record_component_status(
                "processProducer",
                "Polling:healthy",
                10,
                "producer selected",
            )
            .expect("first status should emit");
        assert_eq!(first.kind, EVENT_PRODUCER_CHANGED);
        assert_eq!(
            first.metadata.get("component").map(String::as_str),
            Some("processProducer")
        );

        assert!(bus
            .record_component_status(
                "processProducer",
                "Polling:healthy",
                11,
                "same status",
            )
            .is_none());

        let changed = bus
            .record_component_status(
                "processProducer",
                "Wmi:healthy",
                12,
                "producer changed",
            )
            .expect("status change should emit");
        assert_eq!(changed.kind, EVENT_PRODUCER_CHANGED);
        assert_eq!(
            changed.metadata.get("previousStatus").map(String::as_str),
            Some("Polling:healthy")
        );
    }

    #[test]
    fn accepts_process_producer_heartbeat_event() {
        let mut bus = RuntimeEventBus::new(8);
        let event = bus.emit(
            EVENT_PRODUCER_HEARTBEAT,
            "warn",
            10,
            "producer heartbeat",
            metadata(&[("source", "Polling".to_string())]),
        );

        assert_eq!(event.kind, EVENT_PRODUCER_HEARTBEAT);
        assert_eq!(
            event.metadata.get("source").map(String::as_str),
            Some("Polling")
        );
    }

    #[test]
    fn accepts_process_producer_degraded_event() {
        let mut bus = RuntimeEventBus::new(8);
        let event = bus.emit(
            EVENT_PRODUCER_DEGRADED,
            "warn",
            10,
            "ETW reported lost events.",
            metadata(&[("eventsLost", "1".to_string())]),
        );

        assert_eq!(event.kind, EVENT_PRODUCER_DEGRADED);
    }
}
