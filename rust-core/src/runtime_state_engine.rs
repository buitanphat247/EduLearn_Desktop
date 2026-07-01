use crate::models::{ProcessInfo, ProcessRemediationReport};
use crate::process_watcher::{ProcessCreationEvent, ProcessWatcherSource};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};

pub const RUNTIME_STATE_ENGINE_VERSION: &str = "10.8";
const DEFAULT_RUNTIME_QUEUE_CAPACITY: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessIdentity {
    pub pid: u32,
    pub image_name: String,
    pub creation_time_ms: Option<u64>,
    pub image_path: Option<String>,
    pub image_hash: Option<String>,
    pub signer: Option<String>,
    pub integrity_level: Option<String>,
    pub parent_pid: Option<u32>,
    pub session_id: Option<u32>,
    pub command_line: Option<String>,
}

impl ProcessIdentity {
    pub fn from_process_event(event: &ProcessCreationEvent) -> Self {
        Self {
            pid: event.pid,
            image_name: event.name.clone(),
            creation_time_ms: event.creation_time_ms,
            image_path: event.executable_path.clone(),
            image_hash: None,
            signer: None,
            integrity_level: None,
            parent_pid: event.parent_pid,
            session_id: event.session_id,
            command_line: event.command_line.clone(),
        }
    }

    pub fn from_process_info(process: &ProcessInfo) -> Self {
        Self {
            pid: process.pid,
            image_name: process.name.clone(),
            creation_time_ms: process.creation_time_ms,
            image_path: process.executable_path.clone(),
            image_hash: None,
            signer: None,
            integrity_level: None,
            parent_pid: None,
            session_id: None,
            command_line: None,
        }
    }

    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.pid,
            self.creation_time_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            self.image_name.to_ascii_lowercase(),
            self.image_path
                .as_deref()
                .unwrap_or("unknown")
                .to_ascii_lowercase(),
            self.command_line
                .as_deref()
                .unwrap_or("unknown")
                .to_ascii_lowercase()
        )
    }

    fn same_stable_image(&self, other: &ProcessIdentity) -> bool {
        let name_compatible = self.image_name.is_empty()
            || other.image_name.is_empty()
            || self.image_name.eq_ignore_ascii_case(&other.image_name);
        if self.pid != other.pid
            || !name_compatible
            || matches!(
                (self.creation_time_ms, other.creation_time_ms),
                (Some(left), Some(right)) if left != right
            )
        {
            return false;
        }

        match (&self.image_path, &other.image_path) {
            (Some(left), Some(right)) if !left.is_empty() && !right.is_empty() => {
                left.eq_ignore_ascii_case(right)
            }
            _ => true,
        }
    }

    fn same_reconciliation_image(&self, other: &ProcessIdentity) -> bool {
        if self.pid != other.pid {
            return false;
        }
        let creation_compatible = match (self.creation_time_ms, other.creation_time_ms) {
            (Some(left), Some(right)) => left == right || left / 1_000 == right / 1_000,
            _ => true,
        };
        if !creation_compatible {
            return false;
        }
        let name_compatible = self.image_name.is_empty()
            || other.image_name.is_empty()
            || self.image_name.eq_ignore_ascii_case(&other.image_name);
        let path_compatible = match (&self.image_path, &other.image_path) {
            (Some(left), Some(right)) if !left.is_empty() && !right.is_empty() => {
                left.eq_ignore_ascii_case(right)
            }
            _ => true,
        };
        name_compatible && path_compatible
    }

    fn merge_missing_fields(&mut self, other: &ProcessIdentity) {
        if self.image_name.is_empty() {
            self.image_name = other.image_name.clone();
        }
        if self.creation_time_ms.is_none() {
            self.creation_time_ms = other.creation_time_ms;
        }
        if self.image_path.is_none() {
            self.image_path = other.image_path.clone();
        }
        if self.image_hash.is_none() {
            self.image_hash = other.image_hash.clone();
        }
        if self.signer.is_none() {
            self.signer = other.signer.clone();
        }
        if self.integrity_level.is_none() {
            self.integrity_level = other.integrity_level.clone();
        }
        if self.parent_pid.is_none() {
            self.parent_pid = other.parent_pid;
        }
        if self.session_id.is_none() {
            self.session_id = other.session_id;
        }
        if self.command_line.is_none() {
            self.command_line = other.command_line.clone();
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RuntimeLifecycleState {
    Initializing,
    Starting,
    Healthy,
    Degraded,
    Recovering,
    Fallback,
    Failed,
    ShuttingDown,
}

impl Default for RuntimeLifecycleState {
    fn default() -> Self {
        Self::Initializing
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStateTransition {
    pub previous: RuntimeLifecycleState,
    pub next: RuntimeLifecycleState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RuntimeProcessEventKind {
    ProcessCreated,
    ProcessExited,
    Reconciled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeProcessEvent {
    pub kind: RuntimeProcessEventKind,
    pub source: ProcessWatcherSource,
    pub identity: ProcessIdentity,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProducerHealthSnapshot {
    pub source: ProcessWatcherSource,
    pub health: String,
    pub heartbeat_at_ms: Option<u64>,
    pub last_event_time_ms: Option<u64>,
    pub events_lost: usize,
    pub buffers_lost: usize,
    pub realtime_buffers_lost: usize,
    pub queue_depth: usize,
    pub dropped_events: usize,
    pub callback_latency_micros: u64,
    pub producer_restart_count: u64,
    pub parse_error_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeQueueSnapshot {
    pub capacity: usize,
    pub depth: usize,
    pub dropped_events: usize,
    pub backpressure_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSynchronizationSnapshot {
    pub duplicate_event_count: usize,
    pub late_event_count: usize,
    pub out_of_order_event_count: usize,
    pub pid_reuse_count: usize,
    pub exit_before_create_count: usize,
    pub merge_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStateEngineSnapshot {
    pub runtime_version: String,
    pub runtime_state: RuntimeLifecycleState,
    pub producer_state: BTreeMap<String, ProducerHealthSnapshot>,
    pub queue_state: RuntimeQueueSnapshot,
    pub health_state: String,
    pub synchronization_state: RuntimeSynchronizationSnapshot,
    pub process_identity_count: usize,
    pub active_process_count: usize,
    pub remediation_status: String,
    pub reconciliation_count: usize,
    pub recovery_count: usize,
    pub dropped_events: usize,
}

#[derive(Debug, Clone)]
struct KnownProcess {
    identity: ProcessIdentity,
    active: bool,
    first_seen_ms: u64,
    last_seen_ms: u64,
    last_source: ProcessWatcherSource,
}

#[derive(Debug, Default)]
struct SynchronizationCounters {
    duplicate_event_count: usize,
    late_event_count: usize,
    out_of_order_event_count: usize,
    pid_reuse_count: usize,
    exit_before_create_count: usize,
    merge_count: usize,
}

#[derive(Debug)]
pub struct RuntimeStateEngine {
    runtime_state: RuntimeLifecycleState,
    known_processes: BTreeMap<String, KnownProcess>,
    active_identity_by_pid: BTreeMap<u32, String>,
    producer_health: BTreeMap<String, ProducerHealthSnapshot>,
    queue: VecDeque<RuntimeProcessEvent>,
    queue_capacity: usize,
    dropped_events: usize,
    reconciliation_count: usize,
    recovery_count: usize,
    remediation_status: String,
    counters: SynchronizationCounters,
}

impl Default for RuntimeStateEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeStateEngine {
    pub fn new() -> Self {
        Self {
            runtime_state: RuntimeLifecycleState::Initializing,
            known_processes: BTreeMap::new(),
            active_identity_by_pid: BTreeMap::new(),
            producer_health: BTreeMap::new(),
            queue: VecDeque::new(),
            queue_capacity: DEFAULT_RUNTIME_QUEUE_CAPACITY,
            dropped_events: 0,
            reconciliation_count: 0,
            recovery_count: 0,
            remediation_status: "idle".to_string(),
            counters: SynchronizationCounters::default(),
        }
    }

    #[cfg(test)]
    pub fn with_queue_capacity(queue_capacity: usize) -> Self {
        Self {
            queue_capacity: queue_capacity.max(1),
            ..Self::new()
        }
    }

    pub fn transition(
        &mut self,
        next_state: RuntimeLifecycleState,
    ) -> Result<Option<RuntimeStateTransition>, String> {
        if self.runtime_state == next_state {
            return Ok(None);
        }
        if !is_valid_runtime_transition(&self.runtime_state, &next_state) {
            return Err(format!(
                "Invalid runtime state transition: {:?} -> {:?}.",
                self.runtime_state, next_state
            ));
        }

        let previous = self.runtime_state.clone();
        if matches!(next_state, RuntimeLifecycleState::Recovering) {
            self.recovery_count = self.recovery_count.saturating_add(1);
        }
        self.runtime_state = next_state.clone();
        Ok(Some(RuntimeStateTransition {
            previous,
            next: next_state,
        }))
    }

    pub fn reset_session_data(&mut self) {
        self.known_processes.clear();
        self.active_identity_by_pid.clear();
        self.producer_health.clear();
        self.queue.clear();
        self.dropped_events = 0;
        self.reconciliation_count = 0;
        self.recovery_count = 0;
        self.remediation_status = "idle".to_string();
        self.counters = SynchronizationCounters::default();
    }

    pub fn update_producer_snapshot(&mut self, snapshot: ProducerHealthSnapshot) {
        self.producer_health
            .insert(format!("{:?}", snapshot.source), snapshot);
    }

    pub fn enqueue(&mut self, event: RuntimeProcessEvent) {
        if self.queue.len() >= self.queue_capacity {
            self.queue.pop_front();
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
        self.queue.push_back(event);
    }

    pub fn submit_process_event(
        &mut self,
        event: &ProcessCreationEvent,
        source: ProcessWatcherSource,
    ) {
        let kind = if event.still_running {
            RuntimeProcessEventKind::ProcessCreated
        } else {
            RuntimeProcessEventKind::ProcessExited
        };
        self.enqueue(RuntimeProcessEvent {
            kind,
            source,
            identity: ProcessIdentity::from_process_event(event),
            observed_at_ms: event.observed_at_ms,
        });
    }

    pub fn drain_queue(&mut self) {
        while let Some(event) = self.queue.pop_front() {
            self.apply_event(event);
        }
    }

    pub fn reconcile_processes(
        &mut self,
        processes: &[ProcessInfo],
        observed_at_ms: u64,
        source: ProcessWatcherSource,
    ) {
        let current_pids = processes
            .iter()
            .map(|process| process.pid)
            .collect::<Vec<_>>();

        for process in processes {
            let identity = ProcessIdentity::from_process_info(process);
            let matching_active_key = self
                .active_identity_by_pid
                .get(&identity.pid)
                .and_then(|key| {
                    self.known_processes
                        .get(key)
                        .filter(|known| known.identity.same_reconciliation_image(&identity))
                        .map(|_| key.clone())
                });

            if let Some(key) = matching_active_key {
                if let Some(existing) = self.known_processes.get_mut(&key) {
                    existing.identity.merge_missing_fields(&identity);
                    existing.last_seen_ms = observed_at_ms.max(existing.last_seen_ms);
                    existing.last_source = source.clone();
                }
            } else {
                self.apply_event(RuntimeProcessEvent {
                    kind: RuntimeProcessEventKind::Reconciled,
                    source: source.clone(),
                    identity,
                    observed_at_ms,
                });
                self.reconciliation_count = self.reconciliation_count.saturating_add(1);
            }
        }

        let stale_pids = self
            .active_identity_by_pid
            .keys()
            .filter(|pid| !current_pids.contains(pid))
            .copied()
            .collect::<Vec<_>>();
        for pid in stale_pids {
            if let Some(key) = self.active_identity_by_pid.remove(&pid) {
                if let Some(existing) = self.known_processes.get_mut(&key) {
                    existing.active = false;
                    existing.last_seen_ms = observed_at_ms.max(existing.last_seen_ms);
                    existing.last_source = source.clone();
                    self.reconciliation_count = self.reconciliation_count.saturating_add(1);
                }
            }
        }
    }

    pub fn active_processes(&self) -> Vec<ProcessInfo> {
        self.known_processes
            .values()
            .filter(|known| known.active)
            .map(|known| ProcessInfo {
                pid: known.identity.pid,
                name: known.identity.image_name.clone(),
                executable_path: known.identity.image_path.clone(),
                creation_time_ms: known.identity.creation_time_ms,
                memory_mb: 0,
                categories: vec!["runtimeStateEngine".to_string()],
            })
            .collect()
    }

    pub fn record_remediation(&mut self, report: &ProcessRemediationReport) {
        self.remediation_status = if report.failed_count > 0 {
            "failed"
        } else if report.pending_termination_count > 0 {
            "pending"
        } else if report.terminated_count > 0 {
            "remediated"
        } else {
            "idle"
        }
        .to_string();
    }

    pub fn snapshot(&self) -> RuntimeStateEngineSnapshot {
        let active_process_count = self
            .known_processes
            .values()
            .filter(|process| process.active)
            .count();
        RuntimeStateEngineSnapshot {
            runtime_version: RUNTIME_STATE_ENGINE_VERSION.to_string(),
            runtime_state: self.runtime_state.clone(),
            producer_state: self.producer_health.clone(),
            queue_state: RuntimeQueueSnapshot {
                capacity: self.queue_capacity,
                depth: self.queue.len(),
                dropped_events: self.dropped_events,
                backpressure_active: self.queue.len() >= self.queue_capacity,
            },
            health_state: self.health_state(),
            synchronization_state: RuntimeSynchronizationSnapshot {
                duplicate_event_count: self.counters.duplicate_event_count,
                late_event_count: self.counters.late_event_count,
                out_of_order_event_count: self.counters.out_of_order_event_count,
                pid_reuse_count: self.counters.pid_reuse_count,
                exit_before_create_count: self.counters.exit_before_create_count,
                merge_count: self.counters.merge_count,
            },
            process_identity_count: self.known_processes.len(),
            active_process_count,
            remediation_status: self.remediation_status.clone(),
            reconciliation_count: self.reconciliation_count,
            recovery_count: self.recovery_count,
            dropped_events: self.dropped_events,
        }
    }

    fn apply_event(&mut self, event: RuntimeProcessEvent) {
        let identity_key = self.resolve_identity_key(&event.identity);
        match event.kind {
            RuntimeProcessEventKind::ProcessCreated | RuntimeProcessEventKind::Reconciled => {
                self.apply_create_or_reconcile(identity_key, event);
            }
            RuntimeProcessEventKind::ProcessExited => {
                self.apply_exit(identity_key, event);
            }
        }
    }

    fn resolve_identity_key(&self, identity: &ProcessIdentity) -> String {
        let exact_key = identity.key();
        if self.known_processes.contains_key(&exact_key) {
            return exact_key;
        }
        if let Some(active_key) = self.active_identity_by_pid.get(&identity.pid) {
            if let Some(existing) = self.known_processes.get(active_key) {
                if existing.identity.same_stable_image(identity) {
                    return active_key.clone();
                }
            }
        }
        exact_key
    }

    fn apply_create_or_reconcile(&mut self, identity_key: String, event: RuntimeProcessEvent) {
        if let Some(active_key) = self.active_identity_by_pid.get(&event.identity.pid).cloned() {
            if active_key != identity_key {
                if let Some(active) = self.known_processes.get(&active_key) {
                    if matches!(
                        (
                            event.identity.creation_time_ms,
                            active.identity.creation_time_ms
                        ),
                        (Some(incoming), Some(current)) if incoming < current
                    ) {
                        self.counters.late_event_count =
                            self.counters.late_event_count.saturating_add(1);
                        self.counters.out_of_order_event_count =
                            self.counters.out_of_order_event_count.saturating_add(1);
                        return;
                    }
                }
                if let Some(existing) = self.known_processes.get_mut(&active_key) {
                    existing.active = false;
                    self.counters.pid_reuse_count =
                        self.counters.pid_reuse_count.saturating_add(1);
                }
            }
        }

        match self.known_processes.get_mut(&identity_key) {
            Some(existing) => {
                if event.observed_at_ms < existing.last_seen_ms {
                    self.counters.late_event_count =
                        self.counters.late_event_count.saturating_add(1);
                    self.counters.out_of_order_event_count =
                        self.counters.out_of_order_event_count.saturating_add(1);
                    return;
                }
                if existing.active && matches!(event.kind, RuntimeProcessEventKind::ProcessCreated)
                {
                    self.counters.duplicate_event_count =
                        self.counters.duplicate_event_count.saturating_add(1);
                }
                existing.identity.merge_missing_fields(&event.identity);
                existing.active = true;
                existing.last_seen_ms = event.observed_at_ms;
                existing.last_source = event.source;
                self.counters.merge_count = self.counters.merge_count.saturating_add(1);
            }
            None => {
                self.known_processes.insert(
                    identity_key.clone(),
                    KnownProcess {
                        identity: event.identity,
                        active: true,
                        first_seen_ms: event.observed_at_ms,
                        last_seen_ms: event.observed_at_ms,
                        last_source: event.source,
                    },
                );
            }
        }
        self.active_identity_by_pid.insert(
            self.known_processes
                .get(&identity_key)
                .map(|process| process.identity.pid)
                .unwrap_or_default(),
            identity_key,
        );
    }

    fn apply_exit(&mut self, identity_key: String, event: RuntimeProcessEvent) {
        let key = if self.known_processes.contains_key(&identity_key) {
            Some(identity_key)
        } else {
            self.active_identity_by_pid.get(&event.identity.pid).cloned()
        };

        let Some(key) = key else {
            self.counters.exit_before_create_count =
                self.counters.exit_before_create_count.saturating_add(1);
            return;
        };

        if let Some(existing) = self.known_processes.get_mut(&key) {
            if event.observed_at_ms < existing.first_seen_ms {
                self.counters.late_event_count =
                    self.counters.late_event_count.saturating_add(1);
                self.counters.out_of_order_event_count =
                    self.counters.out_of_order_event_count.saturating_add(1);
                return;
            }
            existing.active = false;
            existing.last_seen_ms = event.observed_at_ms.max(existing.last_seen_ms);
            existing.last_source = event.source;
            if self
                .active_identity_by_pid
                .get(&existing.identity.pid)
                .is_some_and(|active_key| active_key == &key)
            {
                self.active_identity_by_pid.remove(&existing.identity.pid);
            }
        }
    }

    fn health_state(&self) -> String {
        if matches!(self.runtime_state, RuntimeLifecycleState::Failed) {
            "failed".to_string()
        } else if matches!(
            self.runtime_state,
            RuntimeLifecycleState::Degraded | RuntimeLifecycleState::Recovering
        ) {
            "degraded".to_string()
        } else if self.dropped_events > 0 {
            "degraded".to_string()
        } else if self
            .producer_health
            .values()
            .any(|producer| producer.health == "healthy" || producer.health == "healthy-fallback")
        {
            "healthy".to_string()
        } else {
            "initializing".to_string()
        }
    }
}

fn is_valid_runtime_transition(
    current: &RuntimeLifecycleState,
    next: &RuntimeLifecycleState,
) -> bool {
    use RuntimeLifecycleState::{
        Degraded, Failed, Fallback, Healthy, Initializing, Recovering, ShuttingDown, Starting,
    };

    matches!(
        (current, next),
        (Initializing, Starting | Recovering | ShuttingDown)
            | (Starting, Healthy | Degraded | Fallback | Failed | Recovering | ShuttingDown)
            | (Healthy, Degraded | Recovering | Fallback | Failed | ShuttingDown)
            | (Degraded, Healthy | Recovering | Fallback | Failed | ShuttingDown)
            | (Recovering, Healthy | Degraded | Fallback | Failed | ShuttingDown)
            | (Fallback, Healthy | Degraded | Recovering | Failed | ShuttingDown)
            | (Failed, Recovering | ShuttingDown)
            | (ShuttingDown, Initializing | Starting)
    )
}

#[allow(dead_code)]
pub trait RuntimeStateProducer {
    fn start(&mut self) -> Result<(), String>;
    fn stop(&mut self);
    fn health(&self) -> ProducerHealthSnapshot;
    fn snapshot(&self) -> ProducerHealthSnapshot;
    fn recover(&mut self) -> Result<(), String>;
    fn heartbeat(&self) -> Option<u64>;
    fn emit_events(&mut self) -> Vec<RuntimeProcessEvent>;
}

#[cfg(test)]
mod tests {
    use super::{
        ProcessIdentity, ProducerHealthSnapshot, RuntimeLifecycleState, RuntimeProcessEvent,
        RuntimeProcessEventKind, RuntimeStateEngine,
    };
    use crate::models::{ProcessInfo, ProcessRemediationReport};
    use crate::process_watcher::{ProcessCreationEvent, ProcessWatcherSource};

    fn event(pid: u32, name: &str, path: &str, at: u64, still_running: bool) -> ProcessCreationEvent {
        ProcessCreationEvent {
            pid,
            name: name.to_string(),
            executable_path: Some(path.to_string()),
            creation_time_ms: Some(500),
            parent_pid: None,
            session_id: None,
            command_line: None,
            observed_at_ms: at,
            still_running,
        }
    }

    fn process(pid: u32, name: &str, path: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: name.to_string(),
            executable_path: Some(path.to_string()),
            creation_time_ms: Some(500),
            memory_mb: 0,
            categories: Vec::new(),
        }
    }

    #[test]
    fn process_identity_key_does_not_trust_pid_alone() {
        let first = ProcessIdentity {
            pid: 42,
            image_name: "obs64.exe".to_string(),
            creation_time_ms: Some(1_000),
            image_path: Some("C:\\Tools\\obs64.exe".to_string()),
            image_hash: None,
            signer: None,
            integrity_level: None,
            parent_pid: None,
            session_id: None,
            command_line: None,
        };
        let second = ProcessIdentity {
            creation_time_ms: Some(2_000),
            ..first.clone()
        };

        assert_ne!(first.key(), second.key());
    }

    #[test]
    fn merges_duplicate_process_create_events() {
        let mut engine = RuntimeStateEngine::new();
        engine.submit_process_event(
            &event(42, "obs64.exe", "C:\\Tools\\obs64.exe", 1_000, true),
            ProcessWatcherSource::Etw,
        );
        engine.submit_process_event(
            &event(42, "obs64.exe", "C:\\Tools\\obs64.exe", 1_000, true),
            ProcessWatcherSource::Wmi,
        );
        engine.drain_queue();

        let snapshot = engine.snapshot();
        assert_eq!(snapshot.process_identity_count, 1);
        assert_eq!(snapshot.active_process_count, 1);
        assert_eq!(snapshot.synchronization_state.duplicate_event_count, 1);
    }

    #[test]
    fn detects_pid_reuse_when_identity_changes() {
        let mut engine = RuntimeStateEngine::new();
        engine.submit_process_event(
            &event(42, "obs64.exe", "C:\\Tools\\obs64.exe", 1_000, true),
            ProcessWatcherSource::Etw,
        );
        engine.submit_process_event(
            &event(42, "anydesk.exe", "C:\\Tools\\anydesk.exe", 2_000, true),
            ProcessWatcherSource::Etw,
        );
        engine.drain_queue();

        let snapshot = engine.snapshot();
        assert_eq!(snapshot.process_identity_count, 2);
        assert_eq!(snapshot.active_process_count, 1);
        assert_eq!(snapshot.synchronization_state.pid_reuse_count, 1);
    }

    #[test]
    fn records_exit_before_create_without_corrupting_state() {
        let mut engine = RuntimeStateEngine::new();
        engine.submit_process_event(
            &event(42, "obs64.exe", "C:\\Tools\\obs64.exe", 1_000, false),
            ProcessWatcherSource::Etw,
        );
        engine.drain_queue();

        let snapshot = engine.snapshot();
        assert_eq!(snapshot.process_identity_count, 0);
        assert_eq!(snapshot.synchronization_state.exit_before_create_count, 1);
    }

    #[test]
    fn ignores_late_out_of_order_events() {
        let mut engine = RuntimeStateEngine::new();
        engine.submit_process_event(
            &event(42, "obs64.exe", "C:\\Tools\\obs64.exe", 2_000, true),
            ProcessWatcherSource::Etw,
        );
        engine.submit_process_event(
            &event(42, "obs64.exe", "C:\\Tools\\obs64.exe", 1_000, true),
            ProcessWatcherSource::Wmi,
        );
        engine.drain_queue();

        let snapshot = engine.snapshot();
        assert_eq!(snapshot.process_identity_count, 1);
        assert_eq!(snapshot.synchronization_state.late_event_count, 1);
        assert_eq!(snapshot.synchronization_state.out_of_order_event_count, 1);
    }

    #[test]
    fn polling_reconciliation_repairs_missing_process_state() {
        let mut engine = RuntimeStateEngine::new();
        engine.reconcile_processes(
            &[process(42, "obs64.exe", "C:\\Tools\\obs64.exe")],
            5_000,
            ProcessWatcherSource::Polling,
        );

        let snapshot = engine.snapshot();
        assert_eq!(snapshot.process_identity_count, 1);
        assert_eq!(snapshot.active_process_count, 1);
        assert_eq!(snapshot.reconciliation_count, 1);

        engine.reconcile_processes(
            &[process(42, "obs64.exe", "C:\\Tools\\obs64.exe")],
            6_000,
            ProcessWatcherSource::Polling,
        );
        assert_eq!(engine.snapshot().reconciliation_count, 1);

        engine.reconcile_processes(&[], 7_000, ProcessWatcherSource::Polling);
        let repaired_exit = engine.snapshot();
        assert_eq!(repaired_exit.active_process_count, 0);
        assert_eq!(repaired_exit.reconciliation_count, 2);
    }

    #[test]
    fn reconciliation_merges_second_precision_snapshot_with_precise_etw_creation_time() {
        let mut engine = RuntimeStateEngine::new();
        let mut created = event(42, "obs64.exe", "C:\\Tools\\obs64.exe", 10_200, true);
        created.creation_time_ms = Some(10_123);
        engine.submit_process_event(&created, ProcessWatcherSource::Etw);
        engine.drain_queue();

        let mut snapshot_process = process(42, "obs64.exe", "C:\\Tools\\obs64.exe");
        snapshot_process.creation_time_ms = Some(10_000);
        engine.reconcile_processes(
            &[snapshot_process],
            10_500,
            ProcessWatcherSource::Polling,
        );

        let snapshot = engine.snapshot();
        assert_eq!(snapshot.process_identity_count, 1);
        assert_eq!(snapshot.active_process_count, 1);
        assert_eq!(snapshot.synchronization_state.pid_reuse_count, 0);
    }

    #[test]
    fn runtime_queue_is_bounded_and_reports_overflow() {
        let mut engine = RuntimeStateEngine::with_queue_capacity(2);
        for pid in 1..=4 {
            engine.enqueue(RuntimeProcessEvent {
                kind: RuntimeProcessEventKind::ProcessCreated,
                source: ProcessWatcherSource::Etw,
                identity: ProcessIdentity::from_process_event(&event(
                    pid,
                    "obs64.exe",
                    "C:\\Tools\\obs64.exe",
                    pid as u64,
                    true,
                )),
                observed_at_ms: pid as u64,
            });
        }

        let snapshot = engine.snapshot();
        assert_eq!(snapshot.queue_state.depth, 2);
        assert_eq!(snapshot.queue_state.dropped_events, 2);
        assert_eq!(snapshot.dropped_events, 2);
    }

    #[test]
    fn runtime_state_machine_tracks_recovery_transitions() {
        let mut engine = RuntimeStateEngine::new();
        engine
            .transition(RuntimeLifecycleState::Starting)
            .expect("initializing to starting");
        engine
            .transition(RuntimeLifecycleState::Healthy)
            .expect("starting to healthy");
        engine
            .transition(RuntimeLifecycleState::Recovering)
            .expect("healthy to recovering");

        let snapshot = engine.snapshot();
        assert_eq!(snapshot.runtime_state, RuntimeLifecycleState::Recovering);
        assert_eq!(snapshot.recovery_count, 1);
    }

    #[test]
    fn rejects_invalid_runtime_state_transition() {
        let mut engine = RuntimeStateEngine::new();
        let error = engine
            .transition(RuntimeLifecycleState::Healthy)
            .expect_err("initializing cannot transition directly to healthy");

        assert!(error.contains("Initializing -> Healthy"));
        assert_eq!(
            engine.snapshot().runtime_state,
            RuntimeLifecycleState::Initializing
        );
    }

    #[test]
    fn detects_pid_reuse_for_same_image_with_new_creation_time() {
        let mut engine = RuntimeStateEngine::new();
        let mut first = event(42, "obs64.exe", "C:\\Tools\\obs64.exe", 1_000, true);
        first.creation_time_ms = Some(100);
        let mut second = event(42, "obs64.exe", "C:\\Tools\\obs64.exe", 2_000, true);
        second.creation_time_ms = Some(200);

        engine.submit_process_event(&first, ProcessWatcherSource::Etw);
        engine.submit_process_event(&second, ProcessWatcherSource::Wmi);
        engine.drain_queue();

        let snapshot = engine.snapshot();
        assert_eq!(snapshot.process_identity_count, 2);
        assert_eq!(snapshot.active_process_count, 1);
        assert_eq!(snapshot.synchronization_state.pid_reuse_count, 1);
    }

    #[test]
    fn late_exit_for_reused_pid_does_not_remove_new_active_identity() {
        let mut engine = RuntimeStateEngine::new();
        let mut first = event(42, "obs64.exe", "C:\\Tools\\obs64.exe", 1_000, true);
        first.creation_time_ms = Some(100);
        let mut second = event(42, "obs64.exe", "C:\\Tools\\obs64.exe", 2_000, true);
        second.creation_time_ms = Some(200);
        let mut old_exit = first.clone();
        old_exit.observed_at_ms = 3_000;
        old_exit.still_running = false;

        engine.submit_process_event(&first, ProcessWatcherSource::Etw);
        engine.submit_process_event(&second, ProcessWatcherSource::Etw);
        engine.submit_process_event(&old_exit, ProcessWatcherSource::Wmi);
        engine.drain_queue();

        let active = engine.active_processes();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].creation_time_ms, Some(200));
    }

    #[test]
    fn late_create_for_old_identity_does_not_replace_reused_pid() {
        let mut engine = RuntimeStateEngine::new();
        let mut first = event(42, "obs64.exe", "C:\\Tools\\obs64.exe", 1_000, true);
        first.creation_time_ms = Some(100);
        let mut second = event(42, "obs64.exe", "C:\\Tools\\obs64.exe", 2_000, true);
        second.creation_time_ms = Some(200);
        let mut delayed_first = first.clone();
        delayed_first.observed_at_ms = 3_000;

        engine.submit_process_event(&first, ProcessWatcherSource::Etw);
        engine.submit_process_event(&second, ProcessWatcherSource::Etw);
        engine.submit_process_event(&delayed_first, ProcessWatcherSource::Wmi);
        engine.drain_queue();

        let active = engine.active_processes();
        let snapshot = engine.snapshot();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].creation_time_ms, Some(200));
        assert_eq!(snapshot.synchronization_state.late_event_count, 1);
        assert_eq!(snapshot.synchronization_state.out_of_order_event_count, 1);
    }

    #[test]
    fn producer_restart_replaces_health_snapshot_without_duplicate_state() {
        let mut engine = RuntimeStateEngine::new();
        engine.update_producer_snapshot(ProducerHealthSnapshot {
            source: ProcessWatcherSource::Etw,
            health: "recovering".to_string(),
            heartbeat_at_ms: Some(1_000),
            last_event_time_ms: Some(900),
            events_lost: 1,
            buffers_lost: 1,
            realtime_buffers_lost: 1,
            queue_depth: 4,
            dropped_events: 1,
            callback_latency_micros: 50,
            producer_restart_count: 0,
            parse_error_count: 1,
        });
        engine.update_producer_snapshot(ProducerHealthSnapshot {
            source: ProcessWatcherSource::Etw,
            health: "healthy".to_string(),
            heartbeat_at_ms: Some(2_000),
            last_event_time_ms: Some(1_950),
            events_lost: 0,
            buffers_lost: 0,
            realtime_buffers_lost: 0,
            queue_depth: 0,
            dropped_events: 0,
            callback_latency_micros: 10,
            producer_restart_count: 1,
            parse_error_count: 0,
        });

        let snapshot = engine.snapshot();
        assert_eq!(snapshot.producer_state.len(), 1);
        assert_eq!(snapshot.producer_state["Etw"].health, "healthy");
        assert_eq!(snapshot.producer_state["Etw"].heartbeat_at_ms, Some(2_000));
    }

    #[test]
    fn remediation_status_is_owned_by_runtime_state_engine() {
        let mut engine = RuntimeStateEngine::new();
        engine.record_remediation(&ProcessRemediationReport {
            grace_period_ms: 0,
            pending_termination_count: 0,
            terminated_count: 0,
            failed_count: 1,
            actions: Vec::new(),
        });

        assert_eq!(engine.snapshot().remediation_status, "failed");
    }

    #[test]
    fn new_exam_session_clears_previous_runtime_state() {
        let mut engine = RuntimeStateEngine::new();
        engine.submit_process_event(
            &event(42, "obs64.exe", "C:\\Tools\\obs64.exe", 1_000, true),
            ProcessWatcherSource::Etw,
        );
        engine.drain_queue();
        engine.record_remediation(&ProcessRemediationReport {
            grace_period_ms: 0,
            pending_termination_count: 0,
            terminated_count: 0,
            failed_count: 1,
            actions: Vec::new(),
        });

        engine.reset_session_data();

        let snapshot = engine.snapshot();
        assert_eq!(snapshot.process_identity_count, 0);
        assert_eq!(snapshot.active_process_count, 0);
        assert_eq!(snapshot.remediation_status, "idle");
        assert_eq!(snapshot.reconciliation_count, 0);
        assert_eq!(snapshot.dropped_events, 0);
    }
}
