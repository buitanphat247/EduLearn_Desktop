use crate::collectors::read_executable_identity;
use crate::etw_producer::EtwProcessProducer;
use crate::models::ProcessInfo;
use crate::policy_model::ExamPolicy;
use crate::process_policy::is_process_prohibited_with_identity;
use crate::runtime_state_engine::{
    ProcessIdentity, ProducerHealthSnapshot, RuntimeProcessEvent, RuntimeProcessEventKind,
    RuntimeStateProducer,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
#[cfg(test)]
use std::collections::BTreeSet;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_DEBOUNCE_MS: u64 = 500;
const DEBOUNCE_RETENTION_MS: u64 = 60_000;
const MAX_DEBOUNCE_ENTRIES: usize = 4_096;
const DEFAULT_PRODUCER_INTERVAL_MS: u64 = 250;
const DEFAULT_PRODUCER_RECOVERY_INTERVAL_MS: u64 = 1_000;
const MAX_PRODUCER_RECOVERY_INTERVAL_MS: u64 = 60_000;
#[cfg(test)]
const MAX_PRODUCER_QUEUE: usize = 512;
const MAX_DRAINED_EVENTS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessCreationEvent {
    pub pid: u32,
    pub name: String,
    pub executable_path: Option<String>,
    #[serde(default)]
    pub creation_time_ms: Option<u64>,
    #[serde(default)]
    pub parent_pid: Option<u32>,
    #[serde(default)]
    pub session_id: Option<u32>,
    #[serde(default)]
    pub command_line: Option<String>,
    pub observed_at_ms: u64,
    pub still_running: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProcessWatcherSource {
    Polling,
    Wmi,
    Etw,
    Service,
}

impl Default for ProcessWatcherSource {
    fn default() -> Self {
        Self::Polling
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessWatcherProducerCapabilities {
    pub etw_available: bool,
    pub wmi_available: bool,
    pub service_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessWatcherUnavailableProducer {
    pub source: ProcessWatcherSource,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessWatcherProducerStatus {
    pub selected_source: ProcessWatcherSource,
    pub event_driven: bool,
    pub fallback_reason: Option<String>,
    pub health: String,
    pub producer_state: String,
    pub fallback_active: bool,
    pub heartbeat_at_ms: Option<u64>,
    pub active_since_ms: Option<u64>,
    pub failure_count: u64,
    pub recovery_attempt_count: u64,
    pub retry_count: u64,
    pub queue_depth: usize,
    pub drained_event_count: usize,
    pub dropped_event_count: usize,
    pub producer_latency_ms: u64,
    pub events_lost_count: usize,
    pub buffers_lost_count: usize,
    pub realtime_buffers_lost_count: usize,
    pub callback_latency_micros: u64,
    pub producer_restart_count: u64,
    pub parse_error_count: usize,
    pub last_failure: Option<String>,
    pub unavailable_producers: Vec<ProcessWatcherUnavailableProducer>,
}

pub fn select_process_watcher_producer(
    capabilities: &ProcessWatcherProducerCapabilities,
) -> ProcessWatcherProducerStatus {
    let unavailable_producers = unavailable_producers(capabilities);
    if capabilities.etw_available {
        return ProcessWatcherProducerStatus {
            selected_source: ProcessWatcherSource::Etw,
            event_driven: true,
            fallback_reason: None,
            health: "healthy".to_string(),
            producer_state: "active".to_string(),
            fallback_active: false,
            heartbeat_at_ms: None,
            active_since_ms: None,
            failure_count: 0,
            recovery_attempt_count: 0,
            retry_count: 0,
            queue_depth: 0,
            drained_event_count: 0,
            dropped_event_count: 0,
            producer_latency_ms: 0,
            events_lost_count: 0,
            buffers_lost_count: 0,
            realtime_buffers_lost_count: 0,
            callback_latency_micros: 0,
            producer_restart_count: 0,
            parse_error_count: 0,
            last_failure: None,
            unavailable_producers,
        };
    }
    if capabilities.wmi_available {
        return ProcessWatcherProducerStatus {
            selected_source: ProcessWatcherSource::Wmi,
            event_driven: true,
            fallback_reason: Some("ETW process provider is unavailable; WMI process-start events are selected.".to_string()),
            health: "healthy".to_string(),
            producer_state: "active".to_string(),
            fallback_active: true,
            heartbeat_at_ms: None,
            active_since_ms: None,
            failure_count: 0,
            recovery_attempt_count: 0,
            retry_count: 0,
            queue_depth: 0,
            drained_event_count: 0,
            dropped_event_count: 0,
            producer_latency_ms: 0,
            events_lost_count: 0,
            buffers_lost_count: 0,
            realtime_buffers_lost_count: 0,
            callback_latency_micros: 0,
            producer_restart_count: 0,
            parse_error_count: 0,
            last_failure: None,
            unavailable_producers,
        };
    }
    if capabilities.service_available {
        return ProcessWatcherProducerStatus {
            selected_source: ProcessWatcherSource::Service,
            event_driven: true,
            fallback_reason: Some("Local ETW/WMI producer is unavailable; elevated service process events are selected.".to_string()),
            health: "healthy".to_string(),
            producer_state: "active".to_string(),
            fallback_active: true,
            heartbeat_at_ms: None,
            active_since_ms: None,
            failure_count: 0,
            recovery_attempt_count: 0,
            retry_count: 0,
            queue_depth: 0,
            drained_event_count: 0,
            dropped_event_count: 0,
            producer_latency_ms: 0,
            events_lost_count: 0,
            buffers_lost_count: 0,
            realtime_buffers_lost_count: 0,
            callback_latency_micros: 0,
            producer_restart_count: 0,
            parse_error_count: 0,
            last_failure: None,
            unavailable_producers,
        };
    }

    ProcessWatcherProducerStatus {
        selected_source: ProcessWatcherSource::Polling,
        event_driven: false,
        fallback_reason: Some(
            "No native process event producer is available; runtime polling remains the fallback."
                .to_string(),
        ),
        health: "fallback".to_string(),
        producer_state: "fallback".to_string(),
        fallback_active: true,
        heartbeat_at_ms: None,
        active_since_ms: None,
        failure_count: 0,
        recovery_attempt_count: 0,
        retry_count: 0,
        queue_depth: 0,
        drained_event_count: 0,
        dropped_event_count: 0,
        producer_latency_ms: 0,
        events_lost_count: 0,
        buffers_lost_count: 0,
        realtime_buffers_lost_count: 0,
        callback_latency_micros: 0,
        producer_restart_count: 0,
        parse_error_count: 0,
        last_failure: None,
        unavailable_producers,
    }
}

fn unavailable_producers(
    capabilities: &ProcessWatcherProducerCapabilities,
) -> Vec<ProcessWatcherUnavailableProducer> {
    let mut unavailable = Vec::new();
    if !capabilities.etw_available {
        unavailable.push(ProcessWatcherUnavailableProducer {
            source: ProcessWatcherSource::Etw,
            reason: "ETW process provider is not enabled in this build/runtime."
                .to_string(),
        });
    }
    if !capabilities.wmi_available {
        unavailable.push(ProcessWatcherUnavailableProducer {
            source: ProcessWatcherSource::Wmi,
            reason: "WMI process-start producer is not enabled in this build/runtime."
                .to_string(),
        });
    }
    if !capabilities.service_available {
        unavailable.push(ProcessWatcherUnavailableProducer {
            source: ProcessWatcherSource::Service,
            reason: "Elevated service process-event producer is not connected."
                .to_string(),
        });
    }
    unavailable
}

#[allow(dead_code)]
pub trait ProcessEventProducer {
    fn source(&self) -> ProcessWatcherSource;
    fn is_event_driven(&self) -> bool;
    fn status(&self) -> ProcessWatcherProducerStatus;
}

fn update_status_runtime_fields(
    status: &mut ProcessWatcherProducerStatus,
    heartbeat_at_ms: Option<u64>,
    active_since_ms: Option<u64>,
    queue_depth: usize,
    drained_event_count: usize,
    dropped_event_count: usize,
    producer_latency_ms: u64,
) {
    status.heartbeat_at_ms = heartbeat_at_ms;
    status.active_since_ms = active_since_ms;
    status.queue_depth = queue_depth;
    status.drained_event_count = drained_event_count;
    status.dropped_event_count = dropped_event_count;
    status.producer_latency_ms = producer_latency_ms;
    if heartbeat_at_ms.is_some()
        && matches!(status.health.as_str(), "fallback" | "starting-fallback")
    {
        status.health = "healthy-fallback".to_string();
    }
}

#[cfg(test)]
pub fn default_process_watcher_producer_status() -> ProcessWatcherProducerStatus {
    // Phase 1 keeps the background diff producer as the safe default. It is
    // intentionally separate from the runtime tick so process-event collection
    // does not block command handling. ETW/WMI/service producers can be dropped
    // behind the same status/event contract in later native evidence phases.
    select_process_watcher_producer(&ProcessWatcherProducerCapabilities {
        etw_available: false,
        wmi_available: false,
        service_available: false,
    })
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessSnapshot {
    pid: u32,
    name: String,
    executable_path: Option<String>,
    creation_time_ms: Option<u64>,
}

#[cfg(test)]
fn detect_process_delta(
    known: &mut BTreeMap<u32, ProcessSnapshot>,
    current: Vec<ProcessSnapshot>,
    observed_at_ms: u64,
) -> Vec<ProcessCreationEvent> {
    let mut events = Vec::new();
    let current_pids = current
        .iter()
        .map(|process| process.pid)
        .collect::<BTreeSet<_>>();

    for process in current {
        let replaced = known.get(&process.pid).is_some_and(|previous| {
            previous.creation_time_ms != process.creation_time_ms
                || !previous.name.eq_ignore_ascii_case(&process.name)
                || previous.executable_path.as_ref().map(|path| path.to_ascii_lowercase())
                    != process
                        .executable_path
                        .as_ref()
                        .map(|path| path.to_ascii_lowercase())
        });
        if replaced {
            if let Some(previous) = known.get(&process.pid) {
                events.push(ProcessCreationEvent {
                    pid: previous.pid,
                    name: previous.name.clone(),
                    executable_path: previous.executable_path.clone(),
                    creation_time_ms: previous.creation_time_ms,
                    parent_pid: None,
                    session_id: None,
                    command_line: None,
                    observed_at_ms,
                    still_running: false,
                });
            }
        }
        if !known.contains_key(&process.pid) || replaced {
            events.push(ProcessCreationEvent {
                pid: process.pid,
                name: process.name.clone(),
                executable_path: process.executable_path.clone(),
                creation_time_ms: process.creation_time_ms,
                parent_pid: None,
                session_id: None,
                command_line: None,
                observed_at_ms,
                still_running: true,
            });
        }
        known.insert(process.pid, process);
    }

    let exited_pids = known
        .keys()
        .filter(|pid| !current_pids.contains(pid))
        .copied()
        .collect::<Vec<_>>();
    for pid in exited_pids {
        if let Some(process) = known.remove(&pid) {
            events.push(ProcessCreationEvent {
                pid,
                name: process.name,
                executable_path: process.executable_path,
                creation_time_ms: process.creation_time_ms,
                parent_pid: None,
                session_id: None,
                command_line: None,
                observed_at_ms,
                still_running: false,
            });
        }
    }

    events
}

pub struct RuntimeProcessWatcherProducer {
    status: ProcessWatcherProducerStatus,
    running: Arc<AtomicBool>,
    queue: Arc<Mutex<VecDeque<ProcessCreationEvent>>>,
    heartbeat_at_ms: Arc<Mutex<Option<u64>>>,
    dropped_event_count: Arc<Mutex<usize>>,
    handle: Option<JoinHandle<()>>,
    interval_ms: u64,
    recovery_interval_ms: u64,
    active_since_ms: Option<u64>,
    last_recovery_attempt_ms: Option<u64>,
    drained_event_count: usize,
    producer_latency_ms: u64,
    etw_producer: Option<EtwProcessProducer>,
    producer_restart_count: u64,
}

impl fmt::Debug for RuntimeProcessWatcherProducer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeProcessWatcherProducer")
            .field("status", &self.status())
            .field("running", &self.running.load(Ordering::SeqCst))
            .field("interval_ms", &self.interval_ms)
            .field("recovery_interval_ms", &self.recovery_interval_ms)
            .field("producer_restart_count", &self.producer_restart_count)
            .finish()
    }
}

impl Default for RuntimeProcessWatcherProducer {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeProcessWatcherProducer {
    pub fn new() -> Self {
        Self {
            status: ProcessWatcherProducerStatus {
                selected_source: ProcessWatcherSource::Polling,
                event_driven: false,
                fallback_reason: Some(
                    "Runtime producer manager is stopped; polling reconciliation is inactive."
                        .to_string(),
                ),
                health: "stopped".to_string(),
                producer_state: "stopped".to_string(),
                fallback_active: true,
                heartbeat_at_ms: None,
                active_since_ms: None,
                failure_count: 0,
                recovery_attempt_count: 0,
                retry_count: 0,
                queue_depth: 0,
                drained_event_count: 0,
                dropped_event_count: 0,
                producer_latency_ms: 0,
                events_lost_count: 0,
                buffers_lost_count: 0,
                realtime_buffers_lost_count: 0,
                callback_latency_micros: 0,
                producer_restart_count: 0,
                parse_error_count: 0,
                last_failure: None,
                unavailable_producers: unavailable_producers(
                    &ProcessWatcherProducerCapabilities {
                        etw_available: false,
                        wmi_available: false,
                        service_available: false,
                    },
                ),
            },
            running: Arc::new(AtomicBool::new(false)),
            queue: Arc::new(Mutex::new(VecDeque::new())),
            heartbeat_at_ms: Arc::new(Mutex::new(None)),
            dropped_event_count: Arc::new(Mutex::new(0)),
            handle: None,
            interval_ms: DEFAULT_PRODUCER_INTERVAL_MS,
            recovery_interval_ms: DEFAULT_PRODUCER_RECOVERY_INTERVAL_MS,
            active_since_ms: None,
            last_recovery_attempt_ms: None,
            drained_event_count: 0,
            producer_latency_ms: 0,
            etw_producer: None,
            producer_restart_count: 0,
        }
    }

    #[allow(dead_code)]
    pub fn start_polling(&mut self, now_ms: impl Fn() -> u64 + Send + 'static + Copy) {
        self.start_hybrid(now_ms);
    }

    pub fn start_hybrid(&mut self, now_ms: impl Fn() -> u64 + Send + 'static + Copy) {
        if self.running.load(Ordering::SeqCst) {
            return;
        }

        let started_at_ms = now_ms();
        self.running.store(true, Ordering::SeqCst);
        if let Ok(mut heartbeat) = self.heartbeat_at_ms.lock() {
            *heartbeat = Some(started_at_ms);
        }
        self.active_since_ms = Some(started_at_ms);
        match start_etw_producer(
            Arc::clone(&self.queue),
            Arc::clone(&self.dropped_event_count),
            self.producer_restart_count,
        ) {
            Ok(etw_producer) => {
                self.etw_producer = Some(etw_producer);
                self.recovery_interval_ms = DEFAULT_PRODUCER_RECOVERY_INTERVAL_MS;
                self.last_recovery_attempt_ms = None;
                self.status = select_process_watcher_producer(
                    &ProcessWatcherProducerCapabilities {
                        etw_available: true,
                        wmi_available: false,
                        service_available: false,
                    },
                );
                self.status.active_since_ms = self.active_since_ms;
                self.refresh_etw_status();
            }
            Err(error) => {
                self.apply_polling_fallback(error, false);
            }
        }

        let running = Arc::clone(&self.running);
        let heartbeat = Arc::clone(&self.heartbeat_at_ms);
        let interval = Duration::from_millis(self.interval_ms);

        self.handle = Some(thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                thread::sleep(interval);
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                let observed_at_ms = now_ms();
                if let Ok(mut heartbeat) = heartbeat.lock() {
                    *heartbeat = Some(observed_at_ms);
                }
            }
        }));
    }

    pub fn recover_if_due(&mut self, now_ms: u64) {
        if !self.running.load(Ordering::SeqCst) {
            return;
        }

        let etw_failed = self.etw_producer.as_ref().is_some_and(|producer| {
            let health = producer.health();
            !producer.is_running() || health.health == "unavailable"
        });
        if matches!(self.status.selected_source, ProcessWatcherSource::Etw) && !etw_failed {
            self.refresh_etw_status();
            return;
        }
        if etw_failed {
            if let Some(mut producer) = self.etw_producer.take() {
                let failure = producer
                    .health()
                    .last_failure
                    .unwrap_or_else(|| "ETW producer stopped unexpectedly.".to_string());
                producer.stop();
                self.apply_polling_fallback(failure, true);
            }
        }

        if self
            .last_recovery_attempt_ms
            .is_some_and(|last| now_ms.saturating_sub(last) < self.recovery_interval_ms)
        {
            return;
        }

        self.last_recovery_attempt_ms = Some(now_ms);
        self.status.retry_count = self.status.retry_count.saturating_add(1);
        self.status.recovery_attempt_count =
            self.status.recovery_attempt_count.saturating_add(1);
        self.status.producer_state = "fallback-retry".to_string();
        let retry_count = self.status.retry_count;
        let recovery_attempt_count = self.status.recovery_attempt_count;
        let failure_count = self.status.failure_count;

        match start_etw_producer(
            Arc::clone(&self.queue),
            Arc::clone(&self.dropped_event_count),
            self.producer_restart_count.saturating_add(1),
        ) {
            Ok(etw_producer) => {
                self.producer_restart_count = self.producer_restart_count.saturating_add(1);
                self.etw_producer = Some(etw_producer);
                self.recovery_interval_ms = DEFAULT_PRODUCER_RECOVERY_INTERVAL_MS;
                self.last_recovery_attempt_ms = None;
                self.status = select_process_watcher_producer(
                    &ProcessWatcherProducerCapabilities {
                        etw_available: true,
                        wmi_available: false,
                        service_available: false,
                    },
                );
                self.status.active_since_ms = Some(now_ms);
                self.status.retry_count = retry_count;
                self.status.recovery_attempt_count = recovery_attempt_count;
                self.status.failure_count = failure_count;
                self.refresh_etw_status();
            }
            Err(error) => {
                self.apply_polling_fallback(error, true);
                self.recovery_interval_ms = self
                    .recovery_interval_ms
                    .saturating_mul(2)
                    .min(MAX_PRODUCER_RECOVERY_INTERVAL_MS);
            }
        }
    }

    fn refresh_etw_status(&mut self) {
        let Some(producer) = self.etw_producer.as_ref() else {
            return;
        };
        apply_etw_health_to_status(
            &mut self.status,
            producer,
            producer.output_queue_depth(),
        );
    }

    fn apply_polling_fallback(&mut self, etw_error: String, recovery: bool) {
        let mut unavailable_producers = unavailable_producers(
            &ProcessWatcherProducerCapabilities {
                etw_available: false,
                wmi_available: false,
                service_available: false,
            },
        );
        if let Some(etw) = unavailable_producers
            .iter_mut()
            .find(|producer| producer.source == ProcessWatcherSource::Etw)
        {
            etw.reason = etw_error.clone();
        }
        let fallback = select_process_watcher_producer(
            &ProcessWatcherProducerCapabilities {
                etw_available: false,
                wmi_available: false,
                service_available: false,
            },
        );
        let retry_count = self.status.retry_count;
        let recovery_attempt_count = self.status.recovery_attempt_count;
        let failure_count = self.status.failure_count.saturating_add(1);
        self.status = ProcessWatcherProducerStatus {
            fallback_reason: fallback_reason_from_unavailable(&unavailable_producers),
            health: "healthy-fallback".to_string(),
            producer_state: if recovery {
                "fallback-retry".to_string()
            } else {
                "fallback".to_string()
            },
            active_since_ms: self.active_since_ms,
            failure_count,
            retry_count,
            recovery_attempt_count,
            last_failure: Some(etw_error),
            unavailable_producers,
            ..fallback
        };
    }

    pub fn drain_events(&mut self) -> Vec<ProcessCreationEvent> {
        self.drain_events_at(runtime_now_ms())
    }

    fn drain_events_at(&mut self, drained_at_ms: u64) -> Vec<ProcessCreationEvent> {
        let Ok(mut queue) = self.queue.lock() else {
            return Vec::new();
        };
        let count = queue.len().min(MAX_DRAINED_EVENTS);
        let drained = queue.drain(..count).collect::<Vec<_>>();
        self.drained_event_count = self.drained_event_count.saturating_add(drained.len());
        if let Some(latency) = drained
            .iter()
            .map(|event| drained_at_ms.saturating_sub(event.observed_at_ms))
            .max()
        {
            self.producer_latency_ms = latency;
        }
        let queue_depth = queue.len();
        drop(queue);
        if self.etw_producer.is_some() {
            self.refresh_etw_status();
            self.status.queue_depth = queue_depth;
            self.status.drained_event_count = self.drained_event_count;
            self.status.producer_latency_ms = self.producer_latency_ms;
        } else {
            update_status_runtime_fields(
                &mut self.status,
                self.heartbeat_at_ms.lock().ok().and_then(|value| *value),
                self.active_since_ms,
                queue_depth,
                self.drained_event_count,
                self.dropped_event_count.lock().map(|value| *value).unwrap_or(0),
                self.producer_latency_ms,
            );
        }
        drained
    }

    pub fn status(&self) -> ProcessWatcherProducerStatus {
        let queue_depth = self.queue.lock().map(|queue| queue.len()).unwrap_or(0);
        let mut status = self.status.clone();
        if let Some(producer) = self.etw_producer.as_ref() {
            apply_etw_health_to_status(&mut status, producer, queue_depth);
            status.drained_event_count = self.drained_event_count;
            status.producer_latency_ms = self.producer_latency_ms;
        } else {
            update_status_runtime_fields(
                &mut status,
                self.heartbeat_at_ms.lock().ok().and_then(|value| *value),
                self.active_since_ms,
                queue_depth,
                self.drained_event_count,
                self.dropped_event_count.lock().map(|value| *value).unwrap_or(0),
                self.producer_latency_ms,
            );
        }
        status
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn push_event_for_test(&mut self, event: ProcessCreationEvent) {
        if let Ok(mut queue) = self.queue.lock() {
            if queue.len() >= MAX_PRODUCER_QUEUE {
                queue.pop_front();
                if let Ok(mut dropped) = self.dropped_event_count.lock() {
                    *dropped = dropped.saturating_add(1);
                }
            }
            queue.push_back(event);
        }
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(mut etw_producer) = self.etw_producer.take() {
            etw_producer.stop();
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if let Ok(mut queue) = self.queue.lock() {
            queue.clear();
        }
        self.status = ProcessWatcherProducerStatus {
            selected_source: ProcessWatcherSource::Polling,
            event_driven: false,
            fallback_reason: Some("Polling reconciliation heartbeat is stopped.".to_string()),
            health: "stopped".to_string(),
            producer_state: "stopped".to_string(),
            fallback_active: true,
            heartbeat_at_ms: None,
            active_since_ms: None,
            failure_count: 0,
            recovery_attempt_count: self.status.recovery_attempt_count,
            retry_count: self.status.retry_count,
            queue_depth: 0,
            drained_event_count: self.drained_event_count,
            dropped_event_count: self.dropped_event_count.lock().map(|value| *value).unwrap_or(0),
            producer_latency_ms: self.producer_latency_ms,
            events_lost_count: self.status.events_lost_count,
            buffers_lost_count: self.status.buffers_lost_count,
            realtime_buffers_lost_count: self.status.realtime_buffers_lost_count,
            callback_latency_micros: self.status.callback_latency_micros,
            producer_restart_count: self.status.producer_restart_count,
            parse_error_count: self.status.parse_error_count,
            last_failure: None,
            unavailable_producers: unavailable_producers(
                &ProcessWatcherProducerCapabilities {
                    etw_available: false,
                    wmi_available: false,
                    service_available: false,
                },
            ),
        };
        if let Ok(mut heartbeat) = self.heartbeat_at_ms.lock() {
            *heartbeat = None;
        }
        self.active_since_ms = None;
    }
}

fn fallback_reason_from_unavailable(
    unavailable_producers: &[ProcessWatcherUnavailableProducer],
) -> Option<String> {
    if unavailable_producers.is_empty() {
        return None;
    }
    Some(format!(
        "Native process producers unavailable ({}); using bounded runtime polling reconciliation.",
        unavailable_producers
            .iter()
            .map(|producer| format!("{:?}: {}", producer.source, producer.reason))
            .collect::<Vec<_>>()
            .join("; ")
    ))
}

fn start_etw_producer(
    queue: Arc<Mutex<VecDeque<ProcessCreationEvent>>>,
    dropped_event_count: Arc<Mutex<usize>>,
    producer_restart_count: u64,
) -> Result<EtwProcessProducer, String> {
    #[cfg(test)]
    if std::env::var("EDULEARN_RUN_NATIVE_ETW_TEST").ok().as_deref() != Some("1") {
        return Err("Native ETW startup is disabled for deterministic unit tests.".to_string());
    }

    EtwProcessProducer::start(queue, dropped_event_count, producer_restart_count)
}

fn apply_etw_health_to_status(
    status: &mut ProcessWatcherProducerStatus,
    producer: &EtwProcessProducer,
    queue_depth: usize,
) {
    let health = producer.health();
    status.selected_source = ProcessWatcherSource::Etw;
    status.event_driven = true;
    status.fallback_active = false;
    status.fallback_reason = None;
    status.health = health.health.clone();
    status.producer_state = match health.health.as_str() {
        "healthy" => "active",
        "degraded" => "degraded",
        _ => "recovering",
    }
    .to_string();
    status.heartbeat_at_ms = health.heartbeat_at_ms;
    status.queue_depth = queue_depth;
    status.dropped_event_count = health.dropped_events;
    status.events_lost_count = health.events_lost;
    status.buffers_lost_count = health.buffers_lost;
    status.realtime_buffers_lost_count = health.realtime_buffers_lost;
    status.callback_latency_micros = health.callback_latency_micros;
    status.producer_restart_count = health.producer_restart_count;
    status.parse_error_count = health.parse_error_count;
    status.last_failure = health.last_failure;
}

impl ProcessEventProducer for RuntimeProcessWatcherProducer {
    fn source(&self) -> ProcessWatcherSource {
        self.status().selected_source
    }

    fn is_event_driven(&self) -> bool {
        self.status().event_driven
    }

    fn status(&self) -> ProcessWatcherProducerStatus {
        RuntimeProcessWatcherProducer::status(self)
    }
}

impl RuntimeStateProducer for RuntimeProcessWatcherProducer {
    fn start(&mut self) -> Result<(), String> {
        self.start_hybrid(runtime_now_ms);
        Ok(())
    }

    fn stop(&mut self) {
        RuntimeProcessWatcherProducer::stop(self);
    }

    fn health(&self) -> ProducerHealthSnapshot {
        let status = self.status();
        ProducerHealthSnapshot {
            source: status.selected_source,
            health: status.health,
            heartbeat_at_ms: status.heartbeat_at_ms,
            last_event_time_ms: status.heartbeat_at_ms,
            events_lost: status.events_lost_count,
            buffers_lost: status.buffers_lost_count,
            realtime_buffers_lost: status.realtime_buffers_lost_count,
            queue_depth: status.queue_depth,
            dropped_events: status.dropped_event_count,
            callback_latency_micros: status.callback_latency_micros,
            producer_restart_count: status.producer_restart_count,
            parse_error_count: status.parse_error_count,
        }
    }

    fn snapshot(&self) -> ProducerHealthSnapshot {
        self.health()
    }

    fn recover(&mut self) -> Result<(), String> {
        if !self.is_running() {
            return Err("Process producer is not running.".to_string());
        }
        self.recover_if_due(runtime_now_ms());
        Ok(())
    }

    fn heartbeat(&self) -> Option<u64> {
        self.status().heartbeat_at_ms
    }

    fn emit_events(&mut self) -> Vec<RuntimeProcessEvent> {
        let source = self.status().selected_source;
        self.drain_events()
            .into_iter()
            .map(|event| RuntimeProcessEvent {
                kind: if event.still_running {
                    RuntimeProcessEventKind::ProcessCreated
                } else {
                    RuntimeProcessEventKind::ProcessExited
                },
                source: source.clone(),
                identity: ProcessIdentity::from_process_event(&event),
                observed_at_ms: event.observed_at_ms,
            })
            .collect()
    }
}

fn runtime_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl Drop for RuntimeProcessWatcherProducer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessWatcherBatch {
    pub source: ProcessWatcherSource,
    #[serde(default)]
    pub events: Vec<ProcessCreationEvent>,
    pub collected_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessWatcherBatchReport {
    pub source: ProcessWatcherSource,
    pub event_count: usize,
    pub remediation_count: usize,
    pub ignored_count: usize,
    pub max_detection_latency_ms: u64,
    pub ignored_reasons: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum ProcessWatcherDecision {
    Ignored { reason: String },
    Remediate(ProcessInfo),
}

#[derive(Debug, Default)]
pub struct ProcessCreationWatcher {
    debounce_ms: u64,
    last_seen_by_identity: BTreeMap<String, u64>,
    active_identity_by_pid: BTreeMap<u32, String>,
}

impl ProcessCreationWatcher {
    pub fn new() -> Self {
        Self {
            debounce_ms: DEFAULT_DEBOUNCE_MS,
            last_seen_by_identity: BTreeMap::new(),
            active_identity_by_pid: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    pub fn with_debounce_ms(debounce_ms: u64) -> Self {
        Self {
            debounce_ms,
            last_seen_by_identity: BTreeMap::new(),
            active_identity_by_pid: BTreeMap::new(),
        }
    }

    pub fn evaluate_event(
        &mut self,
        event: ProcessCreationEvent,
        policy: &ExamPolicy,
    ) -> ProcessWatcherDecision {
        if event.pid == 0 {
            return ProcessWatcherDecision::Ignored {
                reason: "pid-zero".to_string(),
            };
        }
        self.last_seen_by_identity.retain(|_, last_seen| {
            event.observed_at_ms.saturating_sub(*last_seen) <= DEBOUNCE_RETENTION_MS
        });
        self.active_identity_by_pid.retain(|_, identity_key| {
            self.last_seen_by_identity.contains_key(identity_key)
        });
        let identity_key = process_event_identity_key(&event);
        if !event.still_running {
            self.last_seen_by_identity.remove(&identity_key);
            if let Some(active_key) = self.active_identity_by_pid.remove(&event.pid) {
                self.last_seen_by_identity.remove(&active_key);
            }
            return ProcessWatcherDecision::Ignored {
                reason: "process-exited-before-classification".to_string(),
            };
        }
        if let Some(last_seen) = self.last_seen_by_identity.get(&identity_key) {
            if event.observed_at_ms >= *last_seen
                && event.observed_at_ms.saturating_sub(*last_seen) < self.debounce_ms
            {
                return ProcessWatcherDecision::Ignored {
                    reason: "duplicate-process-create-event".to_string(),
                };
            }
        }
        if let Some(previous_key) = self
            .active_identity_by_pid
            .insert(event.pid, identity_key.clone())
        {
            if previous_key != identity_key {
                self.last_seen_by_identity.remove(&previous_key);
            }
        }
        self.last_seen_by_identity
            .insert(identity_key, event.observed_at_ms);
        while self.last_seen_by_identity.len() > MAX_DEBOUNCE_ENTRIES {
            let Some(oldest_key) = self
                .last_seen_by_identity
                .iter()
                .min_by_key(|(_, observed_at_ms)| **observed_at_ms)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.last_seen_by_identity.remove(&oldest_key);
            self.active_identity_by_pid
                .retain(|_, identity_key| identity_key != &oldest_key);
        }

        let identity = event
            .executable_path
            .as_deref()
            .and_then(read_executable_identity);
        if is_process_prohibited_with_identity(&event.name, identity.as_ref(), policy) {
            return ProcessWatcherDecision::Remediate(ProcessInfo {
                pid: event.pid,
                name: event.name,
                executable_path: event.executable_path,
                creation_time_ms: event.creation_time_ms,
                memory_mb: 0,
                categories: vec!["processWatcher".to_string()],
                identity,
            });
        }

        ProcessWatcherDecision::Ignored {
            reason: "process-not-prohibited-by-policy".to_string(),
        }
    }

    pub fn evaluate_batch(
        &mut self,
        batch: ProcessWatcherBatch,
        policy: &ExamPolicy,
    ) -> (ProcessWatcherBatchReport, Vec<ProcessInfo>) {
        let mut remediation = Vec::new();
        let mut ignored_count = 0;
        let mut ignored_reasons = Vec::new();
        let mut max_detection_latency_ms = 0;
        let event_count = batch.events.len();

        for event in batch.events {
            max_detection_latency_ms = max_detection_latency_ms.max(
                batch.collected_at_ms.saturating_sub(event.observed_at_ms),
            );
            match self.evaluate_event(event, policy) {
                ProcessWatcherDecision::Remediate(process) => remediation.push(process),
                ProcessWatcherDecision::Ignored { reason } => {
                    ignored_count += 1;
                    ignored_reasons.push(reason);
                }
            }
        }

        (
            ProcessWatcherBatchReport {
                source: batch.source,
                event_count,
                remediation_count: remediation.len(),
                ignored_count,
                max_detection_latency_ms,
                ignored_reasons,
            },
            remediation,
        )
    }
}

fn process_event_identity_key(event: &ProcessCreationEvent) -> String {
    format!(
        "{}|{}|{}|{}",
        event.pid,
        event
            .creation_time_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        event.name.to_ascii_lowercase(),
        event
            .executable_path
            .as_deref()
            .unwrap_or("unknown")
            .to_ascii_lowercase()
    )
}

#[cfg(test)]
mod tests {
    use super::{
        detect_process_delta, ProcessCreationEvent, ProcessCreationWatcher, ProcessSnapshot,
        ProcessWatcherBatch, ProcessWatcherDecision, ProcessWatcherSource,
    };
    use crate::policy_model::ExamPolicy;
    use crate::runtime_state_engine::RuntimeStateProducer;
    use std::collections::BTreeMap;

    fn event(pid: u32, name: &str, at: u64) -> ProcessCreationEvent {
        ProcessCreationEvent {
            pid,
            name: name.to_string(),
            executable_path: None,
            creation_time_ms: Some(500),
            parent_pid: None,
            session_id: None,
            command_line: None,
            observed_at_ms: at,
            still_running: true,
        }
    }

    #[test]
    fn classifies_policy_blocked_process_for_remediation() {
        let mut watcher = ProcessCreationWatcher::new();
        let decision = watcher.evaluate_event(event(42, "obs64.exe", 1_000), &ExamPolicy::strict_builtin());

        match decision {
            ProcessWatcherDecision::Remediate(process) => {
                assert_eq!(process.pid, 42);
                assert_eq!(process.name, "obs64.exe");
            }
            other => panic!("expected remediation, got {other:?}"),
        }
    }

    #[test]
    fn debounces_duplicate_process_creation_events() {
        let mut watcher = ProcessCreationWatcher::with_debounce_ms(500);
        assert!(matches!(
            watcher.evaluate_event(event(42, "obs64.exe", 1_000), &ExamPolicy::strict_builtin()),
            ProcessWatcherDecision::Remediate(_)
        ));
        match watcher.evaluate_event(event(42, "obs64.exe", 1_100), &ExamPolicy::strict_builtin())
        {
            ProcessWatcherDecision::Ignored { reason } => {
                assert_eq!(reason, "duplicate-process-create-event");
            }
            ProcessWatcherDecision::Remediate(_) => panic!("duplicate event should be ignored"),
        }
    }

    #[test]
    fn ignores_process_that_exited_before_classification() {
        let mut watcher = ProcessCreationWatcher::new();
        let mut event = event(42, "obs64.exe", 1_000);
        event.still_running = false;

        match watcher.evaluate_event(event, &ExamPolicy::strict_builtin()) {
            ProcessWatcherDecision::Ignored { reason } => {
                assert_eq!(reason, "process-exited-before-classification");
            }
            ProcessWatcherDecision::Remediate(_) => panic!("exited process should be ignored"),
        }
    }

    #[test]
    fn evaluates_event_batches_independent_from_watcher_source() {
        let mut watcher = ProcessCreationWatcher::new();
        let batch = ProcessWatcherBatch {
            source: ProcessWatcherSource::Wmi,
            collected_at_ms: 2_000,
            events: vec![
                event(42, "obs64.exe", 1_750),
                event(43, "notepad.exe", 1_900),
            ],
        };

        let (report, remediation) = watcher.evaluate_batch(batch, &ExamPolicy::strict_builtin());

        assert_eq!(report.source, ProcessWatcherSource::Wmi);
        assert_eq!(report.event_count, 2);
        assert_eq!(report.remediation_count, 1);
        assert_eq!(report.ignored_count, 1);
        assert_eq!(report.max_detection_latency_ms, 250);
        assert_eq!(remediation[0].name, "obs64.exe");
    }

    #[test]
    fn service_source_uses_same_policy_path_as_polling_source() {
        let mut watcher = ProcessCreationWatcher::new();
        let batch = ProcessWatcherBatch {
            source: ProcessWatcherSource::Service,
            collected_at_ms: 2_000,
            events: vec![event(99, "anydesk.exe", 1_990)],
        };

        let (report, remediation) = watcher.evaluate_batch(batch, &ExamPolicy::strict_builtin());

        assert_eq!(report.source, ProcessWatcherSource::Service);
        assert_eq!(report.max_detection_latency_ms, 10);
        assert_eq!(remediation.len(), 1);
        assert_eq!(remediation[0].pid, 99);
    }

    #[test]
    fn process_delta_emits_create_and_exit_events() {
        let mut known = BTreeMap::from([(
            10,
            ProcessSnapshot {
                pid: 10,
                name: "old.exe".to_string(),
                executable_path: None,
                creation_time_ms: Some(1_000),
            },
        )]);

        let events = detect_process_delta(
            &mut known,
            vec![ProcessSnapshot {
                pid: 20,
                name: "obs64.exe".to_string(),
                executable_path: Some("C:\\Tools\\obs64.exe".to_string()),
                creation_time_ms: Some(2_000),
            }],
            5_000,
        );

        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|event| event.pid == 20 && event.still_running));
        assert!(events.iter().any(|event| event.pid == 10 && !event.still_running));
        assert!(known.contains_key(&20));
        assert!(!known.contains_key(&10));
    }

    #[test]
    fn process_delta_detects_same_pid_reuse_from_creation_time() {
        let mut known = BTreeMap::from([(
            20,
            ProcessSnapshot {
                pid: 20,
                name: "obs64.exe".to_string(),
                executable_path: Some("C:\\Tools\\obs64.exe".to_string()),
                creation_time_ms: Some(1_000),
            },
        )]);

        let events = detect_process_delta(
            &mut known,
            vec![ProcessSnapshot {
                pid: 20,
                name: "obs64.exe".to_string(),
                executable_path: Some("C:\\Tools\\obs64.exe".to_string()),
                creation_time_ms: Some(2_000),
            }],
            5_000,
        );

        assert_eq!(events.len(), 2);
        assert!(!events[0].still_running);
        assert_eq!(events[0].creation_time_ms, Some(1_000));
        assert!(events[1].still_running);
        assert_eq!(events[1].creation_time_ms, Some(2_000));
    }

    #[test]
    fn process_exit_releases_pid_from_debounce_state() {
        let mut watcher = ProcessCreationWatcher::with_debounce_ms(500);
        assert!(matches!(
            watcher.evaluate_event(event(42, "obs64.exe", 1_000), &ExamPolicy::strict_builtin()),
            ProcessWatcherDecision::Remediate(_)
        ));

        let mut exited = event(42, "obs64.exe", 1_100);
        exited.still_running = false;
        assert!(matches!(
            watcher.evaluate_event(exited, &ExamPolicy::strict_builtin()),
            ProcessWatcherDecision::Ignored { .. }
        ));

        assert!(matches!(
            watcher.evaluate_event(event(42, "obs64.exe", 1_200), &ExamPolicy::strict_builtin()),
            ProcessWatcherDecision::Remediate(_)
        ));
    }

    #[test]
    fn debounce_state_is_bounded_during_long_process_churn() {
        let mut watcher = ProcessCreationWatcher::with_debounce_ms(0);
        for pid in 1..=5_000 {
            let _ = watcher.evaluate_event(
                event(pid, "notepad.exe", pid as u64),
                &ExamPolicy::strict_builtin(),
            );
        }

        assert!(watcher.last_seen_by_identity.len() <= super::MAX_DEBOUNCE_ENTRIES);
    }

    #[test]
    fn timestamp_regression_does_not_hide_a_reused_pid() {
        let mut watcher = ProcessCreationWatcher::with_debounce_ms(500);
        let _ = watcher.evaluate_event(
            event(42, "obs64.exe", 2_000),
            &ExamPolicy::strict_builtin(),
        );

        assert!(matches!(
            watcher.evaluate_event(event(42, "obs64.exe", 1_000), &ExamPolicy::strict_builtin()),
            ProcessWatcherDecision::Remediate(_)
        ));
    }

    #[test]
    fn selects_event_driven_producer_before_polling_fallback() {
        let etw = super::select_process_watcher_producer(
            &super::ProcessWatcherProducerCapabilities {
                etw_available: true,
                wmi_available: true,
                service_available: true,
            },
        );
        assert_eq!(etw.selected_source, ProcessWatcherSource::Etw);
        assert!(etw.event_driven);
        assert_eq!(etw.health, "healthy");
        assert!(!etw.fallback_active);

        let wmi = super::select_process_watcher_producer(
            &super::ProcessWatcherProducerCapabilities {
                etw_available: false,
                wmi_available: true,
                service_available: true,
            },
        );
        assert_eq!(wmi.selected_source, ProcessWatcherSource::Wmi);
        assert!(wmi.event_driven);
        assert!(wmi.fallback_active);

        let polling = super::default_process_watcher_producer_status();
        assert_eq!(polling.selected_source, ProcessWatcherSource::Polling);
        assert!(!polling.event_driven);
        assert!(polling.fallback_reason.is_some());
        assert!(polling.fallback_active);
        assert!(polling
            .unavailable_producers
            .iter()
            .any(|producer| producer.source == ProcessWatcherSource::Etw));
    }

    #[test]
    fn runtime_process_producer_exposes_queue_and_drain_metrics() {
        let mut producer = super::RuntimeProcessWatcherProducer::new();
        assert_eq!(producer.status().selected_source, ProcessWatcherSource::Polling);
        assert_eq!(producer.status().health, "stopped");
        fn producer_contract(
            producer: &impl super::ProcessEventProducer,
        ) -> (ProcessWatcherSource, bool, String) {
            let status = producer.status();
            (
                producer.source(),
                producer.is_event_driven(),
                status.health,
            )
        }
        assert_eq!(
            producer_contract(&producer),
            (ProcessWatcherSource::Polling, false, "stopped".to_string())
        );

        {
            let mut queue = producer.queue.lock().expect("queue lock");
            queue.push_back(event(1, "obs64.exe", 1_000));
            queue.push_back(event(2, "anydesk.exe", 1_250));
        }

        let drained = producer.drain_events_at(1_500);
        let status = producer.status();
        assert_eq!(drained.len(), 2);
        assert_eq!(status.drained_event_count, 2);
        assert_eq!(status.queue_depth, 0);
        assert_eq!(status.producer_latency_ms, 500);
    }

    #[test]
    fn runtime_process_producer_implements_state_producer_contract() {
        let mut producer = super::RuntimeProcessWatcherProducer::new();
        producer.push_event_for_test(event(42, "obs64.exe", 1_000));

        let events = RuntimeStateProducer::emit_events(&mut producer);
        let health = RuntimeStateProducer::snapshot(&producer);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].identity.pid, 42);
        assert_eq!(events[0].identity.image_name, "obs64.exe");
        assert_eq!(health.source, ProcessWatcherSource::Polling);
        assert_eq!(health.queue_depth, 0);
    }

    #[test]
    fn runtime_process_producer_starts_with_native_unavailable_evidence() {
        let mut producer = super::RuntimeProcessWatcherProducer::new();
        producer.start_hybrid(|| 10_000);

        let status = producer.status();
        assert_eq!(status.selected_source, ProcessWatcherSource::Polling);
        assert_eq!(status.producer_state, "fallback");
        assert_eq!(status.health, "healthy-fallback");
        assert!(status.fallback_active);
        assert_eq!(status.active_since_ms, Some(10_000));
        assert!(status.failure_count >= 1);
        assert!(status
            .unavailable_producers
            .iter()
            .any(|producer| producer.source == ProcessWatcherSource::Etw));
        assert!(status
            .unavailable_producers
            .iter()
            .any(|producer| producer.source == ProcessWatcherSource::Wmi));
        assert!(status
            .unavailable_producers
            .iter()
            .any(|producer| producer.source == ProcessWatcherSource::Service));

        producer.stop();
    }

    #[test]
    fn runtime_process_producer_retries_native_recovery_without_losing_polling() {
        let mut producer = super::RuntimeProcessWatcherProducer::new();
        producer.recovery_interval_ms = 1_000;
        producer.start_hybrid(|| 1_000);

        producer.recover_if_due(2_000);
        let status = producer.status();

        assert_eq!(status.selected_source, ProcessWatcherSource::Polling);
        assert_eq!(status.producer_state, "fallback-retry");
        assert_eq!(status.retry_count, 1);
        assert_eq!(status.recovery_attempt_count, 1);
        assert_eq!(producer.recovery_interval_ms, 2_000);
        assert!(status.last_failure.is_some());
        assert!(status.fallback_reason.is_some());

        producer.recover_if_due(3_000);
        assert_eq!(producer.status().retry_count, 1);
        producer.recover_if_due(4_000);
        assert_eq!(producer.status().retry_count, 2);
        assert_eq!(producer.recovery_interval_ms, 4_000);

        producer.stop();
    }

    #[test]
    fn runtime_process_producer_bounds_queue_and_reports_dropped_events() {
        let mut producer = super::RuntimeProcessWatcherProducer::new();
        for pid in 1..=(super::MAX_PRODUCER_QUEUE as u32 + 8) {
            producer.push_event_for_test(event(pid, "obs64.exe", pid as u64));
        }

        let status = producer.status();
        assert_eq!(status.queue_depth, super::MAX_PRODUCER_QUEUE);
        assert_eq!(status.dropped_event_count, 8);

        let drained = producer.drain_events();
        assert_eq!(drained.len(), super::MAX_DRAINED_EVENTS);
        assert_eq!(producer.status().drained_event_count, super::MAX_DRAINED_EVENTS);
        assert_eq!(
            producer.status().queue_depth,
            super::MAX_PRODUCER_QUEUE - super::MAX_DRAINED_EVENTS
        );
    }
}
