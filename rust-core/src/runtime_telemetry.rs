use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeTelemetrySnapshot {
    pub runtime_latency_ms: u64,
    pub runtime_tick_duration_ms: u64,
    pub watcher_latency_ms: u64,
    pub detection_latency_ms: u64,
    pub classification_latency_ms: u64,
    pub process_classification_time_ms: u64,
    pub kill_latency_ms: u64,
    pub remediation_time_ms: u64,
    pub recovery_latency_ms: u64,
    pub queue_latency_ms: u64,
    pub producer_latency_ms: u64,
    pub guard_restart_count: u64,
    pub watchdog_restart_count: u64,
    pub event_queue_length: usize,
    pub runtime_health: String,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeTelemetrySample {
    pub runtime_tick_duration_ms: u64,
    pub watcher_latency_ms: u64,
    pub detection_latency_ms: u64,
    pub classification_latency_ms: u64,
    pub process_classification_time_ms: u64,
    pub kill_latency_ms: u64,
    pub remediation_time_ms: u64,
    pub recovery_latency_ms: u64,
    pub queue_latency_ms: u64,
    pub producer_latency_ms: u64,
    pub event_queue_length: usize,
    pub degraded_guard_count: usize,
    pub guard_restored_count: usize,
    pub watchdog_restart_count: usize,
}

#[derive(Debug, Default)]
pub struct RuntimeTelemetry {
    guard_restart_count: u64,
    watchdog_restart_count: u64,
    last_snapshot: Option<RuntimeTelemetrySnapshot>,
}

impl RuntimeTelemetry {
    pub fn record_tick(&mut self, sample: RuntimeTelemetrySample) -> RuntimeTelemetrySnapshot {
        self.guard_restart_count = self
            .guard_restart_count
            .saturating_add(sample.guard_restored_count as u64);
        self.watchdog_restart_count = self
            .watchdog_restart_count
            .saturating_add(sample.watchdog_restart_count as u64);

        let runtime_health = if sample.degraded_guard_count > 0 {
            "degraded"
        } else if sample.runtime_tick_duration_ms > 500 {
            "slow"
        } else {
            "healthy"
        }
        .to_string();

        let snapshot = RuntimeTelemetrySnapshot {
            runtime_latency_ms: sample
                .runtime_tick_duration_ms
                .max(sample.watcher_latency_ms)
                .max(sample.detection_latency_ms)
                .max(sample.classification_latency_ms)
                .max(sample.process_classification_time_ms)
                .max(sample.kill_latency_ms)
                .max(sample.remediation_time_ms),
            runtime_tick_duration_ms: sample.runtime_tick_duration_ms,
            watcher_latency_ms: sample.watcher_latency_ms,
            detection_latency_ms: sample.detection_latency_ms,
            classification_latency_ms: sample.classification_latency_ms,
            process_classification_time_ms: sample.process_classification_time_ms,
            kill_latency_ms: sample.kill_latency_ms,
            remediation_time_ms: sample.remediation_time_ms,
            recovery_latency_ms: sample.recovery_latency_ms,
            queue_latency_ms: sample.queue_latency_ms,
            producer_latency_ms: sample.producer_latency_ms,
            guard_restart_count: self.guard_restart_count,
            watchdog_restart_count: self.watchdog_restart_count,
            event_queue_length: sample.event_queue_length,
            runtime_health,
        };
        self.last_snapshot = Some(snapshot.clone());
        snapshot
    }

    pub fn last_snapshot(&self) -> Option<RuntimeTelemetrySnapshot> {
        self.last_snapshot.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeTelemetry, RuntimeTelemetrySample};

    fn sample() -> RuntimeTelemetrySample {
        RuntimeTelemetrySample {
            runtime_tick_duration_ms: 42,
            watcher_latency_ms: 10,
            detection_latency_ms: 10,
            classification_latency_ms: 5,
            process_classification_time_ms: 5,
            kill_latency_ms: 8,
            remediation_time_ms: 8,
            recovery_latency_ms: 0,
            queue_latency_ms: 3,
            producer_latency_ms: 2,
            event_queue_length: 3,
            degraded_guard_count: 0,
            guard_restored_count: 0,
            watchdog_restart_count: 0,
        }
    }

    #[test]
    fn records_healthy_runtime_sample() {
        let mut telemetry = RuntimeTelemetry::default();
        let snapshot = telemetry.record_tick(sample());

        assert_eq!(snapshot.runtime_health, "healthy");
        assert_eq!(snapshot.runtime_latency_ms, 42);
        assert_eq!(snapshot.event_queue_length, 3);
    }

    #[test]
    fn accumulates_guard_restarts_and_marks_degraded() {
        let mut telemetry = RuntimeTelemetry::default();
        let mut first = sample();
        first.guard_restored_count = 2;
        let _ = telemetry.record_tick(first);

        let mut second = sample();
        second.degraded_guard_count = 1;
        second.guard_restored_count = 1;
        let snapshot = telemetry.record_tick(second);

        assert_eq!(snapshot.guard_restart_count, 3);
        assert_eq!(snapshot.runtime_health, "degraded");
    }
}
