pub const DEFAULT_ENVIRONMENT_SCAN_INTERVAL_MS: u64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeTickPlan {
    pub process_scan_due: bool,
    pub guard_healing_due: bool,
    pub environment_scan_due: bool,
}

#[derive(Debug)]
pub struct RuntimeMonitorScheduler {
    environment_scan_interval_ms: u64,
    last_environment_scan_at: Option<u64>,
}

impl RuntimeMonitorScheduler {
    pub fn new(environment_scan_interval_ms: u64) -> Self {
        Self {
            environment_scan_interval_ms,
            last_environment_scan_at: None,
        }
    }

    pub fn next_tick(&mut self, now_ms: u64) -> RuntimeTickPlan {
        // Process remediation and guard healing are fast-path work. Hardware and
        // VM inspection refreshes broader system state and therefore runs slower.
        let environment_scan_due = self
            .last_environment_scan_at
            .map(|last_scan| {
                now_ms.saturating_sub(last_scan) >= self.environment_scan_interval_ms
            })
            .unwrap_or(true);

        if environment_scan_due {
            self.last_environment_scan_at = Some(now_ms);
        }

        RuntimeTickPlan {
            process_scan_due: true,
            guard_healing_due: true,
            environment_scan_due,
        }
    }

    pub fn reset(&mut self) {
        self.last_environment_scan_at = None;
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeMonitorScheduler, RuntimeTickPlan};

    #[test]
    fn first_tick_runs_every_scan_group() {
        let mut scheduler = RuntimeMonitorScheduler::new(5_000);

        assert_eq!(
            scheduler.next_tick(10_000),
            RuntimeTickPlan {
                process_scan_due: true,
                guard_healing_due: true,
                environment_scan_due: true,
            }
        );
    }

    #[test]
    fn fast_ticks_defer_environment_scan_until_interval_elapses() {
        let mut scheduler = RuntimeMonitorScheduler::new(5_000);
        let _ = scheduler.next_tick(10_000);

        assert!(!scheduler.next_tick(11_000).environment_scan_due);
        assert!(!scheduler.next_tick(14_999).environment_scan_due);
        assert!(scheduler.next_tick(15_000).environment_scan_due);
    }

    #[test]
    fn reset_makes_next_environment_scan_immediate() {
        let mut scheduler = RuntimeMonitorScheduler::new(5_000);
        let _ = scheduler.next_tick(10_000);
        scheduler.reset();

        assert!(scheduler.next_tick(10_001).environment_scan_due);
    }
}
