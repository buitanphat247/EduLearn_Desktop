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
    last_tick_at: Option<u64>,
}

impl RuntimeMonitorScheduler {
    pub fn new(environment_scan_interval_ms: u64) -> Self {
        Self {
            environment_scan_interval_ms,
            last_environment_scan_at: None,
            last_tick_at: None,
        }
    }

    pub fn next_tick(&mut self, now_ms: u64) -> RuntimeTickPlan {
        self.last_tick_at = Some(now_ms);
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

    /// M3/P2-1 — has the external driver (Electron) stopped ticking? The core's
    /// autonomous self-heal loop uses this to keep re-arming guards even when the
    /// pull-based driver goes silent (previously remediation stalled with it).
    /// False before the first tick (nothing to compare against yet).
    pub fn is_externally_stalled(&self, now_ms: u64, max_idle_ms: u64) -> bool {
        match self.last_tick_at {
            Some(last) => now_ms.saturating_sub(last) >= max_idle_ms,
            None => false,
        }
    }

    pub fn reset(&mut self) {
        self.last_environment_scan_at = None;
        self.last_tick_at = None;
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
    fn detects_when_the_external_driver_has_stalled() {
        let mut scheduler = RuntimeMonitorScheduler::new(5_000);
        // Before any tick there is nothing to compare against.
        assert!(!scheduler.is_externally_stalled(10_000, 3_000));

        let _ = scheduler.next_tick(10_000);
        // Within the idle window → not stalled.
        assert!(!scheduler.is_externally_stalled(12_999, 3_000));
        // Past the idle window with no fresh tick → stalled (self-heal kicks in).
        assert!(scheduler.is_externally_stalled(13_000, 3_000));

        // A fresh tick clears the stall.
        let _ = scheduler.next_tick(13_000);
        assert!(!scheduler.is_externally_stalled(13_500, 3_000));
    }

    #[test]
    fn reset_makes_next_environment_scan_immediate() {
        let mut scheduler = RuntimeMonitorScheduler::new(5_000);
        let _ = scheduler.next_tick(10_000);
        scheduler.reset();

        assert!(scheduler.next_tick(10_001).environment_scan_due);
    }
}
