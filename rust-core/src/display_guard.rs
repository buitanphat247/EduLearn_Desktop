use crate::models::DesktopStateSnapshot;

#[derive(Debug, Clone)]
pub struct DisplayProtectionPlan {
    pub active_monitor_count: usize,
    pub black_overlay_count: usize,
}

/// Builds the visual monitor plan that Phase 6B expects. Electron will own the
/// real overlay windows, while Rust keeps a stable, testable description of
/// how many monitors and overlays should exist for the session.
pub fn build_display_protection_plan(desktop_state: &DesktopStateSnapshot) -> DisplayProtectionPlan {
    DisplayProtectionPlan {
        active_monitor_count: desktop_state.monitor_count,
        black_overlay_count: desktop_state.monitor_count.saturating_sub(1),
    }
}

#[cfg(test)]
mod tests {
    use super::build_display_protection_plan;
    use crate::models::DesktopStateSnapshot;

    fn desktop_state(monitor_count: usize) -> DesktopStateSnapshot {
        DesktopStateSnapshot {
            captured_at: 1,
            monitor_count,
            taskbar_visible: true,
            start_menu_visible: false,
            foreground_window_title: Some("English Reading".to_string()),
        }
    }

    #[test]
    fn keeps_single_monitor_without_auxiliary_overlays() {
        let plan = build_display_protection_plan(&desktop_state(1));

        assert_eq!(plan.active_monitor_count, 1);
        assert_eq!(plan.black_overlay_count, 0);
    }

    #[test]
    fn adds_black_overlays_for_each_secondary_monitor() {
        let plan = build_display_protection_plan(&desktop_state(3));

        assert_eq!(plan.active_monitor_count, 3);
        assert_eq!(plan.black_overlay_count, 2);
    }
}
