use crate::collectors::collect_display_info;
use crate::models::DesktopStateSnapshot;
use crate::taskbar_guard::is_taskbar_visible;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// Captures the current desktop shell shape before the exam protection layer
/// starts changing anything. Phase 6A keeps this passive and read-only so the
/// lifecycle can be tested safely before real kiosk changes are added.
pub fn capture_desktop_state() -> DesktopStateSnapshot {
    let display_info = collect_display_info();

    DesktopStateSnapshot {
        captured_at: now_ms(),
        monitor_count: display_info.monitor_count,
        taskbar_visible: is_taskbar_visible(),
        start_menu_visible: false,
        foreground_window_title: Some("Edulearn desktop shell".to_string()),
    }
}
