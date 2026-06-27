use crate::display_guard::{build_display_protection_plan, DisplayProtectionPlan};
use crate::input_guard::InputGuardMutationResult;
use crate::models::{
    DesktopStateSnapshot, ProtectionLogLine, ProtectionStatus, ProtectionTransitionResult,
};
use crate::taskbar_guard::TaskbarMutationResult;

use crate::session_guard::{
    SESSION_STATE_ENTERING_KIOSK, SESSION_STATE_EXAM_RUNNING, SESSION_STATE_EXITING_KIOSK,
    SESSION_STATE_PROTECTION_ACTIVE, SESSION_STATE_RESTORING_DESKTOP,
};

fn build_log_line(timestamp: u64, level: &str, code: &str, message: impl Into<String>) -> ProtectionLogLine {
    ProtectionLogLine {
        timestamp,
        level: level.to_string(),
        code: code.to_string(),
        message: message.into(),
    }
}

pub fn build_enter_kiosk_result(
    now_ms: u64,
    desktop_state: &DesktopStateSnapshot,
    taskbar_result: &TaskbarMutationResult,
    input_guard_result: &InputGuardMutationResult,
) -> ProtectionTransitionResult {
    let display_plan: DisplayProtectionPlan = build_display_protection_plan(desktop_state);

    let protection_status = ProtectionStatus {
        exam_protection_active: true,
        protection_dry_run: false,
        kiosk_active: true,
        overlay_active: display_plan.black_overlay_count > 0,
        taskbar_hidden: taskbar_result.applied,
        keyboard_hook_active: input_guard_result.active,
        focus_lock_active: false,
        capture_protection_active: false,
        capture_protection_status: "inactive".to_string(),
        runtime_monitor_active: false,
        active_monitor_count: display_plan.active_monitor_count,
        black_overlay_count: display_plan.black_overlay_count,
        last_runtime_event_at: Some(now_ms + 3),
    };

    let log_lines = vec![
        build_log_line(
            now_ms,
            "info",
            SESSION_STATE_ENTERING_KIOSK,
            "Visual kiosk handoff started. Electron is applying fullscreen and overlay windows.",
        ),
        build_log_line(
            now_ms + 1,
            "success",
            "DISPLAY_OVERLAY_ACTIVE",
            format!(
                "Display plan is active: {} monitor(s), {} black overlay window(s).",
                display_plan.active_monitor_count, display_plan.black_overlay_count
            ),
        ),
        build_log_line(
            now_ms + 2,
            if taskbar_result.applied { "success" } else { "warn" },
            "TASKBAR_STATE_UPDATED",
            taskbar_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 3,
            if input_guard_result.applied && input_guard_result.active {
                "success"
            } else {
                "warn"
            },
            "INPUT_GUARD_STATE_UPDATED",
            input_guard_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 4,
            "success",
            SESSION_STATE_PROTECTION_ACTIVE,
            if input_guard_result.active {
                "Phase 6B visual kiosk is active and the native keyboard guard is now attached."
            } else {
                "Phase 6B visual kiosk is active, but the native keyboard guard is not attached yet."
            },
        ),
        build_log_line(
            now_ms + 5,
            "success",
            SESSION_STATE_EXAM_RUNNING,
            "Exam session is now running with the visual kiosk layer enabled.",
        ),
    ];

    ProtectionTransitionResult {
        transitioned_at: now_ms,
        session_state: SESSION_STATE_EXAM_RUNNING.to_string(),
        protection_status,
        restored_desktop: None,
        log_lines,
    }
}

pub fn build_exit_kiosk_result(
    now_ms: u64,
    previous_status: &ProtectionStatus,
    taskbar_result: &TaskbarMutationResult,
    input_guard_result: &InputGuardMutationResult,
) -> ProtectionTransitionResult {
    let protection_status = ProtectionStatus {
        exam_protection_active: false,
        protection_dry_run: false,
        kiosk_active: false,
        overlay_active: false,
        taskbar_hidden: false,
        keyboard_hook_active: input_guard_result.active,
        focus_lock_active: false,
        capture_protection_active: false,
        capture_protection_status: "inactive".to_string(),
        runtime_monitor_active: false,
        active_monitor_count: previous_status.active_monitor_count,
        black_overlay_count: 0,
        last_runtime_event_at: Some(now_ms + 2),
    };

    let log_lines = vec![
        build_log_line(
            now_ms,
            "info",
            SESSION_STATE_EXITING_KIOSK,
            "Visual kiosk exit started. Electron is restoring fullscreen and overlay windows.",
        ),
        build_log_line(
            now_ms + 1,
            if taskbar_result.applied { "success" } else { "warn" },
            "TASKBAR_STATE_RESTORED",
            taskbar_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 2,
            if input_guard_result.applied { "success" } else { "warn" },
            "INPUT_GUARD_RESTORED",
            input_guard_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 3,
            "success",
            SESSION_STATE_RESTORING_DESKTOP,
            "Phase 6B visual kiosk state was cleared and the desktop shell can return to idle.",
        ),
    ];

    ProtectionTransitionResult {
        transitioned_at: now_ms,
        session_state: SESSION_STATE_RESTORING_DESKTOP.to_string(),
        protection_status,
        restored_desktop: Some(taskbar_result.applied),
        log_lines,
    }
}

#[cfg(test)]
mod tests {
    use super::{build_enter_kiosk_result, build_exit_kiosk_result};
    use crate::input_guard::InputGuardMutationResult;
    use crate::models::{DesktopStateSnapshot, ProtectionStatus};
    use crate::taskbar_guard::TaskbarMutationResult;

    fn desktop_state(monitor_count: usize) -> DesktopStateSnapshot {
        DesktopStateSnapshot {
            captured_at: 1_782_600_000_000,
            monitor_count,
            taskbar_visible: true,
            start_menu_visible: false,
            foreground_window_title: Some("English Reading".to_string()),
        }
    }

    fn taskbar_result(applied: bool, detail: &str) -> TaskbarMutationResult {
        TaskbarMutationResult {
            applied,
            detail: detail.to_string(),
        }
    }

    fn input_result(applied: bool, active: bool, detail: &str) -> InputGuardMutationResult {
        InputGuardMutationResult {
            applied,
            active,
            detail: detail.to_string(),
        }
    }

    fn previous_status() -> ProtectionStatus {
        ProtectionStatus {
            exam_protection_active: true,
            protection_dry_run: false,
            kiosk_active: true,
            overlay_active: true,
            taskbar_hidden: true,
            keyboard_hook_active: true,
            focus_lock_active: false,
            capture_protection_active: false,
            capture_protection_status: "inactive".to_string(),
            runtime_monitor_active: false,
            active_monitor_count: 3,
            black_overlay_count: 2,
            last_runtime_event_at: Some(1_782_600_300_000),
        }
    }

    #[test]
    fn enter_kiosk_activates_visual_shell_and_counts_secondary_overlays() {
        let result = build_enter_kiosk_result(
            1_782_600_300_000,
            &desktop_state(3),
            &taskbar_result(true, "Taskbar hidden."),
            &input_result(true, true, "Keyboard hook active."),
        );

        assert_eq!(result.session_state, "EXAM_RUNNING");
        assert!(result.protection_status.exam_protection_active);
        assert!(result.protection_status.kiosk_active);
        assert!(result.protection_status.overlay_active);
        assert_eq!(result.protection_status.black_overlay_count, 2);
        assert!(result.protection_status.keyboard_hook_active);
    }

    #[test]
    fn exit_kiosk_clears_visual_shell_flags() {
        let result = build_exit_kiosk_result(
            1_782_600_400_000,
            &previous_status(),
            &taskbar_result(true, "Taskbar restored."),
            &input_result(true, false, "Keyboard hook removed."),
        );

        assert_eq!(result.session_state, "RESTORING_DESKTOP");
        assert_eq!(result.restored_desktop, Some(true));
        assert!(!result.protection_status.kiosk_active);
        assert!(!result.protection_status.overlay_active);
        assert!(!result.protection_status.keyboard_hook_active);
        assert_eq!(result.protection_status.black_overlay_count, 0);
    }
}
