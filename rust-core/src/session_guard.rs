use crate::display_guard::build_display_protection_plan;
use crate::models::{
    DesktopStateSnapshot, ExamSessionContext, ExitExamSessionResult, ProtectionLogLine, ProtectionStatus,
    StartExamSessionPayload, StartExamSessionResult,
};

pub const SESSION_STATE_INIT: &str = "INIT";
pub const SESSION_STATE_PREFLIGHT_READY: &str = "PREFLIGHT_READY";
pub const SESSION_STATE_STARTING_EXAM_SESSION: &str = "STARTING_EXAM_SESSION";
pub const SESSION_STATE_SAVING_DESKTOP_STATE: &str = "SAVING_DESKTOP_STATE";
pub const SESSION_STATE_ENTERING_KIOSK: &str = "ENTERING_KIOSK";
pub const SESSION_STATE_EXAM_RUNNING_CONFIRMED: &str = "EXAM_RUNNING_CONFIRMED";
pub const SESSION_STATE_PROTECTION_ACTIVE: &str = "PROTECTION_ACTIVE";
pub const SESSION_STATE_EXAM_RUNNING: &str = "EXAM_RUNNING";
pub const SESSION_STATE_RECOVERY_REQUIRED: &str = "RECOVERY_REQUIRED";
pub const SESSION_STATE_EXIT_REQUESTED: &str = "EXIT_REQUESTED";
pub const SESSION_STATE_EXITING_KIOSK: &str = "EXITING_KIOSK";
pub const SESSION_STATE_RESTORING_DESKTOP: &str = "RESTORING_DESKTOP";
pub const SESSION_STATE_EXAM_ENDED: &str = "EXAM_ENDED";
pub const SESSION_STATE_IDLE: &str = "IDLE";
pub const SESSION_STATE_PROTECTION_FAILED: &str = "PROTECTION_FAILED";
pub const SESSION_STATE_RESTORE_FAILED: &str = "RESTORE_FAILED";

pub fn is_valid_session_transition(from: &str, to: &str) -> bool {
    if from == to {
        return true;
    }

    matches!(
        (from, to),
        (SESSION_STATE_INIT, SESSION_STATE_PREFLIGHT_READY)
            | (SESSION_STATE_INIT, SESSION_STATE_STARTING_EXAM_SESSION)
            | (SESSION_STATE_INIT, SESSION_STATE_EXAM_RUNNING)
            | (SESSION_STATE_IDLE, SESSION_STATE_PREFLIGHT_READY)
            | (SESSION_STATE_IDLE, SESSION_STATE_STARTING_EXAM_SESSION)
            | (SESSION_STATE_IDLE, SESSION_STATE_EXAM_RUNNING)
            | (
                SESSION_STATE_PREFLIGHT_READY,
                SESSION_STATE_STARTING_EXAM_SESSION
            )
            | (SESSION_STATE_PREFLIGHT_READY, SESSION_STATE_EXAM_RUNNING)
            | (
                SESSION_STATE_STARTING_EXAM_SESSION,
                SESSION_STATE_EXAM_RUNNING
            )
            | (
                SESSION_STATE_STARTING_EXAM_SESSION,
                SESSION_STATE_ENTERING_KIOSK
            )
            | (
                SESSION_STATE_ENTERING_KIOSK,
                SESSION_STATE_EXAM_RUNNING_CONFIRMED
            )
            | (
                SESSION_STATE_EXAM_RUNNING_CONFIRMED,
                SESSION_STATE_EXAM_RUNNING
            )
            | (
                SESSION_STATE_ENTERING_KIOSK,
                SESSION_STATE_IDLE
            )
            | (
                SESSION_STATE_EXAM_RUNNING_CONFIRMED,
                SESSION_STATE_IDLE
            )
            | (SESSION_STATE_EXAM_RUNNING, SESSION_STATE_RECOVERY_REQUIRED)
            | (SESSION_STATE_STARTING_EXAM_SESSION, SESSION_STATE_IDLE)
            | (SESSION_STATE_EXAM_RUNNING, SESSION_STATE_IDLE)
            | (SESSION_STATE_RECOVERY_REQUIRED, SESSION_STATE_IDLE)
            | (SESSION_STATE_PROTECTION_FAILED, SESSION_STATE_IDLE)
            | (SESSION_STATE_RESTORE_FAILED, SESSION_STATE_IDLE)
    )
}

fn build_log_line(timestamp: u64, level: &str, code: &str, message: impl Into<String>) -> ProtectionLogLine {
    ProtectionLogLine {
        timestamp,
        level: level.to_string(),
        code: code.to_string(),
        message: message.into(),
    }
}

pub fn build_idle_protection_status() -> ProtectionStatus {
    ProtectionStatus {
        exam_protection_active: false,
        protection_dry_run: false,
        kiosk_active: false,
        overlay_active: false,
        taskbar_hidden: false,
        keyboard_hook_active: false,
        focus_lock_active: false,
        input_hook_active: false,
        mouse_hook_active: false,
        focus_hook_active: false,
        clipboard_listener_active: false,
        overlay_heal_active: false,
        capture_heal_active: false,
        capture_protection_active: false,
        capture_protection_status: "inactive".to_string(),
        electron_content_protection_active: false,
        rust_overlay_capture_protection_active: false,
        capture_protection_best_effort: false,
        runtime_monitor_active: false,
        active_monitor_count: 0,
        black_overlay_count: 0,
        last_runtime_event_at: None,
    }
}

/// Dry-run mode validates the whole lifecycle without touching the real
/// Windows shell yet. This keeps Phase 6A safe while the team hardens restore
/// logic before enabling actual kiosk mutations.
pub fn build_start_exam_session_result(
    now_ms: u64,
    payload: StartExamSessionPayload,
    desktop_state: DesktopStateSnapshot,
) -> StartExamSessionResult {
    let display_plan = build_display_protection_plan(&desktop_state);
    let session_context = ExamSessionContext {
        session_id: payload.session_id,
        exam_id: payload.exam_id,
        room_code: payload.room_code,
        started_at: now_ms,
        dry_run: payload.dry_run,
        exit_password_hash: payload.exit_password_hash.clone(),
    };

    let protection_status = ProtectionStatus {
        exam_protection_active: false,
        protection_dry_run: payload.dry_run,
        kiosk_active: false,
        overlay_active: false,
        taskbar_hidden: false,
        keyboard_hook_active: false,
        focus_lock_active: false,
        input_hook_active: false,
        mouse_hook_active: false,
        focus_hook_active: false,
        clipboard_listener_active: false,
        overlay_heal_active: false,
        capture_heal_active: false,
        capture_protection_active: false,
        capture_protection_status: if payload.dry_run {
            "dry-run".to_string()
        } else {
            "pending".to_string()
        },
        electron_content_protection_active: false,
        rust_overlay_capture_protection_active: false,
        capture_protection_best_effort: false,
        runtime_monitor_active: false,
        active_monitor_count: display_plan.active_monitor_count,
        black_overlay_count: display_plan.black_overlay_count,
        last_runtime_event_at: Some(now_ms + 3),
    };

    let reserved_failure_states = format!(
        "Reserved fallback states for next phases: {}/{}.",
        SESSION_STATE_PROTECTION_FAILED, SESSION_STATE_RESTORE_FAILED
    );

    let log_lines = vec![
        build_log_line(
            now_ms,
            "info",
            SESSION_STATE_PREFLIGHT_READY,
            "Preflight gate completed. Preparing exam session startup.",
        ),
        build_log_line(
            now_ms + 1,
            "info",
            SESSION_STATE_STARTING_EXAM_SESSION,
            "Start exam session requested.",
        ),
        build_log_line(
            now_ms + 2,
            "info",
            SESSION_STATE_SAVING_DESKTOP_STATE,
            format!(
                "Saved desktop shell snapshot with {} monitor(s).",
                desktop_state.monitor_count
            ),
        ),
        build_log_line(
            now_ms + 3,
            "info",
            SESSION_STATE_ENTERING_KIOSK,
            if payload.dry_run {
                "Dry-run mode is active. No real Windows kiosk mutations were applied."
            } else {
                "Desktop snapshot is ready. The shell can now enter the Phase 6B visual kiosk handoff."
            },
        ),
        build_log_line(
            now_ms + 4,
            "success",
            if payload.dry_run {
                SESSION_STATE_PROTECTION_ACTIVE
            } else {
                SESSION_STATE_STARTING_EXAM_SESSION
            },
            if payload.dry_run {
                "Desktop session protection layer is staged for the next phases."
            } else {
                "Phase 6B visual kiosk is pending activation by the Electron shell."
            },
        ),
        build_log_line(now_ms + 5, "info", "FAILURE_STATE_RESERVED", reserved_failure_states),
    ];

    StartExamSessionResult {
        started_at: now_ms,
        session_state: if payload.dry_run {
            SESSION_STATE_EXAM_RUNNING.to_string()
        } else {
            SESSION_STATE_STARTING_EXAM_SESSION.to_string()
        },
        session_context,
        desktop_state,
        protection_status,
        runtime_risk_level: "normal".to_string(),
        process_policy: Vec::new(),
        log_lines,
    }
}

pub fn build_exit_exam_session_result(
    now_ms: u64,
    previous_status: &ProtectionStatus,
    reason: Option<String>,
) -> ExitExamSessionResult {
    let reason_text = reason.unwrap_or_else(|| "Exit requested by desktop shell.".to_string());
    let log_lines = vec![
        build_log_line(now_ms, "info", SESSION_STATE_EXIT_REQUESTED, reason_text),
        build_log_line(
            now_ms + 1,
            "info",
            SESSION_STATE_EXITING_KIOSK,
            "Runtime monitor and temporary protection flags were cleared.",
        ),
        build_log_line(
            now_ms + 2,
            "info",
            SESSION_STATE_RESTORING_DESKTOP,
            "Desktop restore sequence is replaying the saved shell state.",
        ),
        build_log_line(
            now_ms + 3,
            "success",
            SESSION_STATE_EXAM_ENDED,
            format!(
                "Desktop restore flow completed. Previous overlay count: {}.",
                previous_status.black_overlay_count
            ),
        ),
        build_log_line(
            now_ms + 4,
            "success",
            SESSION_STATE_IDLE,
            "Desktop shell is back to the idle state.",
        ),
    ];

    ExitExamSessionResult {
        exited_at: now_ms,
        session_state: SESSION_STATE_IDLE.to_string(),
        protection_status: build_idle_protection_status(),
        restored_desktop: true,
        log_lines,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_exit_exam_session_result, build_idle_protection_status, build_start_exam_session_result,
        is_valid_session_transition, SESSION_STATE_EXAM_RUNNING, SESSION_STATE_EXAM_RUNNING_CONFIRMED,
        SESSION_STATE_IDLE,
        SESSION_STATE_INIT, SESSION_STATE_PREFLIGHT_READY,
        SESSION_STATE_RECOVERY_REQUIRED, SESSION_STATE_ENTERING_KIOSK,
        SESSION_STATE_STARTING_EXAM_SESSION,
    };
    use crate::models::{DesktopStateSnapshot, StartExamSessionPayload};

    fn desktop_state(monitor_count: usize) -> DesktopStateSnapshot {
        DesktopStateSnapshot {
            captured_at: 1_782_600_000_000,
            monitor_count,
            taskbar_visible: true,
            start_menu_visible: false,
            foreground_window_title: Some("English Reading".to_string()),
        }
    }

    fn start_payload(dry_run: bool) -> StartExamSessionPayload {
        StartExamSessionPayload {
            session_id: "ses-1".to_string(),
            exam_id: Some("exam-1".to_string()),
            room_code: Some("ROOM-1".to_string()),
            window_handle_hex: None,
            exam_key: None,
            service_authorization: None,
            exit_password_hash: None,
            dry_run,
        }
    }

    #[test]
    fn dry_run_start_marks_exam_running_without_real_protection() {
        let result = build_start_exam_session_result(1_782_600_100_000, start_payload(true), desktop_state(2));

        assert_eq!(result.session_state, SESSION_STATE_EXAM_RUNNING);
        assert!(result.session_context.dry_run);
        assert!(!result.protection_status.exam_protection_active);
        assert!(result.protection_status.protection_dry_run);
        assert_eq!(result.protection_status.black_overlay_count, 1);
        assert_eq!(result.log_lines.len(), 6);
    }

    #[test]
    fn real_start_keeps_session_in_startup_handoff_state() {
        let result = build_start_exam_session_result(1_782_600_100_000, start_payload(false), desktop_state(1));

        assert_eq!(result.session_state, SESSION_STATE_STARTING_EXAM_SESSION);
        assert!(!result.session_context.dry_run);
        assert!(!result.protection_status.exam_protection_active);
        assert!(!result.protection_status.protection_dry_run);
        assert_eq!(result.protection_status.black_overlay_count, 0);
    }

    #[test]
    fn exit_result_restores_idle_protection_snapshot() {
        let previous_status = build_idle_protection_status();
        let result = build_exit_exam_session_result(
            1_782_600_200_000,
            &previous_status,
            Some("User exited room.".to_string()),
        );

        assert_eq!(result.session_state, SESSION_STATE_IDLE);
        assert!(result.restored_desktop);
        assert!(!result.protection_status.exam_protection_active);
        assert_eq!(result.log_lines.last().map(|line| line.code.as_str()), Some(SESSION_STATE_IDLE));
    }

    #[test]
    fn state_machine_accepts_exam_lifecycle_transitions() {
        assert!(is_valid_session_transition(
            SESSION_STATE_INIT,
            SESSION_STATE_PREFLIGHT_READY,
        ));
        assert!(is_valid_session_transition(
            SESSION_STATE_PREFLIGHT_READY,
            SESSION_STATE_STARTING_EXAM_SESSION,
        ));
        assert!(is_valid_session_transition(
            SESSION_STATE_STARTING_EXAM_SESSION,
            SESSION_STATE_ENTERING_KIOSK,
        ));
        assert!(is_valid_session_transition(
            SESSION_STATE_ENTERING_KIOSK,
            SESSION_STATE_EXAM_RUNNING_CONFIRMED,
        ));
        assert!(is_valid_session_transition(
            SESSION_STATE_EXAM_RUNNING_CONFIRMED,
            SESSION_STATE_EXAM_RUNNING,
        ));
        assert!(is_valid_session_transition(
            SESSION_STATE_EXAM_RUNNING,
            SESSION_STATE_RECOVERY_REQUIRED,
        ));
        assert!(is_valid_session_transition(
            SESSION_STATE_RECOVERY_REQUIRED,
            SESSION_STATE_IDLE,
        ));
    }

    #[test]
    fn state_machine_rejects_runtime_to_preflight_regression() {
        assert!(!is_valid_session_transition(
            SESSION_STATE_EXAM_RUNNING,
            SESSION_STATE_PREFLIGHT_READY,
        ));
    }
}
