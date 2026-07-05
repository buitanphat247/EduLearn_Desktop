use crate::accessibility_guard::AccessibilityGuardMutationResult;
use crate::capture_guard::CaptureGuardMutationResult;
use crate::clipboard_guard::ClipboardGuardMutationResult;
use crate::display_guard::{
    build_display_protection_plan_from_display_info, DisplayProtectionPlan, OverlayMutationResult,
};
use crate::input_guard::InputGuardMutationResult;
use crate::models::{
    DisplayInfo, ProtectionLogLine, ProtectionStatus, ProtectionTransitionResult,
};
use crate::focus_guard::FocusGuardMutationResult;
use crate::mouse_guard::MouseGuardMutationResult;
use crate::taskbar_guard::TaskbarMutationResult;

use crate::session_guard::{
    SESSION_STATE_ENTERING_KIOSK, SESSION_STATE_EXITING_KIOSK,
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
    display_info: &DisplayInfo,
    overlay_result: &OverlayMutationResult,
    taskbar_result: &TaskbarMutationResult,
    input_guard_result: &InputGuardMutationResult,
    focus_guard_result: &FocusGuardMutationResult,
    capture_guard_result: &CaptureGuardMutationResult,
    electron_content_protection_active: bool,
    mouse_guard_result: &MouseGuardMutationResult,
    clipboard_guard_result: &ClipboardGuardMutationResult,
    accessibility_guard_result: &AccessibilityGuardMutationResult,
) -> ProtectionTransitionResult {
    let display_plan: DisplayProtectionPlan = build_display_protection_plan_from_display_info(display_info);
    let rust_overlay_capture_protection_active = overlay_result.active;
    let capture_protection_best_effort =
        electron_content_protection_active || rust_overlay_capture_protection_active || capture_guard_result.active;
    let capture_protection_status = if electron_content_protection_active && capture_guard_result.active {
        format!("electron-content-protection+{}", capture_guard_result.status)
    } else if electron_content_protection_active {
        "electron-content-protection-active".to_string()
    } else {
        capture_guard_result.status.clone()
    };

    let protection_status = ProtectionStatus {
        exam_protection_active: true,
        protection_dry_run: false,
        kiosk_active: true,
        overlay_active: overlay_result.active,
        taskbar_hidden: taskbar_result.applied,
        keyboard_hook_active: input_guard_result.active,
        focus_lock_active: focus_guard_result.active,
        input_hook_active: input_guard_result.active,
        mouse_hook_active: mouse_guard_result.active,
        focus_hook_active: focus_guard_result.active,
        clipboard_listener_active: clipboard_guard_result.applied,
        overlay_heal_active: overlay_result.applied,
        capture_heal_active: capture_protection_best_effort,
        capture_protection_active: capture_protection_best_effort,
        capture_protection_status,
        electron_content_protection_active,
        rust_overlay_capture_protection_active,
        capture_protection_best_effort,
        runtime_monitor_active: true,
        active_monitor_count: display_plan.active_monitor_count,
        black_overlay_count: overlay_result.overlay_count,
        last_runtime_event_at: Some(now_ms + 10),
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
            if overlay_result.applied { "success" } else { "warn" },
            "DISPLAY_OVERLAY_ACTIVE",
            overlay_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 2,
            if taskbar_result.applied { "success" } else { "warn" },
            "TASKBAR_STATE_UPDATED",
            taskbar_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 3,
            if focus_guard_result.applied && focus_guard_result.active {
                "success"
            } else {
                "warn"
            },
            "FOCUS_GUARD_STATE_UPDATED",
            focus_guard_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 4,
            if input_guard_result.applied && input_guard_result.active {
                "success"
            } else {
                "warn"
            },
            "INPUT_GUARD_STATE_UPDATED",
            input_guard_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 5,
            if capture_protection_best_effort {
                "success"
            } else {
                "warn"
            },
            "CAPTURE_GUARD_STATE_UPDATED",
            if electron_content_protection_active {
                format!(
                    "{} Electron BrowserWindow content protection is authoritative for the exam window.",
                    capture_guard_result.detail
                )
            } else {
                capture_guard_result.detail.clone()
            },
        ),
        build_log_line(
            now_ms + 6,
            if mouse_guard_result.applied && mouse_guard_result.active {
                "success"
            } else {
                "warn"
            },
            "MOUSE_GUARD_STATE_UPDATED",
            mouse_guard_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 7,
            if clipboard_guard_result.applied {
                "success"
            } else {
                "warn"
            },
            "CLIPBOARD_GUARD_STATE_UPDATED",
            clipboard_guard_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 8,
            if accessibility_guard_result.applied
                && accessibility_guard_result.active
            {
                "success"
            } else {
                "warn"
            },
            "ACCESSIBILITY_GUARD_STATE_UPDATED",
            accessibility_guard_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 9,
            "success",
            SESSION_STATE_PROTECTION_ACTIVE,
            if overlay_result.active && input_guard_result.active && focus_guard_result.active && capture_protection_best_effort && mouse_guard_result.active && clipboard_guard_result.applied && accessibility_guard_result.active {
                "Strict exam protection is active with native overlays, keyboard, focus, capture, mouse, clipboard and accessibility guards attached."
            } else if overlay_result.active && input_guard_result.active {
                "Strict exam protection is partially active with native visual and keyboard protection attached."
            } else {
                "Strict exam protection is partially active. Review guard state logs for fallbacks or unsupported features."
            },
        ),
        build_log_line(
            now_ms + 10,
            "info",
            crate::session_guard::SESSION_STATE_ENTERING_KIOSK,
            "Native guards applied successfully. Waiting for visual kiosk handoff completion.",
        ),
    ];

    ProtectionTransitionResult {
        transitioned_at: now_ms,
        session_state: crate::session_guard::SESSION_STATE_ENTERING_KIOSK.to_string(),
        protection_status,
        restored_desktop: None,
        log_lines,
    }
}

pub fn build_exit_kiosk_result(
    now_ms: u64,
    previous_status: &ProtectionStatus,
    overlay_result: &OverlayMutationResult,
    taskbar_result: &TaskbarMutationResult,
    focus_guard_result: &FocusGuardMutationResult,
    input_guard_result: &InputGuardMutationResult,
    capture_guard_result: &CaptureGuardMutationResult,
    mouse_guard_result: &MouseGuardMutationResult,
    accessibility_guard_result: &AccessibilityGuardMutationResult,
    clipboard_guard_result: &ClipboardGuardMutationResult,
) -> ProtectionTransitionResult {
    let protection_status = ProtectionStatus {
        exam_protection_active: false,
        protection_dry_run: false,
        kiosk_active: false,
        overlay_active: false,
        taskbar_hidden: false,
        keyboard_hook_active: input_guard_result.active,
        focus_lock_active: focus_guard_result.active,
        input_hook_active: input_guard_result.active,
        mouse_hook_active: mouse_guard_result.active,
        focus_hook_active: focus_guard_result.active,
        clipboard_listener_active: false,
        overlay_heal_active: false,
        capture_heal_active: false,
        capture_protection_active: false,
        capture_protection_status: "inactive".to_string(),
        electron_content_protection_active: false,
        rust_overlay_capture_protection_active: false,
        capture_protection_best_effort: false,
        runtime_monitor_active: false,
        active_monitor_count: previous_status.active_monitor_count,
        black_overlay_count: 0,
        last_runtime_event_at: Some(now_ms + 9),
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
            if overlay_result.applied { "success" } else { "warn" },
            "DISPLAY_OVERLAY_RESTORED",
            overlay_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 2,
            if focus_guard_result.applied { "success" } else { "warn" },
            "FOCUS_GUARD_RESTORED",
            focus_guard_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 3,
            if taskbar_result.applied { "success" } else { "warn" },
            "TASKBAR_STATE_RESTORED",
            taskbar_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 4,
            if input_guard_result.applied { "success" } else { "warn" },
            "INPUT_GUARD_RESTORED",
            input_guard_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 5,
            if capture_guard_result.applied { "success" } else { "warn" },
            "CAPTURE_GUARD_RESTORED",
            capture_guard_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 6,
            if mouse_guard_result.applied { "success" } else { "warn" },
            "MOUSE_GUARD_RESTORED",
            mouse_guard_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 7,
            if accessibility_guard_result.applied {
                "success"
            } else {
                "warn"
            },
            "ACCESSIBILITY_GUARD_RESTORED",
            accessibility_guard_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 8,
            if clipboard_guard_result.applied {
                "success"
            } else {
                "warn"
            },
            "CLIPBOARD_GUARD_RESTORED",
            clipboard_guard_result.detail.clone(),
        ),
        build_log_line(
            now_ms + 9,
            "success",
            SESSION_STATE_RESTORING_DESKTOP,
            "Strict exam kiosk state was cleared and the desktop shell can return to idle.",
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
    use crate::accessibility_guard::AccessibilityGuardMutationResult;
    use crate::capture_guard::CaptureGuardMutationResult;
    use crate::clipboard_guard::ClipboardGuardMutationResult;
    use crate::display_guard::OverlayMutationResult;
    use crate::focus_guard::FocusGuardMutationResult;
    use crate::input_guard::InputGuardMutationResult;
    use crate::models::{DisplayInfo, MonitorInfo, ProtectionStatus};
    use crate::mouse_guard::MouseGuardMutationResult;
    use crate::taskbar_guard::TaskbarMutationResult;

    fn display_info(monitor_count: usize) -> DisplayInfo {
        let monitors = (0..monitor_count)
            .map(|index| MonitorInfo {
                device_name: format!("MONITOR-{index}"),
                width: 1920,
                height: 1080,
                offset_x: (index as i32) * 1920,
                offset_y: 0,
                is_primary: index == 0,
            })
            .collect::<Vec<_>>();

        DisplayInfo {
            monitor_count,
            monitors,
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

    fn focus_result(applied: bool, active: bool, detail: &str) -> FocusGuardMutationResult {
        FocusGuardMutationResult {
            applied,
            active,
            detail: detail.to_string(),
        }
    }

    fn overlay_result(applied: bool, active: bool, overlay_count: usize, detail: &str) -> OverlayMutationResult {
        OverlayMutationResult {
            applied,
            active,
            overlay_count,
            detail: detail.to_string(),
        }
    }

    fn capture_result(applied: bool, active: bool, status: &str, detail: &str) -> CaptureGuardMutationResult {
        CaptureGuardMutationResult {
            applied,
            active,
            status: status.to_string(),
            detail: detail.to_string(),
        }
    }

    fn mouse_result(applied: bool, active: bool, detail: &str) -> MouseGuardMutationResult {
        MouseGuardMutationResult {
            applied,
            active,
            detail: detail.to_string(),
        }
    }

    fn clipboard_result(applied: bool, detail: &str) -> ClipboardGuardMutationResult {
        ClipboardGuardMutationResult {
            applied,
            detail: detail.to_string(),
        }
    }

    fn accessibility_result(
        applied: bool,
        active: bool,
        detail: &str,
    ) -> AccessibilityGuardMutationResult {
        AccessibilityGuardMutationResult {
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
            input_hook_active: true,
            mouse_hook_active: true,
            focus_hook_active: false,
            clipboard_listener_active: true,
            overlay_heal_active: true,
            capture_heal_active: false,
            capture_protection_active: false,
            capture_protection_status: "inactive".to_string(),
            electron_content_protection_active: false,
            rust_overlay_capture_protection_active: false,
            capture_protection_best_effort: false,
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
            &display_info(3),
            &overlay_result(true, true, 2, "Native overlays active."),
            &taskbar_result(true, "Taskbar hidden."),
            &input_result(true, true, "Keyboard hook active."),
            &focus_result(true, true, "Focus guard active."),
            &capture_result(true, true, "exclude-from-capture", "Capture guard active."),
            true,
            &mouse_result(true, true, "Mouse clipped to primary."),
            &clipboard_result(true, "Clipboard cleared."),
            &accessibility_result(true, true, "Accessibility hotkeys disabled."),
        );

        assert_eq!(result.session_state, "ENTERING_KIOSK");
        assert!(result.protection_status.exam_protection_active);
        assert!(result.protection_status.kiosk_active);
        assert!(result.protection_status.overlay_active);
        assert_eq!(result.protection_status.black_overlay_count, 2);
        assert!(result.protection_status.keyboard_hook_active);
        assert!(result.protection_status.capture_protection_active);
        assert_eq!(
            result.protection_status.capture_protection_status,
            "electron-content-protection+exclude-from-capture"
        );
        assert!(result.protection_status.electron_content_protection_active);
        assert!(result.protection_status.capture_protection_best_effort);
    }

    #[test]
    fn exit_kiosk_clears_visual_shell_flags() {
        let result = build_exit_kiosk_result(
            1_782_600_400_000,
            &previous_status(),
            &overlay_result(true, false, 0, "Native overlays destroyed."),
            &taskbar_result(true, "Taskbar restored."),
            &focus_result(true, false, "Focus guard removed."),
            &input_result(true, false, "Keyboard hook removed."),
            &capture_result(true, false, "inactive", "Capture guard removed."),
            &mouse_result(true, false, "Mouse restored."),
            &accessibility_result(true, false, "Accessibility restored."),
            &clipboard_result(true, "Clipboard listener stopped."),
        );

        assert_eq!(result.session_state, "RESTORING_DESKTOP");
        assert_eq!(result.restored_desktop, Some(true));
        assert!(!result.protection_status.kiosk_active);
        assert!(!result.protection_status.overlay_active);
        assert!(!result.protection_status.keyboard_hook_active);
        assert_eq!(result.protection_status.black_overlay_count, 0);
    }
}
