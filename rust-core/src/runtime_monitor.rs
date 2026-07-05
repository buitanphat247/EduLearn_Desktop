use crate::clipboard_guard::ClipboardGuardMutationResult;
use crate::capture_guard::CaptureGuardMutationResult;
use crate::display_guard::OverlayMutationResult;
use crate::models::{
    DetectionSignal, DisplayInfo, ProcessCategories, ProcessPolicyMatch,
    ProcessRemediationReport, ProtectionLogLine, ProtectionStatus, RuntimeMonitorSummary,
    RuntimeMonitorTickResult,
};
use crate::policy_model::{ExamPolicy, REMEDIATION_FAILURE_CONTINUE_AND_AUDIT};
use crate::process_watcher::{ProcessWatcherBatchReport, ProcessWatcherProducerStatus};
use crate::runtime_events::RuntimeEvent;
use crate::runtime_state_engine::RuntimeStateEngineSnapshot;
use crate::runtime_policy::{evaluate_runtime_policy, RuntimePolicyInput};
use crate::runtime_telemetry::RuntimeTelemetrySnapshot;
use crate::session_guard::SESSION_STATE_RECOVERY_REQUIRED;
use crate::mouse_guard::MouseGuardMutationResult;

pub fn build_runtime_monitor_tick_result(
    collected_at: u64,
    session_state: &str,
    previous_status: &ProtectionStatus,
    display_info: &DisplayInfo,
    total_process_count: usize,
    process_categories: &ProcessCategories,
    vm_signals: &[DetectionSignal],
    remote_signals: &[DetectionSignal],
    screen_capture_signals: &[DetectionSignal],
    overlay_result: Option<&OverlayMutationResult>,
    mouse_guard_result: &MouseGuardMutationResult,
    clipboard_guard_result: &ClipboardGuardMutationResult,
    capture_guard_result: &CaptureGuardMutationResult,
    electron_content_protection_active: bool,
    process_remediation: ProcessRemediationReport,
    process_watcher: ProcessWatcherBatchReport,
    process_watcher_producer: ProcessWatcherProducerStatus,
    runtime_state_engine: RuntimeStateEngineSnapshot,
    runtime_telemetry: RuntimeTelemetrySnapshot,
    runtime_events: Vec<RuntimeEvent>,
    policy: &ExamPolicy,
) -> RuntimeMonitorTickResult {
    let mut timestamp = collected_at.saturating_sub(4_000);
    let mut log_lines = Vec::new();

    push_log_line(
        &mut log_lines,
        &mut timestamp,
        "info",
        "RUNTIME_MONITOR_TICK",
        "Running desktop runtime monitor tick.",
    );

    if previous_status.active_monitor_count != display_info.monitor_count {
        push_log_line(
            &mut log_lines,
            &mut timestamp,
            "warn",
            "DISPLAY_TOPOLOGY_CHANGED",
            format!(
                "Monitor topology changed from {} to {} active display(s).",
                previous_status.active_monitor_count, display_info.monitor_count
            ),
        );
    }

    if let Some(overlay_result) = overlay_result {
        if overlay_result.applied {
            push_log_line(
                &mut log_lines,
                &mut timestamp,
                if overlay_result.active { "success" } else { "info" },
                "OVERLAY_SYNC",
                overlay_result.detail.clone(),
            );
        }
    }

    if !mouse_guard_result.applied || !mouse_guard_result.active {
        push_log_line(
            &mut log_lines,
            &mut timestamp,
            "block",
            "MOUSE_GUARD_RECLIP_FAILED",
            mouse_guard_result.detail.clone(),
        );
    }

    if !clipboard_guard_result.applied {
        push_log_line(
            &mut log_lines,
            &mut timestamp,
            "warn",
            "CLIPBOARD_GUARD_INACTIVE",
            clipboard_guard_result.detail.clone(),
        );
    }

    let rust_overlay_capture_protection_active = overlay_result
        .map(|result| result.active)
        .unwrap_or(previous_status.rust_overlay_capture_protection_active);
    let capture_protection_best_effort = electron_content_protection_active
        || rust_overlay_capture_protection_active
        || capture_guard_result.active;
    let capture_protection_status = if electron_content_protection_active && capture_guard_result.active {
        format!("electron-content-protection+{}", capture_guard_result.status)
    } else if electron_content_protection_active {
        "electron-content-protection-active".to_string()
    } else if capture_guard_result.active {
        capture_guard_result.status.clone()
    } else {
        "inactive".to_string()
    };

    if (!capture_guard_result.applied || !capture_guard_result.active)
        && !electron_content_protection_active
    {
        push_log_line(
            &mut log_lines,
            &mut timestamp,
            if policy.capture_protection_required {
                "block"
            } else {
                "warn"
            },
            "CAPTURE_GUARD_HEAL_FAILED",
            capture_guard_result.detail.clone(),
        );
    }

    let display_policy_violated = display_info.monitor_count > policy.max_monitor_count;
    if display_policy_violated {
        push_log_line(
            &mut log_lines,
            &mut timestamp,
            "block",
            "DISPLAY_POLICY_VIOLATION",
            format!(
                "{} monitor(s) are active, but policy {} allows at most {}.",
                display_info.monitor_count, policy.policy_version, policy.max_monitor_count
            ),
        );
    }

    push_log_line(
        &mut log_lines,
        &mut timestamp,
        "info",
        "PROCESS_HEARTBEAT",
        format!(
            "Runtime scan: {} process(es), {} remote app(s), {} capture app(s), {} VM signal(s).",
            total_process_count,
            process_categories.remote_desktop.len(),
            process_categories.screen_capture.len(),
            vm_signals.len()
        ),
    );

    for signal in remote_signals {
        push_log_line(
            &mut log_lines,
            &mut timestamp,
            "warn",
            "REMOTE_SIGNAL_RECURRING",
            format!("{}: {}", signal.label, signal.detail),
        );
    }

    for signal in screen_capture_signals {
        push_log_line(
            &mut log_lines,
            &mut timestamp,
            "warn",
            "SCREEN_CAPTURE_SIGNAL",
            format!("{}: {}", signal.label, signal.detail),
        );
    }

    for action in &process_remediation.actions {
        let level = match action.status.as_str() {
            "terminated" => "block",
            "failed" => "block",
            _ => "info",
        };
        let code = match action.status.as_str() {
            "terminated" => "PROCESS_TERMINATED",
            "failed" => "PROCESS_TERMINATION_FAILED",
            _ => "PROCESS_REMEDIATION",
        };

        push_log_line(
            &mut log_lines,
            &mut timestamp,
            level,
            code,
            format!(
                "{} (pid {}, category {}) | {}",
                action.name, action.pid, action.category, action.detail
            ),
        );
    }

    if process_remediation.failed_count > 0
        && policy.remediation_failure_mode == REMEDIATION_FAILURE_CONTINUE_AND_AUDIT
    {
        push_log_line(
            &mut log_lines,
            &mut timestamp,
            "warn",
            "PROCESS_REMEDIATION_CONTINUE_AND_AUDIT",
            "A prohibited process could not be terminated, but policy remediationFailureMode=continueAndAudit keeps the exam running while runtime remediation retries and audit logs record the failure.",
        );
    }

    for signal in vm_signals {
        push_log_line(
            &mut log_lines,
            &mut timestamp,
            "warn",
            "VM_SIGNAL_RECURRING",
            format!("{}: {}", signal.label, signal.detail),
        );
    }

    if !vm_signals.is_empty() {
        push_log_line(
            &mut log_lines,
            &mut timestamp,
            "block",
            "POLICY_ENFORCEMENT_BLOCK",
            "A virtual-machine signal cannot be remediated by closing a capture process. Strict runtime policy requires recovery.",
        );
    } else if !remote_signals.is_empty() || !screen_capture_signals.is_empty() {
        push_log_line(
            &mut log_lines,
            &mut timestamp,
            "warn",
            "POLICY_ENFORCEMENT_ISOLATION",
            "The exam remains active under monitored isolation and best-effort capture protection for policy-allowed remote-control or capture processes.",
        );
    } else {
        push_log_line(
            &mut log_lines,
            &mut timestamp,
            "success",
            "RUNTIME_MONITOR_CLEAN",
            "No new remote-control, screen-capture or VM recurrence was detected in this tick.",
        );
    }

    let policy_decision = evaluate_runtime_policy(
        &RuntimePolicyInput {
            vm_signal_count: vm_signals.len(),
            monitor_count: display_info.monitor_count,
            capture_protection_best_effort,
            pending_termination_count: process_remediation.pending_termination_count,
            failed_termination_count: process_remediation.failed_count,
        },
        policy,
    );
    let next_session_state = if policy_decision.recovery_required {
        SESSION_STATE_RECOVERY_REQUIRED
    } else {
        session_state
    };
    let capture_protection_status = if !vm_signals.is_empty() {
        "vm-risk-detected".to_string()
    } else {
        capture_protection_status
    };

    let protection_status = ProtectionStatus {
        exam_protection_active: previous_status.exam_protection_active,
        protection_dry_run: previous_status.protection_dry_run,
        kiosk_active: previous_status.kiosk_active,
        overlay_active: overlay_result
            .map(|result| result.active)
            .unwrap_or(previous_status.overlay_active),
        taskbar_hidden: previous_status.taskbar_hidden,
        keyboard_hook_active: previous_status.keyboard_hook_active,
        focus_lock_active: previous_status.focus_lock_active,
        input_hook_active: previous_status.keyboard_hook_active,
        mouse_hook_active: mouse_guard_result.active,
        focus_hook_active: previous_status.focus_lock_active,
        clipboard_listener_active: clipboard_guard_result.applied,
        overlay_heal_active: overlay_result.map(|result| result.applied).unwrap_or(false),
        capture_heal_active: capture_protection_best_effort,
        capture_protection_active: capture_protection_best_effort,
        capture_protection_status,
        electron_content_protection_active,
        rust_overlay_capture_protection_active,
        capture_protection_best_effort,
        runtime_monitor_active: true,
        active_monitor_count: display_info.monitor_count,
        black_overlay_count: overlay_result
            .map(|result| result.overlay_count)
            .unwrap_or(previous_status.black_overlay_count),
        last_runtime_event_at: Some(collected_at),
    };

    let process_policy = process_policy_from_remediation(&process_remediation);
    let runtime_risk_level = if process_policy.iter().any(|process| {
        process.action == "continueAndAudit"
            || process.action == "attemptTerminateThenContinue"
            || process.action == "isolateAndProtect"
            || process.action == "warnOnly"
    }) {
        "elevated"
    } else {
        "normal"
    };

    RuntimeMonitorTickResult {
        collected_at,
        session_state: next_session_state.to_string(),
        summary: RuntimeMonitorSummary {
            total_process_count,
            monitor_count: display_info.monitor_count,
            remote_signal_count: remote_signals.len(),
            screen_capture_signal_count: screen_capture_signals.len(),
            vm_signal_count: vm_signals.len(),
        },
        process_watcher,
        process_watcher_producer,
        runtime_state_engine,
        runtime_telemetry,
        runtime_events,
        display_info: display_info.clone(),
        remote_signals: remote_signals.to_vec(),
        screen_capture_signals: screen_capture_signals.to_vec(),
        vm_signals: vm_signals.to_vec(),
        process_remediation,
        runtime_risk_level: runtime_risk_level.to_string(),
        process_policy,
        protection_status,
        log_lines,
    }
}

fn process_policy_from_remediation(
    report: &ProcessRemediationReport,
) -> Vec<ProcessPolicyMatch> {
    report
        .actions
        .iter()
        .map(|action| ProcessPolicyMatch {
            pid: action.pid,
            name: action.name.clone(),
            executable_path: None,
            creation_time_ms: None,
            category: action.category.clone(),
            action: action.action.clone(),
            severity: if action.action == "hardBlock"
                || action.action == "attemptTerminateThenBlock"
            {
                "critical".to_string()
            } else {
                "high".to_string()
            },
            allow_exam_start: action.action != "hardBlock"
                && action.action != "attemptTerminateThenBlock",
            attempt_terminate: action.action == "attemptTerminateThenBlock"
                || action.action == "attemptTerminateThenContinue",
            audit_required: action.action != "ignore",
        })
        .collect()
}

fn push_log_line(
    lines: &mut Vec<ProtectionLogLine>,
    timestamp: &mut u64,
    level: &str,
    code: &str,
    message: impl Into<String>,
) {
    lines.push(ProtectionLogLine {
        timestamp: *timestamp,
        level: level.to_string(),
        code: code.to_string(),
        message: message.into(),
    });
    *timestamp = timestamp.saturating_add(1_000);
}

#[cfg(test)]
mod tests {
    use super::build_runtime_monitor_tick_result;
    use crate::capture_guard::CaptureGuardMutationResult;
    use crate::clipboard_guard::ClipboardGuardMutationResult;
    use crate::display_guard::OverlayMutationResult;
    use crate::mouse_guard::MouseGuardMutationResult;
    use crate::models::{
        DetectionSignal, DisplayInfo, MonitorInfo, ProcessCategories, ProcessRemediationReport,
        ProtectionStatus,
    };
    use crate::policy_model::ExamPolicy;
    use crate::process_watcher::{
        default_process_watcher_producer_status, ProcessWatcherBatchReport, ProcessWatcherSource,
    };
    use crate::runtime_state_engine::{RuntimeStateEngine, RuntimeStateEngineSnapshot};
    use crate::runtime_telemetry::RuntimeTelemetrySnapshot;
    use crate::session_guard::{SESSION_STATE_EXAM_RUNNING, SESSION_STATE_RECOVERY_REQUIRED};

    fn protection_status() -> ProtectionStatus {
        ProtectionStatus {
            exam_protection_active: true,
            protection_dry_run: false,
            kiosk_active: true,
            overlay_active: false,
            taskbar_hidden: true,
            keyboard_hook_active: true,
            focus_lock_active: true,
            input_hook_active: true,
            mouse_hook_active: true,
            focus_hook_active: true,
            clipboard_listener_active: true,
            overlay_heal_active: true,
            capture_heal_active: true,
            capture_protection_active: true,
            capture_protection_status: "exclude-from-capture".to_string(),
            electron_content_protection_active: false,
            rust_overlay_capture_protection_active: false,
            capture_protection_best_effort: true,
            runtime_monitor_active: true,
            active_monitor_count: 1,
            black_overlay_count: 0,
            last_runtime_event_at: Some(1),
        }
    }

    fn display_info() -> DisplayInfo {
        DisplayInfo {
            monitor_count: 1,
            monitors: vec![MonitorInfo {
                device_name: "DISPLAY1".to_string(),
                width: 1920,
                height: 1080,
                offset_x: 0,
                offset_y: 0,
                is_primary: true,
            }],
        }
    }

    fn empty_categories() -> ProcessCategories {
        ProcessCategories {
            browser: Vec::new(),
            communication: Vec::new(),
            policy_blocked: Vec::new(),
            remote_desktop: Vec::new(),
            screen_capture: Vec::new(),
            virtual_machine: Vec::new(),
            debug_tools: Vec::new(),
        }
    }

    fn signal(id: &str) -> DetectionSignal {
        DetectionSignal {
            id: id.to_string(),
            label: "Remote access process".to_string(),
            detail: "AnyDesk.exe (pid 42)".to_string(),
            severity: "warn".to_string(),
            source: "process".to_string(),
        }
    }

    fn remediation_report(pending: usize, terminated: usize) -> ProcessRemediationReport {
        ProcessRemediationReport {
            grace_period_ms: 0,
            pending_termination_count: pending,
            terminated_count: terminated,
            failed_count: 0,
            actions: Vec::new(),
        }
    }

    fn failed_remediation_report() -> ProcessRemediationReport {
        ProcessRemediationReport {
            grace_period_ms: 0,
            pending_termination_count: 0,
            terminated_count: 0,
            failed_count: 1,
            actions: Vec::new(),
        }
    }

    fn mouse_guard_result() -> MouseGuardMutationResult {
        MouseGuardMutationResult {
            applied: true,
            active: true,
            detail: "Mouse re-clipped.".to_string(),
        }
    }

    fn clipboard_guard_result() -> ClipboardGuardMutationResult {
        ClipboardGuardMutationResult {
            applied: true,
            detail: "Clipboard cleared.".to_string(),
        }
    }

    fn capture_guard_result() -> CaptureGuardMutationResult {
        CaptureGuardMutationResult {
            applied: true,
            active: true,
            status: "exclude-from-capture".to_string(),
            detail: "Capture affinity re-applied.".to_string(),
        }
    }

    fn watcher_report() -> ProcessWatcherBatchReport {
        ProcessWatcherBatchReport {
            source: ProcessWatcherSource::Polling,
            event_count: 0,
            remediation_count: 0,
            ignored_count: 0,
            max_detection_latency_ms: 0,
            ignored_reasons: Vec::new(),
        }
    }

    fn telemetry() -> RuntimeTelemetrySnapshot {
        RuntimeTelemetrySnapshot {
            runtime_latency_ms: 25,
            runtime_tick_duration_ms: 25,
            watcher_latency_ms: 0,
            detection_latency_ms: 0,
            classification_latency_ms: 5,
            process_classification_time_ms: 5,
            kill_latency_ms: 3,
            remediation_time_ms: 3,
            recovery_latency_ms: 0,
            queue_latency_ms: 0,
            producer_latency_ms: 0,
            guard_restart_count: 0,
            watchdog_restart_count: 0,
            event_queue_length: 0,
            runtime_health: "healthy".to_string(),
        }
    }

    fn runtime_state_snapshot() -> RuntimeStateEngineSnapshot {
        RuntimeStateEngine::new().snapshot()
    }

    #[test]
    fn runtime_monitor_keeps_exam_running_while_remote_process_is_isolated() {
        let remote_signals = vec![signal("remote-process-42")];
        let result = build_runtime_monitor_tick_result(
            1_782_600_500_000,
            SESSION_STATE_EXAM_RUNNING,
            &protection_status(),
            &display_info(),
            100,
            &empty_categories(),
            &[],
            &remote_signals,
            &[],
            None,
            &mouse_guard_result(),
            &clipboard_guard_result(),
            &capture_guard_result(),
            false,
            remediation_report(0, 1),
            watcher_report(),
            default_process_watcher_producer_status(),
            runtime_state_snapshot(),
            telemetry(),
            Vec::new(),
            &ExamPolicy::strict_builtin(),
        );

        assert_eq!(result.session_state, SESSION_STATE_EXAM_RUNNING);
        assert_eq!(
            result.protection_status.capture_protection_status,
            "exclude-from-capture"
        );
        assert!(result
            .log_lines
            .iter()
            .any(|line| line.code == "POLICY_ENFORCEMENT_ISOLATION"));
    }

    #[test]
    fn runtime_monitor_requires_recovery_when_vm_signal_is_detected() {
        let vm_signals = vec![signal("vm-process-42")];
        let result = build_runtime_monitor_tick_result(
            1_782_600_500_000,
            SESSION_STATE_EXAM_RUNNING,
            &protection_status(),
            &display_info(),
            100,
            &empty_categories(),
            &vm_signals,
            &[],
            &[],
            None,
            &mouse_guard_result(),
            &clipboard_guard_result(),
            &capture_guard_result(),
            false,
            remediation_report(0, 0),
            watcher_report(),
            default_process_watcher_producer_status(),
            runtime_state_snapshot(),
            telemetry(),
            Vec::new(),
            &ExamPolicy::strict_builtin(),
        );

        assert_eq!(result.session_state, SESSION_STATE_RECOVERY_REQUIRED);
        assert_eq!(
            result.protection_status.capture_protection_status,
            "vm-risk-detected"
        );
        assert!(result
            .log_lines
            .iter()
            .any(|line| line.code == "POLICY_ENFORCEMENT_BLOCK"));
    }

    #[test]
    fn runtime_monitor_keeps_exam_running_when_tick_is_clean() {
        let overlay_result = OverlayMutationResult {
            applied: true,
            active: false,
            overlay_count: 0,
            detail: "No secondary monitors.".to_string(),
        };
        let result = build_runtime_monitor_tick_result(
            1_782_600_500_000,
            SESSION_STATE_EXAM_RUNNING,
            &protection_status(),
            &display_info(),
            100,
            &empty_categories(),
            &[],
            &[],
            &[],
            Some(&overlay_result),
            &mouse_guard_result(),
            &clipboard_guard_result(),
            &capture_guard_result(),
            false,
            remediation_report(0, 0),
            watcher_report(),
            default_process_watcher_producer_status(),
            runtime_state_snapshot(),
            telemetry(),
            Vec::new(),
            &ExamPolicy::strict_builtin(),
        );

        assert_eq!(result.session_state, SESSION_STATE_EXAM_RUNNING);
        assert_eq!(result.protection_status.capture_protection_status, "exclude-from-capture");
    }

    #[test]
    fn clean_tick_clears_a_previous_process_risk_status() {
        let mut previous_status = protection_status();
        previous_status.capture_protection_status = "screen-capture-risk-detected".to_string();
        let result = build_runtime_monitor_tick_result(
            1_782_600_500_000,
            SESSION_STATE_EXAM_RUNNING,
            &previous_status,
            &display_info(),
            100,
            &empty_categories(),
            &[],
            &[],
            &[],
            None,
            &mouse_guard_result(),
            &clipboard_guard_result(),
            &capture_guard_result(),
            false,
            remediation_report(0, 1),
            watcher_report(),
            default_process_watcher_producer_status(),
            runtime_state_snapshot(),
            telemetry(),
            Vec::new(),
            &ExamPolicy::strict_builtin(),
        );

        assert_eq!(result.session_state, SESSION_STATE_EXAM_RUNNING);
        assert_eq!(
            result.protection_status.capture_protection_status,
            "exclude-from-capture"
        );
    }

    #[test]
    fn runtime_tick_logs_guard_recovery_failures() {
        let mouse_result = MouseGuardMutationResult {
            applied: false,
            active: false,
            detail: "ClipCursor denied.".to_string(),
        };
        let clipboard_result = ClipboardGuardMutationResult {
            applied: false,
            detail: "Clipboard busy.".to_string(),
        };
        let capture_result = CaptureGuardMutationResult {
            applied: false,
            active: false,
            status: "failed".to_string(),
            detail: "Affinity rejected.".to_string(),
        };
        let result = build_runtime_monitor_tick_result(
            1_782_600_500_000,
            SESSION_STATE_EXAM_RUNNING,
            &protection_status(),
            &display_info(),
            100,
            &empty_categories(),
            &[],
            &[],
            &[],
            None,
            &mouse_result,
            &clipboard_result,
            &capture_result,
            false,
            remediation_report(0, 0),
            watcher_report(),
            default_process_watcher_producer_status(),
            runtime_state_snapshot(),
            telemetry(),
            Vec::new(),
            &ExamPolicy::strict_builtin(),
        );

        assert!(result
            .log_lines
            .iter()
            .any(|line| line.code == "MOUSE_GUARD_RECLIP_FAILED"));
        assert!(result
            .log_lines
            .iter()
            .any(|line| line.code == "CLIPBOARD_GUARD_INACTIVE"));
        assert!(result
            .log_lines
            .iter()
            .any(|line| line.code == "CAPTURE_GUARD_HEAL_FAILED"));
        assert!(!result.protection_status.capture_protection_active);
    }

    #[test]
    fn electron_content_protection_prevents_false_recovery_when_rust_wda_fails() {
        let capture_result = CaptureGuardMutationResult {
            applied: false,
            active: false,
            status: "electron-owned-window-skipped".to_string(),
            detail: "Electron owns content protection for the exam window.".to_string(),
        };
        let result = build_runtime_monitor_tick_result(
            1_782_600_500_000,
            SESSION_STATE_EXAM_RUNNING,
            &protection_status(),
            &display_info(),
            100,
            &empty_categories(),
            &[],
            &[],
            &[],
            None,
            &mouse_guard_result(),
            &clipboard_guard_result(),
            &capture_result,
            true,
            remediation_report(0, 0),
            watcher_report(),
            default_process_watcher_producer_status(),
            runtime_state_snapshot(),
            telemetry(),
            Vec::new(),
            &ExamPolicy::strict_builtin(),
        );

        assert_eq!(result.session_state, SESSION_STATE_EXAM_RUNNING);
        assert!(result.protection_status.capture_protection_active);
        assert!(result.protection_status.electron_content_protection_active);
        assert_eq!(
            result.protection_status.capture_protection_status,
            "electron-content-protection-active"
        );
        assert!(!result
            .log_lines
            .iter()
            .any(|line| line.code == "CAPTURE_GUARD_HEAL_FAILED"));
    }

    #[test]
    fn failed_process_remediation_requires_recovery_by_default() {
        let result = build_runtime_monitor_tick_result(
            1_782_600_500_000,
            SESSION_STATE_EXAM_RUNNING,
            &protection_status(),
            &display_info(),
            100,
            &empty_categories(),
            &[],
            &[],
            &[],
            None,
            &mouse_guard_result(),
            &clipboard_guard_result(),
            &capture_guard_result(),
            false,
            failed_remediation_report(),
            watcher_report(),
            default_process_watcher_producer_status(),
            runtime_state_snapshot(),
            telemetry(),
            Vec::new(),
            &ExamPolicy::strict_builtin(),
        );

        assert_eq!(result.session_state, SESSION_STATE_RECOVERY_REQUIRED);
    }

    #[test]
    fn failed_process_remediation_can_continue_and_audit_by_policy() {
        let mut policy = ExamPolicy::strict_builtin();
        policy.remediation_failure_mode = "continueAndAudit".to_string();
        let result = build_runtime_monitor_tick_result(
            1_782_600_500_000,
            SESSION_STATE_EXAM_RUNNING,
            &protection_status(),
            &display_info(),
            100,
            &empty_categories(),
            &[],
            &[],
            &[],
            None,
            &mouse_guard_result(),
            &clipboard_guard_result(),
            &capture_guard_result(),
            false,
            failed_remediation_report(),
            watcher_report(),
            default_process_watcher_producer_status(),
            runtime_state_snapshot(),
            telemetry(),
            Vec::new(),
            &policy,
        );

        assert_eq!(result.session_state, SESSION_STATE_EXAM_RUNNING);
        assert!(result
            .log_lines
            .iter()
            .any(|line| line.code == "PROCESS_REMEDIATION_CONTINUE_AND_AUDIT"));
    }

    #[test]
    fn runtime_tick_exposes_watcher_and_telemetry_payloads() {
        let mut watcher = watcher_report();
        watcher.source = ProcessWatcherSource::Wmi;
        watcher.event_count = 2;
        watcher.max_detection_latency_ms = 42;
        let result = build_runtime_monitor_tick_result(
            1_782_600_500_000,
            SESSION_STATE_EXAM_RUNNING,
            &protection_status(),
            &display_info(),
            100,
            &empty_categories(),
            &[],
            &[],
            &[],
            None,
            &mouse_guard_result(),
            &clipboard_guard_result(),
            &capture_guard_result(),
            false,
            remediation_report(0, 0),
            watcher,
            default_process_watcher_producer_status(),
            runtime_state_snapshot(),
            telemetry(),
            Vec::new(),
            &ExamPolicy::strict_builtin(),
        );

        assert_eq!(result.process_watcher.source, ProcessWatcherSource::Wmi);
        assert_eq!(result.process_watcher.event_count, 2);
        assert_eq!(result.process_watcher.max_detection_latency_ms, 42);
        assert_eq!(result.runtime_telemetry.runtime_health, "healthy");
    }
}
