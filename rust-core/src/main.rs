mod accessibility_guard;
mod audit_log;
mod collectors;
mod capture_guard;
mod clipboard_guard;
mod desktop_state;
mod desktop_isolation;
mod evaluation;
mod etw_producer;
mod exam_key;
mod display_guard;
mod dpi_awareness;
mod focus_guard;
mod guard_liveness;
mod input_guard;
mod ipc_auth;
mod ipc_pipe;
mod kiosk_guard;
mod models;
mod mouse_guard;
mod policy;
mod policy_loader;
mod policy_model;
mod policy_signature;
mod process_remediation;
mod process_watcher;
mod process_policy;
mod rules;
mod runtime_monitor;
mod runtime_events;
mod runtime_policy;
mod runtime_scheduler;
mod runtime_state_engine;
mod runtime_telemetry;
mod service_client;
mod session_guard;
mod taskbar_guard;

use accessibility_guard::{
    activate_accessibility_guard, deactivate_accessibility_guard,
    restore_accessibility_after_unclean_shutdown,
};
use audit_log::append_audit_event;
use collectors::{
    collect_display_info, collect_precheck_snapshot_with_policy,
    collect_process_categories_from_processes, collect_remote_signals,
    collect_screen_capture_signals, collect_system_info, collect_vm_signals, ProcessCollector,
};
use capture_guard::{
    activate_capture_guard, deactivate_capture_guard, re_apply_capture_guard,
    CaptureGuardMutationResult,
};
use clipboard_guard::{
    activate_clipboard_guard, deactivate_clipboard_guard,
};
use desktop_state::capture_desktop_state;
use desktop_isolation::restore_default_input_desktop;
use display_guard::{activate_native_overlays, deactivate_native_overlays, sync_native_overlays};
use dpi_awareness::activate_per_monitor_v2_awareness;
use evaluation::{build_precheck_report_with_policy, build_preflight_result_with_policy};
use exam_key::{
    build_elevated_termination_request, get_exam_device_identity, sign_exam_challenge,
    verify_exam_receipt, verify_service_authorization, ExamChallengePayload,
    SignedExamReceipt,
};
use focus_guard::{activate_focus_guard, deactivate_focus_guard};
use input_guard::{activate_input_guard, deactivate_input_guard};
use ipc_auth::{AuthenticatedFrame, IpcAuthenticator};
use kiosk_guard::{build_enter_kiosk_result, build_exit_kiosk_result};
use models::{
    DesktopStateSnapshot, DetectionSignal, EnterKioskPayload, ExitExamSessionPayload,
    LoadExamPolicyPayload, PrecheckReport, PreflightKillPayload, PreflightResult,
    ProtectionStatus, RuntimeMonitorTickPayload, StartExamSessionPayload,
};
use mouse_guard::{activate_mouse_guard, deactivate_mouse_guard};
use process_remediation::{
    preflight_remediate_policy_processes_using, terminate_process_user_mode,
    PreflightKillReport, RuntimeProcessRemediator,
};
use process_watcher::{
    ProcessCreationWatcher, ProcessWatcherBatch, ProcessWatcherSource,
    RuntimeProcessWatcherProducer,
};
use policy_loader::{load_signed_exam_policy, LoadedExamPolicy};
use policy_signature::TrustedPolicyKeys;
use service_client::request_elevated_termination;
use runtime_monitor::build_runtime_monitor_tick_result;
use runtime_events::{
    metadata as event_metadata, RuntimeEventBus, EVENT_CAPTURE_DETECTED, EVENT_DESKTOP_CHANGED,
    EVENT_POLICY_RELOADED, EVENT_PROCESS_CREATED, EVENT_PROCESS_EXITED, EVENT_PRODUCER_HEARTBEAT,
    EVENT_PRODUCER_DEGRADED, EVENT_RECOVERY_COMPLETED, EVENT_RECOVERY_STARTED,
    EVENT_RUNTIME_STATE_CHANGED,
    EVENT_RUNTIME_STOPPED,
};
use runtime_scheduler::{
    RuntimeMonitorScheduler, DEFAULT_ENVIRONMENT_SCAN_INTERVAL_MS,
};
use runtime_state_engine::{RuntimeLifecycleState, RuntimeStateEngine, RuntimeStateProducer};
use runtime_telemetry::{RuntimeTelemetry, RuntimeTelemetrySample};
use serde::{Deserialize, Serialize};
use serde_json::{json, to_value, Value};
use session_guard::{
    build_exit_exam_session_result, build_idle_protection_status, build_start_exam_session_result,
    is_valid_session_transition, SESSION_STATE_EXAM_RUNNING, SESSION_STATE_IDLE,
    SESSION_STATE_INIT, SESSION_STATE_PREFLIGHT_READY,
    SESSION_STATE_STARTING_EXAM_SESSION,
};
use taskbar_guard::{hide_taskbar, show_taskbar};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const CORE_VERSION: &str = "0.0.1";
const SESSION_STATE_CORE_READY: &str = "CORE_READY";

#[derive(Debug)]
struct CoreRuntimeState {
    precheck_report: Option<PrecheckReport>,
    preflight_result: Option<PreflightResult>,
    session_state: String,
    protection_status: ProtectionStatus,
    desktop_state_snapshot: Option<DesktopStateSnapshot>,
    active_session_id: Option<String>,
    exam_window_handle_hex: Option<String>,
    process_remediator: RuntimeProcessRemediator,
    process_creation_watcher: ProcessCreationWatcher,
    process_event_producer: RuntimeProcessWatcherProducer,
    runtime_event_bus: RuntimeEventBus,
    runtime_state_engine: RuntimeStateEngine,
    runtime_telemetry: RuntimeTelemetry,
    runtime_scheduler: RuntimeMonitorScheduler,
    cached_vm_signals: Vec<DetectionSignal>,
    process_collector: ProcessCollector,
    loaded_policy: LoadedExamPolicy,
    trusted_policy_keys: TrustedPolicyKeys,
    require_signed_policy: bool,
    active_service_authorization: Option<SignedExamReceipt>,
}

impl Drop for CoreRuntimeState {
    fn drop(&mut self) {
        if has_active_protection(self) {
            let _ = restore_active_protection(
                self,
                Some(
                    "Rust core is exiting without a completed shutdown; restoring desktop protection state."
                        .to_string(),
                ),
            );
        }
    }
}

#[derive(Debug, Deserialize)]
struct CoreRequest {
    #[serde(rename = "requestId")]
    request_id: String,
    cmd: String,
    #[serde(default)]
    payload: Value,
}

#[derive(Debug, Serialize)]
struct CoreError {
    code: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
struct CoreResponse {
    #[serde(rename = "requestId")]
    request_id: String,
    ok: bool,
    data: Value,
    error: Option<CoreError>,
}

#[derive(Debug, Serialize)]
struct CoreEvent {
    #[serde(rename = "eventId")]
    event_id: String,
    event: &'static str,
    severity: &'static str,
    timestamp: u64,
    data: Value,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn write_json_line<T: Serialize>(value: &T) -> io::Result<()> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer(&mut lock, value)?;
    lock.write_all(b"\n")?;
    lock.flush()
}

fn write_json_line_to<T: Serialize, W: Write>(writer: &mut W, value: &T) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn success_response(request_id: &str, data: Value) -> CoreResponse {
    CoreResponse {
        request_id: request_id.to_string(),
        ok: true,
        data,
        error: None,
    }
}

fn error_response(request_id: &str, code: &'static str, message: impl Into<String>) -> CoreResponse {
    CoreResponse {
        request_id: request_id.to_string(),
        ok: false,
        data: Value::Null,
        error: Some(CoreError {
            code,
            message: message.into(),
        }),
    }
}

fn build_status_snapshot(state: &CoreRuntimeState) -> Value {
    let latest_report = state
        .preflight_result
        .as_ref()
        .map(|result| &result.report)
        .or(state.precheck_report.as_ref());
    let precheck_summary = latest_report
        .and_then(|report| to_value(&report.snapshot.summary).ok())
        .unwrap_or(Value::Null);
    let precheck_recommendations = latest_report
        .and_then(|report| to_value(&report.evaluation.secondary_recommendations).ok())
        .unwrap_or(Value::Null);

    let safe_exam_mode = state.protection_status.exam_protection_active
        || state.protection_status.kiosk_active
        || state.session_state == SESSION_STATE_EXAM_RUNNING;

    json!({
        "safeExamMode": safe_exam_mode,
        "nativeCoreConnected": true,
        "coreVersion": CORE_VERSION,
        "sessionState": state.session_state,
        "lastCoreHeartbeat": now_ms(),
        "precheckCollectedAt": latest_report.map(|report| report.collected_at),
        "precheckAvailable": latest_report.is_some(),
        "precheckSummary": precheck_summary,
        "precheckStatus": latest_report.map(|report| report.evaluation.status.clone()),
        "precheckRiskScore": latest_report.map(|report| report.evaluation.total_risk_score),
        "precheckRecommendations": precheck_recommendations,
        "preflightCollectedAt": state.preflight_result.as_ref().map(|result| result.collected_at),
        "preflightStatus": state.preflight_result.as_ref().map(|result| result.decision.status.clone()),
        "preflightCanEnterExam": state.preflight_result.as_ref().map(|result| result.decision.can_enter_exam),
        "preflightPrimaryReasonCode": state
            .preflight_result
            .as_ref()
            .map(|result| result.decision.primary_reason_code.clone()),
        "examProtectionActive": state.protection_status.exam_protection_active,
        "protectionDryRun": state.protection_status.protection_dry_run,
        "kioskActive": state.protection_status.kiosk_active,
        "overlayActive": state.protection_status.overlay_active,
        "taskbarHidden": state.protection_status.taskbar_hidden,
        "keyboardHookActive": state.protection_status.keyboard_hook_active,
        "focusLockActive": state.protection_status.focus_lock_active,
        "captureProtectionActive": state.protection_status.capture_protection_active,
        "captureProtectionStatus": state.protection_status.capture_protection_status,
        "runtimeMonitorActive": state.protection_status.runtime_monitor_active,
        "activeMonitorCount": state.protection_status.active_monitor_count,
        "blackOverlayCount": state.protection_status.black_overlay_count,
        "lastRuntimeEventAt": state.protection_status.last_runtime_event_at,
        "errorCode": Value::Null,
        "policyVersion": state.loaded_policy.policy.policy_version,
        "policySource": state.loaded_policy.source,
        "policyDigestSha256": state.loaded_policy.digest_sha256,
        "signedPolicyRequired": state.require_signed_policy,
        "processWatcherProducer": state.process_event_producer.status(),
        "runtimeStateEngine": state.runtime_state_engine.snapshot(),
        "runtimeTelemetry": state.runtime_telemetry.last_snapshot(),
        "runtimeEvents": state.runtime_event_bus.recent_events(25),
    })
}

fn value_from_serializable<T: Serialize>(request_id: &str, value: &T) -> CoreResponse {
    match to_value(value) {
        Ok(json_value) => success_response(request_id, json_value),
        Err(error) => error_response(
            request_id,
            "IPC_FAILURE",
            format!("Failed to serialize response payload: {error}"),
        ),
    }
}

fn is_audited_command(cmd: &str) -> bool {
    matches!(
        cmd,
        "load_policy"
            | "preflight_kill"
            | "run_preflight"
            | "start_exam_session"
            | "enter_kiosk"
            | "exit_exam_session"
            | "exit_kiosk"
            | "force_restore_desktop"
            | "sync_display_topology"
            | "run_runtime_monitor_tick"
            | "shutdown"
    )
}

fn audit_core_command(state: &CoreRuntimeState, request: &CoreRequest, response: &CoreResponse) {
    if !is_audited_command(&request.cmd) {
        return;
    }

    let process_remediation = response
        .data
        .get("processRemediation")
        .cloned()
        .unwrap_or(Value::Null);
    let runtime_logs = response
        .data
        .get("logs")
        .and_then(Value::as_array)
        .map(|logs| logs.len())
        .unwrap_or(0);
    let process_watcher_producer = response
        .data
        .get("processWatcherProducer")
        .cloned()
        .unwrap_or(Value::Null);
    let severity = if response.ok { "INFO" } else { "WARN" };
    let data = json!({
        "cmd": request.cmd,
        "ok": response.ok,
        "errorCode": response.error.as_ref().map(|error| error.code),
        "runtimeLogCount": runtime_logs,
        "processRemediation": process_remediation,
        "processWatcherProducer": process_watcher_producer,
        "protection": {
            "kioskActive": state.protection_status.kiosk_active,
            "captureProtectionBestEffort": state.protection_status.capture_protection_best_effort,
            "overlayActive": state.protection_status.overlay_active,
            "runtimeMonitorActive": state.protection_status.runtime_monitor_active,
        }
    });

    let _ = append_audit_event(
        now_ms(),
        "SECURITY_COMMAND",
        severity,
        &state.session_state,
        state.active_session_id.as_deref(),
        &state.loaded_policy.digest_sha256,
        data,
    );
}

fn run_preflight_process_remediation(
    process_collector: &mut ProcessCollector,
    loaded_policy: &LoadedExamPolicy,
    receipt: Option<&SignedExamReceipt>,
) -> PreflightKillReport {
    let policy = &loaded_policy.policy;
    let signed_policy = loaded_policy.signed_envelope.clone();
    let receipt = receipt.cloned();
    preflight_remediate_policy_processes_using(
        policy,
        || process_collector.collect_with_policy(policy),
        move |pid| terminate_with_service_fallback(pid, signed_policy.as_ref(), receipt.as_ref()),
    )
}

fn electron_owned_capture_guard_status(active: bool) -> CaptureGuardMutationResult {
    CaptureGuardMutationResult {
        applied: active,
        active: false,
        status: if active {
            "electron-owned-window-skipped".to_string()
        } else {
            "electron-content-protection-inactive".to_string()
        },
        detail: if active {
            "Exam-window capture protection is owned by Electron BrowserWindow.setContentProtection; Rust WDA is reserved for Rust-owned native overlays.".to_string()
        } else {
            "Electron content protection was not reported active for the exam window.".to_string()
        },
    }
}

fn terminate_with_service_fallback(
    pid: u32,
    policy: Option<&policy_signature::SignedExamPolicy>,
    receipt: Option<&SignedExamReceipt>,
) -> Result<(), String> {
    match terminate_process_user_mode(pid) {
        Ok(()) => Ok(()),
        Err(user_error) => {
            let (Some(policy), Some(receipt)) = (policy, receipt) else {
                return Err(user_error);
            };
            let request = build_elevated_termination_request(policy, receipt, pid, now_ms())
                .map_err(|error| format!("{user_error}; service request rejected: {error}"))?;
            request_elevated_termination(&request)
                .map(|_| ())
                .map_err(|error| format!("{user_error}; elevated remediation failed: {error}"))
        }
    }
}

fn has_active_protection(state: &CoreRuntimeState) -> bool {
    state.active_session_id.is_some()
        || state.desktop_state_snapshot.is_some()
        || state.protection_status.taskbar_hidden
        || state.protection_status.keyboard_hook_active
        || state.protection_status.focus_lock_active
        || state.protection_status.overlay_active
        || state.protection_status.exam_protection_active
        || state.protection_status.kiosk_active
}

fn can_sync_display_topology(state: &CoreRuntimeState) -> bool {
    state.active_session_id.is_some()
        && state.session_state == SESSION_STATE_EXAM_RUNNING
        && state.protection_status.kiosk_active
}

fn transition_session_state(
    state: &mut CoreRuntimeState,
    next_state: &str,
    force: bool,
) -> Result<(), String> {
    if force || is_valid_session_transition(&state.session_state, next_state) {
        state.session_state = next_state.to_string();
        Ok(())
    } else {
        Err(format!(
            "Invalid exam session transition: {} -> {}.",
            state.session_state, next_state
        ))
    }
}

fn transition_runtime_state(
    state: &mut CoreRuntimeState,
    next_state: RuntimeLifecycleState,
    timestamp: u64,
    reason: &str,
) -> Result<(), String> {
    let transition = state.runtime_state_engine.transition(next_state)?;
    if let Some(transition) = transition {
        state.runtime_event_bus.emit(
            EVENT_RUNTIME_STATE_CHANGED,
            if matches!(
                transition.next,
                RuntimeLifecycleState::Degraded | RuntimeLifecycleState::Failed
            ) {
                "warn"
            } else {
                "info"
            },
            timestamp,
            reason,
            event_metadata(&[
                ("previousState", format!("{:?}", transition.previous)),
                ("nextState", format!("{:?}", transition.next)),
            ]),
        );
    }
    Ok(())
}

fn restore_active_protection(state: &mut CoreRuntimeState, reason: Option<String>) -> Value {
    let reason_text = reason
        .clone()
        .unwrap_or_else(|| "Desktop protection restore requested.".to_string());
    state.runtime_event_bus.emit(
        EVENT_RECOVERY_STARTED,
        "warn",
        now_ms(),
        reason_text.clone(),
        event_metadata(&[("sessionState", state.session_state.clone())]),
    );
    let _ = transition_runtime_state(
        state,
        RuntimeLifecycleState::Recovering,
        now_ms(),
        "Runtime recovery started.",
    );
    state.process_event_producer.stop();
    state
        .runtime_state_engine
        .update_producer_snapshot(state.process_event_producer.snapshot());

    let overlay_restore = deactivate_native_overlays();
    let capture_guard_restore = deactivate_capture_guard();
    let clipboard_guard_restore = deactivate_clipboard_guard();
    let mouse_guard_restore = deactivate_mouse_guard();
    let accessibility_guard_restore = deactivate_accessibility_guard();
    let focus_guard_restore = deactivate_focus_guard();
    let input_guard_restore = deactivate_input_guard();
    let taskbar_restore = show_taskbar(
        state
            .desktop_state_snapshot
            .as_ref()
            .map(|snapshot| snapshot.taskbar_visible)
            .unwrap_or(true),
    );

    let kiosk_restore = build_exit_kiosk_result(
        now_ms(),
        &state.protection_status,
        &overlay_restore,
        &taskbar_restore,
        &focus_guard_restore,
        &input_guard_restore,
        &capture_guard_restore,
        &mouse_guard_restore,
        &accessibility_guard_restore,
        &clipboard_guard_restore,
    );
    let session_restore = build_exit_exam_session_result(now_ms(), &state.protection_status, reason);

    let _ = transition_session_state(
        state,
        &session_restore.session_state,
        session_restore.session_state == SESSION_STATE_IDLE,
    );
    state.protection_status = session_restore.protection_status.clone();
    state.desktop_state_snapshot = None;
    state.active_session_id = None;
    state.exam_window_handle_hex = None;
    state.process_remediator = RuntimeProcessRemediator::new();
    state.runtime_scheduler.reset();
    state.cached_vm_signals.clear();
    state.active_service_authorization = None;
    let _ = transition_runtime_state(
        state,
        RuntimeLifecycleState::ShuttingDown,
        now_ms(),
        "Runtime guards stopped after desktop recovery.",
    );
    state.runtime_event_bus.emit(
        EVENT_RECOVERY_COMPLETED,
        "info",
        now_ms(),
        "Desktop protection restore completed.",
        event_metadata(&[("reason", reason_text)]),
    );

    json!({
        "kioskRestore": kiosk_restore,
        "sessionRestore": session_restore,
    })
}

fn handle_command(state: &mut CoreRuntimeState, request: &CoreRequest) -> CoreResponse {
    match request.cmd.as_str() {
        "ping" => success_response(
            &request.request_id,
            json!({
                "pong": true,
                "source": "rust-core",
                "bridgeAliveAt": now_ms(),
                "nativeCoreConnected": true,
                "sessionState": state.session_state,
            }),
        ),
        "get_core_version" => success_response(
            &request.request_id,
            json!({
                "coreVersion": CORE_VERSION,
                "nativeCoreConnected": true,
            }),
        ),
        "get_status" => success_response(&request.request_id, build_status_snapshot(state)),
        "get_policy_status" => value_from_serializable(
            &request.request_id,
            &state.loaded_policy,
        ),
        "get_exam_device_identity" => match get_exam_device_identity() {
            Ok(identity) => value_from_serializable(&request.request_id, &identity),
            Err(error) => error_response(
                &request.request_id,
                "DEVICE_KEY_FAILURE",
                error,
            ),
        },
        "sign_exam_challenge" => {
            let payload: ExamChallengePayload =
                match serde_json::from_value(request.payload.clone()) {
                    Ok(value) => value,
                    Err(error) => {
                        return error_response(
                            &request.request_id,
                            "INVALID_REQUEST",
                            format!("Invalid sign_exam_challenge payload: {error}"),
                        )
                    }
                };
            match sign_exam_challenge(payload, now_ms()) {
                Ok(signed) => value_from_serializable(&request.request_id, &signed),
                Err(error) => error_response(
                    &request.request_id,
                    "EXAM_KEY_FAILURE",
                    error,
                ),
            }
        }
        "load_policy" => {
            if state.active_session_id.is_some() {
                return error_response(
                    &request.request_id,
                    "INVALID_REQUEST",
                    "Exam policy cannot be replaced while a session is active.",
                );
            }
            let payload: LoadExamPolicyPayload =
                match serde_json::from_value(request.payload.clone()) {
                    Ok(value) => value,
                    Err(error) => {
                        return error_response(
                            &request.request_id,
                            "INVALID_REQUEST",
                            format!("Invalid load_policy payload: {error}"),
                        )
                    }
                };
            match load_signed_exam_policy(
                payload.envelope,
                &state.trusted_policy_keys,
                &payload.exam_id,
                now_ms(),
            ) {
                Ok(policy) => {
                    state.loaded_policy = policy;
                    state.precheck_report = None;
                    state.preflight_result = None;
                    state.runtime_event_bus.emit(
                        EVENT_POLICY_RELOADED,
                        "info",
                        now_ms(),
                        format!(
                            "Signed exam policy {} loaded.",
                            state.loaded_policy.policy.policy_version
                        ),
                        event_metadata(&[
                            (
                                "policyVersion",
                                state.loaded_policy.policy.policy_version.clone(),
                            ),
                            ("source", state.loaded_policy.source.clone()),
                        ]),
                    );
                    value_from_serializable(&request.request_id, &state.loaded_policy)
                }
                Err(error) => error_response(
                    &request.request_id,
                    "POLICY_VERIFICATION_FAILED",
                    error,
                ),
            }
        }
        "get_system_info" => value_from_serializable(&request.request_id, &collect_system_info()),
        "get_display_info" => value_from_serializable(&request.request_id, &collect_display_info()),
        "get_process_list" => {
            let processes = state
                .process_collector
                .collect_with_policy(&state.loaded_policy.policy);
            value_from_serializable(&request.request_id, &processes)
        }
        "get_process_categories" => {
            let process_list = state
                .process_collector
                .collect_with_policy(&state.loaded_policy.policy);
            let categories = collect_process_categories_from_processes(&process_list);
            value_from_serializable(&request.request_id, &categories)
        }
        "get_vm_signals" => {
            let system_info = collect_system_info();
            let process_list = state
                .process_collector
                .collect_with_policy(&state.loaded_policy.policy);
            let categories = collect_process_categories_from_processes(&process_list);
            let signals = collect_vm_signals(&system_info, &categories);
            value_from_serializable(&request.request_id, &signals)
        }
        "get_remote_signals" => {
            let process_list = state
                .process_collector
                .collect_with_policy(&state.loaded_policy.policy);
            let categories = collect_process_categories_from_processes(&process_list);
            let signals = collect_remote_signals(&categories);
            value_from_serializable(&request.request_id, &signals)
        }
        "get_screen_capture_signals" => {
            let process_list = state
                .process_collector
                .collect_with_policy(&state.loaded_policy.policy);
            let categories = collect_process_categories_from_processes(&process_list);
            let signals = collect_screen_capture_signals(&categories);
            value_from_serializable(&request.request_id, &signals)
        }
        "collect_precheck_snapshot" => {
            let snapshot =
                collect_precheck_snapshot_with_policy(now_ms(), &state.loaded_policy.policy);
            state.precheck_report = Some(build_precheck_report_with_policy(
                snapshot.clone(),
                &state.loaded_policy.policy,
            ));
            state.preflight_result = None;
            value_from_serializable(&request.request_id, &snapshot)
        }
        "collect_precheck_report" => {
            // Phase 4 evaluates the raw collection through dedicated rules so the UI
            // can consume stable status, findings, confidence and recommendations.
            let report = build_precheck_report_with_policy(
                collect_precheck_snapshot_with_policy(now_ms(), &state.loaded_policy.policy),
                &state.loaded_policy.policy,
            );
            state.precheck_report = Some(report.clone());
            state.preflight_result = None;
            value_from_serializable(&request.request_id, &report)
        }
        "preflight_kill" => {
            let payload: PreflightKillPayload =
                match serde_json::from_value(request.payload.clone()) {
                    Ok(value) => value,
                    Err(error) => {
                        return error_response(
                            &request.request_id,
                            "INVALID_REQUEST",
                            format!("Invalid preflight_kill payload: {error}"),
                        )
                    }
                };
            let report = run_preflight_process_remediation(
                &mut state.process_collector,
                &state.loaded_policy,
                payload.service_authorization.as_ref(),
            );
            value_from_serializable(&request.request_id, &report)
        }
        "run_preflight" => {
            // Phase 5 turns collection + evaluation into a final room-entry decision.
            // The UI should trust this result instead of rebuilding gate logic client-side.
            let result = build_preflight_result_with_policy(
                collect_precheck_snapshot_with_policy(now_ms(), &state.loaded_policy.policy),
                &state.loaded_policy.policy,
            );
            if let Err(error) = transition_session_state(
                state,
                SESSION_STATE_PREFLIGHT_READY,
                false,
            ) {
                return error_response(
                    &request.request_id,
                    "INVALID_REQUEST",
                    error,
                );
            }
            state.precheck_report = Some(result.report.clone());
            state.preflight_result = Some(result.clone());
            value_from_serializable(&request.request_id, &result)
        }
        "start_exam_session" => {
            let payload: StartExamSessionPayload = match serde_json::from_value(request.payload.clone()) {
                Ok(value) => value,
                Err(error) => {
                    return error_response(
                        &request.request_id,
                        "INVALID_REQUEST",
                        format!("Invalid start_exam_session payload: {error}"),
                    )
                }
            };

            if state.active_session_id.is_some() || state.session_state == SESSION_STATE_EXAM_RUNNING {
                return error_response(
                    &request.request_id,
                    "INVALID_REQUEST",
                    "An exam session is already active. Exit or restore it before starting a new one.",
                );
            }

            let expected_exam_id = payload.exam_id.as_deref().unwrap_or("");
            if state.require_signed_policy && state.loaded_policy.source != "signed" {
                return error_response(
                    &request.request_id,
                    "POLICY_REQUIRED",
                    "A verified signed exam policy must be loaded before starting this session.",
                );
            }
            if expected_exam_id.is_empty() && state.require_signed_policy {
                return error_response(
                    &request.request_id,
                    "INVALID_REQUEST",
                    "examId is required when signed policy enforcement is enabled.",
                );
            }
            if state.require_signed_policy {
                let Some(exam_key) = payload.exam_key.as_ref() else {
                    return error_response(
                        &request.request_id,
                        "EXAM_KEY_REQUIRED",
                        "A server-signed exam receipt is required before starting this session.",
                    );
                };
                if let Err(error) = verify_exam_receipt(
                    exam_key,
                    &state.trusted_policy_keys,
                    expected_exam_id,
                    &payload.session_id,
                    &state.loaded_policy.policy.policy_version,
                    now_ms(),
                ) {
                    return error_response(
                        &request.request_id,
                        "EXAM_KEY_FAILURE",
                        error,
                    );
                }
                let Some(service_authorization) = payload.service_authorization.as_ref() else {
                    return error_response(
                        &request.request_id,
                        "EXAM_KEY_REQUIRED",
                        "A server-signed elevated-remediation authorization is required.",
                    );
                };
                if let Err(error) = verify_service_authorization(
                    service_authorization,
                    &state.trusted_policy_keys,
                    expected_exam_id,
                    &payload.session_id,
                    &state.loaded_policy.policy.policy_version,
                    now_ms(),
                ) {
                    return error_response(
                        &request.request_id,
                        "EXAM_KEY_FAILURE",
                        error,
                    );
                }
            }
            if let Err(error) = state
                .loaded_policy
                .policy
                .validate_for(expected_exam_id, now_ms())
            {
                return error_response(
                    &request.request_id,
                    "POLICY_VERIFICATION_FAILED",
                    error,
                );
            }

            if !payload.dry_run {
                let remediation_report = run_preflight_process_remediation(
                    &mut state.process_collector,
                    &state.loaded_policy,
                    payload.service_authorization.as_ref(),
                );
                if !remediation_report.all_clear {
                    return error_response(
                        &request.request_id,
                        "PROTECTION_FAILURE",
                        format!(
                            "Protected exam session could not close prohibited process(es): {}.",
                            remediation_report.remaining_names.join(", ")
                        ),
                    );
                }
            }

            let preflight_result = build_preflight_result_with_policy(
                collect_precheck_snapshot_with_policy(now_ms(), &state.loaded_policy.policy),
                &state.loaded_policy.policy,
            );
            state.precheck_report = Some(preflight_result.report.clone());
            state.preflight_result = Some(preflight_result.clone());

            if !payload.dry_run && !preflight_result.decision.can_enter_exam {
                if let Err(error) = transition_session_state(
                    state,
                    SESSION_STATE_PREFLIGHT_READY,
                    false,
                ) {
                    return error_response(
                        &request.request_id,
                        "INVALID_REQUEST",
                        error,
                    );
                }
                return error_response(
                    &request.request_id,
                    "PROTECTION_FAILURE",
                    format!(
                        "Protected exam session blocked by strict preflight policy: {}",
                        preflight_result.decision.primary_reason
                    ),
                );
            }

            let desktop_state = capture_desktop_state();
            let result = build_start_exam_session_result(now_ms(), payload.clone(), desktop_state.clone());
            if let Err(error) =
                transition_session_state(state, &result.session_state, false)
            {
                return error_response(
                    &request.request_id,
                    "INVALID_REQUEST",
                    error,
                );
            }
            state.protection_status = result.protection_status.clone();
            state.active_session_id = Some(result.session_context.session_id.clone());
            state.desktop_state_snapshot = Some(desktop_state);
            state.exam_window_handle_hex = payload.window_handle_hex.clone();
            state.active_service_authorization = payload.service_authorization.clone();
            value_from_serializable(&request.request_id, &result)
        }
        "enter_kiosk" => {
            let payload: EnterKioskPayload = match serde_json::from_value(request.payload.clone()) {
                Ok(value) => value,
                Err(error) => {
                    return error_response(
                        &request.request_id,
                        "INVALID_REQUEST",
                        format!("Invalid enter_kiosk payload: {error}"),
                    )
                }
            };

            if state.active_session_id.is_none() || state.desktop_state_snapshot.is_none() {
                return error_response(
                    &request.request_id,
                    "INVALID_REQUEST",
                    "No desktop session snapshot is available for kiosk activation.",
                );
            }

            if let (Some(expected_session_id), Some(active_session_id)) =
                (payload.session_id.as_ref(), state.active_session_id.as_ref())
            {
                if expected_session_id != active_session_id {
                    return error_response(
                        &request.request_id,
                        "INVALID_REQUEST",
                        format!(
                            "Session mismatch. Active session is {}, but {} was requested for kiosk entry.",
                            active_session_id, expected_session_id
                        ),
                    );
                }
            }

            if state.session_state != SESSION_STATE_STARTING_EXAM_SESSION {
                return error_response(
                    &request.request_id,
                    "INVALID_REQUEST",
                    format!(
                        "Kiosk entry requires {}, current state is {}.",
                        SESSION_STATE_STARTING_EXAM_SESSION, state.session_state
                    ),
                );
            }

            let display_info = collect_display_info();
            let overlay_result = activate_native_overlays(&display_info);
            let taskbar_result = hide_taskbar();
            let mouse_guard_result = activate_mouse_guard(&display_info);
            let clipboard_guard_result = activate_clipboard_guard();
            let accessibility_guard_result = activate_accessibility_guard();
            let focus_guard_result = activate_focus_guard(
                payload
                    .window_handle_hex
                    .as_deref()
                    .or(state.exam_window_handle_hex.as_deref()),
            );
            let input_guard_result = activate_input_guard();
            let capture_guard_result = if payload.electron_content_protection_active {
                electron_owned_capture_guard_status(true)
            } else {
                activate_capture_guard(
                    payload
                        .window_handle_hex
                        .as_deref()
                        .or(state.exam_window_handle_hex.as_deref()),
                )
            };
            let result = build_enter_kiosk_result(
                now_ms(),
                &display_info,
                &overlay_result,
                &taskbar_result,
                &input_guard_result,
                &focus_guard_result,
                &capture_guard_result,
                payload.electron_content_protection_active,
                &mouse_guard_result,
                &clipboard_guard_result,
                &accessibility_guard_result,
            );
            if let Err(error) =
                transition_session_state(state, &result.session_state, false)
            {
                let _ = restore_active_protection(
                    state,
                    Some(format!(
                        "Kiosk activation produced an invalid state transition: {error}"
                    )),
                );
                return error_response(
                    &request.request_id,
                    "PROTECTION_FAILURE",
                    error,
                );
            }
            state.protection_status = result.protection_status.clone();
            state.runtime_state_engine.reset_session_data();
            if let Err(error) = transition_runtime_state(
                state,
                RuntimeLifecycleState::Starting,
                now_ms(),
                "Runtime state engine started with kiosk activation.",
            ) {
                let _ = restore_active_protection(
                    state,
                    Some(format!("Runtime state engine failed to start: {error}")),
                );
                return error_response(
                    &request.request_id,
                    "PROTECTION_FAILURE",
                    error,
                );
            }
            if let Err(error) = state.process_event_producer.start() {
                let _ = restore_active_protection(
                    state,
                    Some(format!("Runtime process producer failed to start: {error}")),
                );
                return error_response(
                    &request.request_id,
                    "PROTECTION_FAILURE",
                    error,
                );
            }
            let producer_status = state.process_event_producer.status();
            state
                .runtime_state_engine
                .update_producer_snapshot(state.process_event_producer.snapshot());
            let producer_runtime_state = if producer_status.fallback_active {
                RuntimeLifecycleState::Fallback
            } else {
                RuntimeLifecycleState::Healthy
            };
            if let Err(error) = transition_runtime_state(
                state,
                producer_runtime_state,
                now_ms(),
                "Runtime process producer selected.",
            ) {
                let _ = restore_active_protection(
                    state,
                    Some(format!("Runtime producer state transition failed: {error}")),
                );
                return error_response(
                    &request.request_id,
                    "PROTECTION_FAILURE",
                    error,
                );
            }
            value_from_serializable(&request.request_id, &result)
        }
        "exit_exam_session" => {
            let payload: ExitExamSessionPayload = match serde_json::from_value(request.payload.clone()) {
                Ok(value) => value,
                Err(error) => {
                    return error_response(
                        &request.request_id,
                        "INVALID_REQUEST",
                        format!("Invalid exit_exam_session payload: {error}"),
                    )
                }
            };

            if let (Some(expected_session_id), Some(active_session_id)) =
                (payload.session_id.as_ref(), state.active_session_id.as_ref())
            {
                if expected_session_id != active_session_id {
                    return error_response(
                        &request.request_id,
                        "INVALID_REQUEST",
                        format!(
                            "Session mismatch. Active session is {}, but {} was requested for exit.",
                            active_session_id, expected_session_id
                        ),
                    );
                }
            }

            let restore_payload = restore_active_protection(state, payload.reason);
            success_response(&request.request_id, restore_payload)
        }
        "exit_kiosk" => {
            if state.active_session_id.is_none() {
                return error_response(
                    &request.request_id,
                    "INVALID_REQUEST",
                    "No active session is running for kiosk exit.",
                );
            }

            let restore_payload = restore_active_protection(
                state,
                Some("Kiosk exit requested by desktop shell.".to_string()),
            );
            success_response(&request.request_id, restore_payload)
        }
        "force_restore_desktop" => {
            let restore_payload = restore_active_protection(
                state,
                Some("Emergency restore requested by the desktop shell.".to_string()),
            );
            success_response(&request.request_id, restore_payload)
        }
        "sync_display_topology" => {
            if !can_sync_display_topology(state) {
                return error_response(
                    &request.request_id,
                    "INVALID_REQUEST",
                    "Display topology sync requires an active kiosk-protected exam session.",
                );
            }
            let display_info = collect_display_info();
            let overlay_result = sync_native_overlays(&display_info);

            if overlay_result.applied {
                state.protection_status.overlay_active = overlay_result.active;
                state.protection_status.black_overlay_count = overlay_result.overlay_count;
                state.protection_status.active_monitor_count = display_info.monitor_count;
                state.protection_status.last_runtime_event_at = Some(now_ms());
            }

            success_response(
                &request.request_id,
                json!({
                    "displayInfo": display_info,
                    "overlayResult": overlay_result,
                    "protectionStatus": state.protection_status,
                }),
            )
        }
        "run_runtime_monitor_tick" => {
            let tick_started = Instant::now();
            if state.active_session_id.is_none()
                || !state.protection_status.kiosk_active
                || state.session_state != SESSION_STATE_EXAM_RUNNING
            {
                return error_response(
                    &request.request_id,
                    "INVALID_REQUEST",
                    "Runtime monitor ticks require an active kiosk-protected exam session.",
                );
            }

            let payload: RuntimeMonitorTickPayload =
                match serde_json::from_value(request.payload.clone()) {
                    Ok(value) => value,
                    Err(error) => {
                        return error_response(
                            &request.request_id,
                            "INVALID_REQUEST",
                            format!(
                                "Invalid run_runtime_monitor_tick payload: {error}"
                            ),
                        )
                    }
                };
            if payload.window_handle_hex.is_some() {
                state.exam_window_handle_hex = payload.window_handle_hex;
            }

            let collected_at = now_ms();
            let tick_plan = state.runtime_scheduler.next_tick(collected_at);
            debug_assert!(tick_plan.process_scan_due);
            debug_assert!(tick_plan.guard_healing_due);

            state.process_event_producer.recover_if_due(collected_at);
            let mut process_creation_events = state.process_event_producer.drain_events();
            let native_producer_event_count = process_creation_events.len();
            process_creation_events.extend(payload.process_creation_events.clone());
            let native_producer_source = state.process_event_producer.status().selected_source;
            let process_watcher_source = if native_producer_event_count > 0
                || payload.process_creation_events.is_empty()
            {
                native_producer_source.clone()
            } else {
                payload.process_watcher_source.clone()
            };
            let producer_status = state.process_event_producer.status();
            state
                .runtime_state_engine
                .update_producer_snapshot(state.process_event_producer.snapshot());
            let producer_transition = state.runtime_event_bus.record_component_status(
                "processProducer",
                &format!(
                    "{:?}:{}",
                    producer_status.selected_source, producer_status.health
                ),
                collected_at,
                format!(
                    "Process event producer source={:?}, health={}, fallbackActive={}.",
                    producer_status.selected_source,
                    producer_status.health,
                    producer_status.fallback_active
                ),
            );
            if producer_transition.is_some()
                && (producer_status.health == "degraded"
                    || producer_status.events_lost_count > 0
                    || producer_status.buffers_lost_count > 0
                    || producer_status.realtime_buffers_lost_count > 0
                    || producer_status.dropped_event_count > 0)
            {
                state.runtime_event_bus.emit(
                    EVENT_PRODUCER_DEGRADED,
                    "warn",
                    collected_at,
                    "ETW process producer reported loss, parser failure, or queue pressure; polling reconciliation remains active.",
                    event_metadata(&[
                        ("source", format!("{:?}", producer_status.selected_source)),
                        ("health", producer_status.health.clone()),
                        ("eventsLost", producer_status.events_lost_count.to_string()),
                        ("buffersLost", producer_status.buffers_lost_count.to_string()),
                        (
                            "realTimeBuffersLost",
                            producer_status.realtime_buffers_lost_count.to_string(),
                        ),
                        (
                            "droppedEventCount",
                            producer_status.dropped_event_count.to_string(),
                        ),
                    ]),
                );
            }
            state.runtime_event_bus.emit(
                EVENT_PRODUCER_HEARTBEAT,
                if producer_status.fallback_active { "warn" } else { "info" },
                collected_at,
                format!(
                    "Process producer heartbeat source={:?}, state={}, health={}, queueDepth={}.",
                    producer_status.selected_source,
                    producer_status.producer_state,
                    producer_status.health,
                    producer_status.queue_depth
                ),
                event_metadata(&[
                    ("source", format!("{:?}", producer_status.selected_source)),
                    ("state", producer_status.producer_state.clone()),
                    ("health", producer_status.health.clone()),
                    ("fallbackActive", producer_status.fallback_active.to_string()),
                    ("queueDepth", producer_status.queue_depth.to_string()),
                    ("retryCount", producer_status.retry_count.to_string()),
                    (
                        "recoveryAttemptCount",
                        producer_status.recovery_attempt_count.to_string(),
                    ),
                    (
                        "droppedEventCount",
                        producer_status.dropped_event_count.to_string(),
                    ),
                ]),
            );
            for (event_index, event) in process_creation_events.iter().enumerate() {
                let event_source = if event_index < native_producer_event_count {
                    native_producer_source.clone()
                } else {
                    payload.process_watcher_source.clone()
                };
                state.runtime_state_engine.submit_process_event(
                    event,
                    event_source.clone(),
                );
                let kind = if event.still_running {
                    EVENT_PROCESS_CREATED
                } else {
                    EVENT_PROCESS_EXITED
                };
                state.runtime_event_bus.emit(
                    kind,
                    "info",
                    event.observed_at_ms,
                    format!("{} pid {} observed by process watcher.", event.name, event.pid),
                    event_metadata(&[
                        ("pid", event.pid.to_string()),
                        ("name", event.name.clone()),
                        ("source", format!("{:?}", event_source)),
                    ]),
                );
            }

            let display_info = collect_display_info();
            if state.protection_status.active_monitor_count != display_info.monitor_count {
                state.runtime_event_bus.emit(
                    EVENT_DESKTOP_CHANGED,
                    "warn",
                    collected_at,
                    format!(
                        "Display topology changed from {} to {} monitor(s).",
                        state.protection_status.active_monitor_count,
                        display_info.monitor_count
                    ),
                    event_metadata(&[
                        (
                            "previousMonitorCount",
                            state.protection_status.active_monitor_count.to_string(),
                        ),
                        ("monitorCount", display_info.monitor_count.to_string()),
                    ]),
                );
            }

            let classification_started = Instant::now();
            let mut process_list = state
                .process_collector
                .collect_with_policy(&state.loaded_policy.policy);
            state.runtime_state_engine.drain_queue();
            state.runtime_state_engine.reconcile_processes(
                &process_list,
                collected_at,
                ProcessWatcherSource::Polling,
            );
            let watcher_batch = ProcessWatcherBatch {
                source: process_watcher_source,
                events: process_creation_events,
                collected_at_ms: collected_at,
            };
            let (watcher_report, watcher_processes) = state
                .process_creation_watcher
                .evaluate_batch(watcher_batch, &state.loaded_policy.policy);
            for process in watcher_processes {
                if !process_list.iter().any(|entry| entry.pid == process.pid) {
                    process_list.push(process);
                }
            }
            let process_categories = collect_process_categories_from_processes(&process_list);
            let process_classification_time_ms = classification_started.elapsed().as_millis() as u64;
            if tick_plan.environment_scan_due {
                // Keep the last environment decision between slow scans so a VM
                // finding cannot disappear merely because this is a fast tick.
                let system_info = collect_system_info();
                state.cached_vm_signals =
                    collect_vm_signals(&system_info, &process_categories);
            }
            let vm_signals = state.cached_vm_signals.clone();
            let remote_signals = collect_remote_signals(&process_categories);
            let screen_capture_signals = collect_screen_capture_signals(&process_categories);
            for signal in &screen_capture_signals {
                state.runtime_event_bus.emit(
                    EVENT_CAPTURE_DETECTED,
                    "warn",
                    collected_at,
                    format!("{}: {}", signal.label, signal.detail),
                    event_metadata(&[
                        ("signalId", signal.id.clone()),
                        ("source", signal.source.clone()),
                    ]),
                );
            }

            let overlay_result = if state.protection_status.overlay_active || state.protection_status.kiosk_active {
                Some(sync_native_overlays(&display_info))
            } else {
                None
            };
            let mouse_guard_result = activate_mouse_guard(&display_info);
            let clipboard_guard_result = activate_clipboard_guard();
            let input_guard_result = activate_input_guard();
            let focus_guard_result =
                activate_focus_guard(state.exam_window_handle_hex.as_deref());
            let capture_guard_result = if payload.electron_content_protection_active {
                electron_owned_capture_guard_status(true)
            } else {
                re_apply_capture_guard(state.exam_window_handle_hex.as_deref())
            };
            let mut healed_protection_status = state.protection_status.clone();
            healed_protection_status.keyboard_hook_active = input_guard_result.active;
            healed_protection_status.input_hook_active = input_guard_result.active;
            healed_protection_status.mouse_hook_active = mouse_guard_result.active;
            healed_protection_status.focus_lock_active = focus_guard_result.active;
            healed_protection_status.focus_hook_active = focus_guard_result.active;
            healed_protection_status.clipboard_listener_active =
                clipboard_guard_result.applied;

            let mut degraded_guard_count = 0_usize;
            let mut guard_restored_count = 0_usize;
            if let Some(event) = state.runtime_event_bus.record_guard_health(
                "mouse",
                mouse_guard_result.applied,
                mouse_guard_result.active,
                collected_at,
                mouse_guard_result.detail.clone(),
            ) {
                if event.kind == "GuardDegraded" {
                    degraded_guard_count += 1;
                } else if event.kind == "GuardRestored" {
                    guard_restored_count += 1;
                }
            }
            if let Some(event) = state.runtime_event_bus.record_guard_health(
                "clipboard",
                clipboard_guard_result.applied,
                clipboard_guard_result.applied,
                collected_at,
                clipboard_guard_result.detail.clone(),
            ) {
                if event.kind == "GuardDegraded" {
                    degraded_guard_count += 1;
                } else if event.kind == "GuardRestored" {
                    guard_restored_count += 1;
                }
            }
            if let Some(event) = state.runtime_event_bus.record_guard_health(
                "capture",
                capture_guard_result.applied,
                capture_guard_result.active || payload.electron_content_protection_active,
                collected_at,
                capture_guard_result.detail.clone(),
            ) {
                if event.kind == "GuardDegraded" {
                    degraded_guard_count += 1;
                } else if event.kind == "GuardRestored" {
                    guard_restored_count += 1;
                }
            }
            if let Some(overlay) = overlay_result.as_ref() {
                if let Some(event) = state.runtime_event_bus.record_guard_health(
                    "overlay",
                    overlay.applied,
                    overlay.active || display_info.monitor_count <= 1,
                    collected_at,
                    overlay.detail.clone(),
                ) {
                    if event.kind == "GuardDegraded" {
                        degraded_guard_count += 1;
                    } else if event.kind == "GuardRestored" {
                        guard_restored_count += 1;
                    }
                }
            }
            let static_guard_checks = [
                (
                    "keyboard",
                    input_guard_result.applied,
                    input_guard_result.active,
                    input_guard_result.detail.clone(),
                ),
                (
                    "focus",
                    focus_guard_result.applied,
                    focus_guard_result.active,
                    focus_guard_result.detail.clone(),
                ),
                (
                    "runtime",
                    state.protection_status.runtime_monitor_active,
                    state.protection_status.runtime_monitor_active,
                    "Runtime monitor heartbeat.".to_string(),
                ),
                (
                    "watcher",
                    state.process_event_producer.is_running(),
                    state.process_event_producer.is_running(),
                    "Background process watcher producer heartbeat.".to_string(),
                ),
                (
                    "policy",
                    !state.loaded_policy.policy.policy_version.is_empty()
                        && collected_at <= state.loaded_policy.policy.expires_at_ms,
                    !state.loaded_policy.policy.policy_version.is_empty()
                        && collected_at <= state.loaded_policy.policy.expires_at_ms,
                    "Runtime policy heartbeat.".to_string(),
                ),
            ];
            for (guard_name, applied, active, detail) in static_guard_checks {
                if let Some(event) = state.runtime_event_bus.record_guard_health(
                    guard_name,
                    applied,
                    active,
                    collected_at,
                    detail,
                ) {
                    if event.kind == "GuardDegraded" {
                        degraded_guard_count += 1;
                    } else if event.kind == "GuardRestored" {
                        guard_restored_count += 1;
                    }
                }
            }

            let signed_policy = state.loaded_policy.signed_envelope.clone();
            let receipt = state.active_service_authorization.clone();
            let remediation_processes = state.runtime_state_engine.active_processes();
            let remediation_started = Instant::now();
            let process_remediation = state.process_remediator.observe_policy_and_remediate_using(
                collected_at,
                &remediation_processes,
                &state.loaded_policy.policy,
                move |pid| {
                    terminate_with_service_fallback(
                        pid,
                        signed_policy.as_ref(),
                        receipt.as_ref(),
                    )
                },
            );
            let remediation_time_ms = remediation_started.elapsed().as_millis() as u64;
            state
                .runtime_state_engine
                .record_remediation(&process_remediation);
            let next_runtime_state = if process_remediation.failed_count > 0
                || process_remediation.pending_termination_count > 0
                || producer_status.health == "degraded"
                || producer_status.health == "unavailable"
                || producer_status.events_lost_count > 0
                || producer_status.buffers_lost_count > 0
                || producer_status.realtime_buffers_lost_count > 0
                || producer_status.dropped_event_count > 0
            {
                RuntimeLifecycleState::Degraded
            } else if producer_status.fallback_active {
                RuntimeLifecycleState::Fallback
            } else {
                RuntimeLifecycleState::Healthy
            };
            if let Err(error) = transition_runtime_state(
                state,
                next_runtime_state,
                collected_at,
                "Runtime health state was recomputed after policy remediation.",
            ) {
                return error_response(
                    &request.request_id,
                    "RUNTIME_STATE_FAILURE",
                    error,
                );
            }

            let runtime_telemetry = state.runtime_telemetry.record_tick(RuntimeTelemetrySample {
                runtime_tick_duration_ms: tick_started.elapsed().as_millis() as u64,
                watcher_latency_ms: watcher_report.max_detection_latency_ms,
                detection_latency_ms: watcher_report.max_detection_latency_ms,
                classification_latency_ms: process_classification_time_ms,
                process_classification_time_ms,
                kill_latency_ms: remediation_time_ms,
                remediation_time_ms,
                recovery_latency_ms: 0,
                queue_latency_ms: producer_status.producer_latency_ms,
                producer_latency_ms: producer_status.producer_latency_ms,
                event_queue_length: state.runtime_event_bus.len(),
                degraded_guard_count,
                guard_restored_count,
                watchdog_restart_count: 0,
            });
            let runtime_events = state.runtime_event_bus.recent_events(50);
            let runtime_state_engine = state.runtime_state_engine.snapshot();

            let result = build_runtime_monitor_tick_result(
                collected_at,
                &state.session_state,
                &healed_protection_status,
                &display_info,
                process_list.len(),
                &process_categories,
                &vm_signals,
                &remote_signals,
                &screen_capture_signals,
                overlay_result.as_ref(),
                &mouse_guard_result,
                &clipboard_guard_result,
                &capture_guard_result,
                payload.electron_content_protection_active,
                process_remediation,
                watcher_report,
                state.process_event_producer.status(),
                runtime_state_engine,
                runtime_telemetry,
                runtime_events,
                &state.loaded_policy.policy,
            );

            if let Err(error) =
                transition_session_state(state, &result.session_state, false)
            {
                return error_response(
                    &request.request_id,
                    "INVALID_REQUEST",
                    error,
                );
            }
            state.protection_status = result.protection_status.clone();

            value_from_serializable(&request.request_id, &result)
        }
        "get_protection_status" => success_response(
            &request.request_id,
            json!({
                "sessionState": state.session_state,
                "activeSessionId": state.active_session_id,
                "desktopStateCaptured": state.desktop_state_snapshot.is_some(),
                "protectionStatus": state.protection_status,
                "processWatcherProducer": state.process_event_producer.status(),
                "runtimeStateEngine": state.runtime_state_engine.snapshot(),
                "runtimeTelemetry": state.runtime_telemetry.last_snapshot(),
                "runtimeEvents": state.runtime_event_bus.recent_events(25),
            }),
        ),
        "shutdown" => {
            let had_active_protection = has_active_protection(state);

            if had_active_protection {
                let restore_payload = restore_active_protection(
                    state,
                    Some("Rust core shutdown requested while protection was still active.".to_string()),
                );
                let _ = restore_payload;
            }
            state.process_event_producer.stop();
            state.runtime_event_bus.emit(
                EVENT_RUNTIME_STOPPED,
                "info",
                now_ms(),
                "Rust core shutdown command was acknowledged.",
                event_metadata(&[("restoredDesktop", had_active_protection.to_string())]),
            );

            success_response(
                &request.request_id,
                json!({
                    "shuttingDown": true,
                    "coreVersion": CORE_VERSION,
                    "restoredDesktop": had_active_protection,
                    "sessionState": state.session_state,
                    "protectionStatus": state.protection_status,
                }),
            )
        }
        "compatibility_check"
        | "verify_config"
        | "check_environment"
        | "start_exam"
        | "pause_exam"
        | "resume_exam"
        | "submit_exam"
        | "scan_processes"
        | "sync_logs"
        | "create_recovery_snapshot"
        | "restore_session"
        | "check_update" => error_response(
            &request.request_id,
            "NOT_IMPLEMENTED",
            format!(
                "Command {} is reserved for the next safe exam core phase.",
                request.cmd
            ),
        ),
        _ => error_response(
            &request.request_id,
            "INVALID_COMMAND",
            format!("Unsupported command: {}", request.cmd),
        ),
    }
}

fn run_emergency_restore() -> io::Result<()> {
    let desktop = restore_default_input_desktop();
    let overlay = deactivate_native_overlays();
    let capture = deactivate_capture_guard();
    let clipboard = deactivate_clipboard_guard();
    let mouse = deactivate_mouse_guard();
    let accessibility = restore_accessibility_after_unclean_shutdown();
    let focus = deactivate_focus_guard();
    let input = deactivate_input_guard();
    let taskbar = show_taskbar(true);

    write_json_line(&json!({
        "ok": taskbar.applied && desktop.applied,
        "mode": "emergency-restore",
        "desktop": desktop.detail,
        "taskbar": taskbar.detail,
        "overlay": overlay.detail,
        "capture": capture.detail,
        "clipboard": clipboard.detail,
        "mouse": mouse.detail,
        "accessibility": accessibility.detail,
        "focus": focus.detail,
        "input": input.detail,
    }))
}

fn initial_runtime_state() -> CoreRuntimeState {
    CoreRuntimeState {
        precheck_report: None,
        preflight_result: None,
        session_state: SESSION_STATE_INIT.to_string(),
        protection_status: build_idle_protection_status(),
        desktop_state_snapshot: None,
        active_session_id: None,
        exam_window_handle_hex: None,
        process_remediator: RuntimeProcessRemediator::new(),
        process_creation_watcher: ProcessCreationWatcher::new(),
        process_event_producer: RuntimeProcessWatcherProducer::new(),
        runtime_event_bus: RuntimeEventBus::default(),
        runtime_state_engine: RuntimeStateEngine::new(),
        runtime_telemetry: RuntimeTelemetry::default(),
        runtime_scheduler: RuntimeMonitorScheduler::new(
            DEFAULT_ENVIRONMENT_SCAN_INTERVAL_MS,
        ),
        cached_vm_signals: Vec::new(),
        process_collector: ProcessCollector::new(),
        loaded_policy: LoadedExamPolicy::builtin(),
        trusted_policy_keys: TrustedPolicyKeys::from_environment().unwrap_or_default(),
        require_signed_policy: std::env::var("EDULEARN_REQUIRE_SIGNED_EXAM_POLICY")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        active_service_authorization: None,
    }
}

fn run_stdio_command_loop(mut state: CoreRuntimeState) -> io::Result<()> {
    let stdin = io::stdin();
    for line_result in stdin.lock().lines() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }

        let request: CoreRequest = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(error) => {
                let fallback = error_response(
                    "invalid-request",
                    "INVALID_REQUEST",
                    format!("Failed to parse request: {error}"),
                );
                write_json_line(&fallback)?;
                continue;
            }
        };

        let should_exit = request.cmd == "shutdown";
        let response = handle_command(&mut state, &request);
        audit_core_command(&state, &request, &response);
        write_json_line(&response)?;
        if should_exit {
            break;
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_named_pipe_command_loop(
    mut state: CoreRuntimeState,
    pipe_name: &str,
    expected_client_pid: u32,
    encoded_secret: &str,
) -> io::Result<()> {
    let pipe = ipc_pipe::accept_authenticated_pipe(pipe_name, expected_client_pid)
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error))?;
    let reader_pipe = pipe.try_clone()?;
    let mut reader = BufReader::new(reader_pipe);
    let mut writer = BufWriter::new(pipe);
    let mut authenticator = IpcAuthenticator::from_base64_secret(encoded_secret)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut line = String::new();

    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line.len() > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Authenticated IPC frame exceeded 1 MiB.",
            ));
        }
        let frame: AuthenticatedFrame = match serde_json::from_str(&line) {
            Ok(frame) => frame,
            Err(error) => {
                let response = error_response(
                    "invalid-request",
                    "IPC_AUTH_FAILED",
                    format!("Authenticated IPC frame is invalid: {error}"),
                );
                let signed = authenticator
                    .sign_response(
                        to_value(response).unwrap_or(Value::Null),
                        format!("error-{}", now_ms()),
                        now_ms(),
                    )
                    .map_err(io::Error::other)?;
                write_json_line_to(&mut writer, &signed)?;
                continue;
            }
        };
        let payload = match authenticator.verify_request(&frame, now_ms()) {
            Ok(payload) => payload,
            Err(error) => {
                let response =
                    error_response("invalid-request", "IPC_AUTH_FAILED", error);
                let signed = authenticator
                    .sign_response(
                        to_value(response).unwrap_or(Value::Null),
                        format!("response-{}", frame.nonce),
                        now_ms(),
                    )
                    .map_err(io::Error::other)?;
                write_json_line_to(&mut writer, &signed)?;
                continue;
            }
        };
        let request: CoreRequest = match serde_json::from_value(payload) {
            Ok(request) => request,
            Err(error) => {
                let response = error_response(
                    "invalid-request",
                    "INVALID_REQUEST",
                    format!("IPC request payload is invalid: {error}"),
                );
                let signed = authenticator
                    .sign_response(
                        to_value(response).unwrap_or(Value::Null),
                        format!("response-{}", frame.nonce),
                        now_ms(),
                    )
                    .map_err(io::Error::other)?;
                write_json_line_to(&mut writer, &signed)?;
                continue;
            }
        };
        let should_exit = request.cmd == "shutdown";
        let response = handle_command(&mut state, &request);
        audit_core_command(&state, &request, &response);
        let signed = authenticator
            .sign_response(
                to_value(response).unwrap_or(Value::Null),
                format!("response-{}", frame.nonce),
                now_ms(),
            )
            .map_err(io::Error::other)?;
        write_json_line_to(&mut writer, &signed)?;
        if should_exit {
            break;
        }
    }
    Ok(())
}

fn named_pipe_configuration() -> Result<Option<(String, u32, String)>, String> {
    let arguments = std::env::args().collect::<Vec<_>>();
    let Some(index) = arguments
        .iter()
        .position(|argument| argument == "--named-pipe")
    else {
        return Ok(None);
    };
    let pipe_name = arguments
        .get(index + 1)
        .cloned()
        .ok_or_else(|| "--named-pipe requires a pipe name.".to_string())?;
    let expected_pid = std::env::var("EDULEARN_CORE_IPC_PARENT_PID")
        .map_err(|_| "EDULEARN_CORE_IPC_PARENT_PID is required.".to_string())?
        .parse::<u32>()
        .map_err(|_| "EDULEARN_CORE_IPC_PARENT_PID is invalid.".to_string())?;
    let secret = std::env::var("EDULEARN_CORE_IPC_SECRET")
        .map_err(|_| "EDULEARN_CORE_IPC_SECRET is required.".to_string())?;
    std::env::remove_var("EDULEARN_CORE_IPC_SECRET");
    Ok(Some((pipe_name, expected_pid, secret)))
}

fn main() -> io::Result<()> {
    let dpi_awareness = activate_per_monitor_v2_awareness();
    if std::env::args().any(|argument| argument == "--emergency-restore") {
        return run_emergency_restore();
    }

    let accessibility_recovery =
        restore_accessibility_after_unclean_shutdown();
    let ready_event = CoreEvent {
        event_id: format!("evt-ready-{}", now_ms()),
        event: "RUST_CORE_READY",
        severity: "INFO",
        timestamp: now_ms(),
        data: json!({
            "coreVersion": CORE_VERSION,
            "sessionState": SESSION_STATE_CORE_READY,
            "dpiAwarenessApplied": dpi_awareness.applied,
            "dpiAwarenessDetail": dpi_awareness.detail,
            "accessibilityRecoveryApplied": accessibility_recovery.applied,
            "accessibilityRecoveryDetail": accessibility_recovery.detail,
        }),
    };
    write_json_line(&ready_event)?;

    let state = initial_runtime_state();
    match named_pipe_configuration()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
    {
        #[cfg(target_os = "windows")]
        Some((pipe_name, expected_pid, secret)) => {
            run_named_pipe_command_loop(state, &pipe_name, expected_pid, &secret)
        }
        #[cfg(not(target_os = "windows"))]
        Some(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Authenticated named-pipe IPC is only supported on Windows.",
        )),
        None => run_stdio_command_loop(state),
    }
}

#[cfg(test)]
mod core_state_tests {
    use super::{
        build_idle_protection_status, can_sync_display_topology, has_active_protection,
        CoreRuntimeState,
        ProcessCollector, RuntimeMonitorScheduler, RuntimeProcessRemediator,
        LoadedExamPolicy, ProcessCreationWatcher, RuntimeEventBus, RuntimeProcessWatcherProducer,
        RuntimeStateEngine, RuntimeTelemetry,
        TrustedPolicyKeys,
        DEFAULT_ENVIRONMENT_SCAN_INTERVAL_MS, SESSION_STATE_INIT,
    };

    fn idle_state() -> CoreRuntimeState {
        CoreRuntimeState {
            precheck_report: None,
            preflight_result: None,
            session_state: SESSION_STATE_INIT.to_string(),
            protection_status: build_idle_protection_status(),
            desktop_state_snapshot: None,
            active_session_id: None,
            exam_window_handle_hex: None,
            process_remediator: RuntimeProcessRemediator::new(),
            process_creation_watcher: ProcessCreationWatcher::new(),
            process_event_producer: RuntimeProcessWatcherProducer::new(),
            runtime_event_bus: RuntimeEventBus::default(),
            runtime_state_engine: RuntimeStateEngine::new(),
            runtime_telemetry: RuntimeTelemetry::default(),
            runtime_scheduler: RuntimeMonitorScheduler::new(
                DEFAULT_ENVIRONMENT_SCAN_INTERVAL_MS,
            ),
            cached_vm_signals: Vec::new(),
            process_collector: ProcessCollector::new(),
            loaded_policy: LoadedExamPolicy::builtin(),
            trusted_policy_keys: TrustedPolicyKeys::default(),
            require_signed_policy: false,
            active_service_authorization: None,
        }
    }

    #[test]
    fn drop_cleanup_is_armed_only_for_active_protection() {
        let mut state = idle_state();
        assert!(!has_active_protection(&state));

        state.active_session_id = Some("session-1".to_string());
        assert!(has_active_protection(&state));

        state.active_session_id = None;
    }

    #[test]
    fn display_topology_sync_is_rejected_outside_running_kiosk_session() {
        let mut state = idle_state();
        assert!(!can_sync_display_topology(&state));

        state.active_session_id = Some("session-1".to_string());
        state.session_state = super::SESSION_STATE_EXAM_RUNNING.to_string();
        state.protection_status.kiosk_active = true;
        assert!(can_sync_display_topology(&state));

        state.protection_status.kiosk_active = false;
        assert!(!can_sync_display_topology(&state));
        state.active_session_id = None;
    }
}
