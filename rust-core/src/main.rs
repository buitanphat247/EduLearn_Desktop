mod collectors;
mod desktop_state;
mod evaluation;
mod display_guard;
mod input_guard;
mod kiosk_guard;
mod models;
mod policy;
mod rules;
mod session_guard;
mod taskbar_guard;

use collectors::{
    collect_display_info, collect_precheck_snapshot, collect_process_categories_from_processes,
    collect_process_list, collect_remote_signals, collect_screen_capture_signals, collect_system_info,
    collect_vm_signals,
};
use desktop_state::capture_desktop_state;
use evaluation::{build_precheck_report, build_preflight_result};
use input_guard::{activate_input_guard, deactivate_input_guard};
use kiosk_guard::{build_enter_kiosk_result, build_exit_kiosk_result};
use models::{
    DesktopStateSnapshot, EnterKioskPayload, ExitExamSessionPayload, PrecheckReport, PreflightResult,
    ProtectionStatus, StartExamSessionPayload,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, to_value, Value};
use session_guard::{
    build_exit_exam_session_result, build_idle_protection_status, build_start_exam_session_result,
    SESSION_STATE_EXAM_RUNNING, SESSION_STATE_IDLE, SESSION_STATE_INIT, SESSION_STATE_PREFLIGHT_READY,
    SESSION_STATE_STARTING_EXAM_SESSION,
};
use taskbar_guard::{hide_taskbar, show_taskbar};
use std::io::{self, BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

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
        "get_system_info" => value_from_serializable(&request.request_id, &collect_system_info()),
        "get_display_info" => value_from_serializable(&request.request_id, &collect_display_info()),
        "get_process_list" => value_from_serializable(&request.request_id, &collect_process_list()),
        "get_process_categories" => {
            let process_list = collect_process_list();
            let categories = collect_process_categories_from_processes(&process_list);
            value_from_serializable(&request.request_id, &categories)
        }
        "get_vm_signals" => {
            let system_info = collect_system_info();
            let process_list = collect_process_list();
            let categories = collect_process_categories_from_processes(&process_list);
            let signals = collect_vm_signals(&system_info, &categories);
            value_from_serializable(&request.request_id, &signals)
        }
        "get_remote_signals" => {
            let process_list = collect_process_list();
            let categories = collect_process_categories_from_processes(&process_list);
            let signals = collect_remote_signals(&categories);
            value_from_serializable(&request.request_id, &signals)
        }
        "get_screen_capture_signals" => {
            let process_list = collect_process_list();
            let categories = collect_process_categories_from_processes(&process_list);
            let signals = collect_screen_capture_signals(&categories);
            value_from_serializable(&request.request_id, &signals)
        }
        "collect_precheck_snapshot" => {
            let snapshot = collect_precheck_snapshot(now_ms());
            state.precheck_report = Some(build_precheck_report(snapshot.clone()));
            state.preflight_result = None;
            value_from_serializable(&request.request_id, &snapshot)
        }
        "collect_precheck_report" => {
            // Phase 4 evaluates the raw collection through dedicated rules so the UI
            // can consume stable status, findings, confidence and recommendations.
            let report = build_precheck_report(collect_precheck_snapshot(now_ms()));
            state.precheck_report = Some(report.clone());
            state.preflight_result = None;
            value_from_serializable(&request.request_id, &report)
        }
        "run_preflight" => {
            // Phase 5 turns collection + evaluation into a final room-entry decision.
            // The UI should trust this result instead of rebuilding gate logic client-side.
            let result = build_preflight_result(collect_precheck_snapshot(now_ms()));
            state.precheck_report = Some(result.report.clone());
            state.preflight_result = Some(result.clone());
            state.session_state = SESSION_STATE_PREFLIGHT_READY.to_string();
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

            let desktop_state = capture_desktop_state();
            let result = build_start_exam_session_result(now_ms(), payload, desktop_state.clone());
            state.session_state = result.session_state.clone();
            state.protection_status = result.protection_status.clone();
            state.active_session_id = Some(result.session_context.session_id.clone());
            state.desktop_state_snapshot = Some(desktop_state);
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

            let desktop_state = state
                .desktop_state_snapshot
                .clone()
                .expect("desktop snapshot must exist after guard");
            let taskbar_result = hide_taskbar();
            let input_guard_result = activate_input_guard();
            let result = build_enter_kiosk_result(
                now_ms(),
                &desktop_state,
                &taskbar_result,
                &input_guard_result,
            );
            state.session_state = result.session_state.clone();
            state.protection_status = result.protection_status.clone();
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

            if state.protection_status.taskbar_hidden {
                let input_guard_restore = deactivate_input_guard();
                let taskbar_restore = show_taskbar(
                    state
                        .desktop_state_snapshot
                        .as_ref()
                        .map(|snapshot| snapshot.taskbar_visible)
                        .unwrap_or(true),
                );
                let _ = build_exit_kiosk_result(
                    now_ms(),
                    &state.protection_status,
                    &taskbar_restore,
                    &input_guard_restore,
                );
            } else if state.protection_status.keyboard_hook_active {
                let _ = deactivate_input_guard();
            }

            let result = build_exit_exam_session_result(now_ms(), &state.protection_status, payload.reason);
            state.session_state = result.session_state.clone();
            state.protection_status = result.protection_status.clone();
            state.desktop_state_snapshot = None;
            state.active_session_id = None;
            value_from_serializable(&request.request_id, &result)
        }
        "exit_kiosk" => {
            if state.active_session_id.is_none() {
                return error_response(
                    &request.request_id,
                    "INVALID_REQUEST",
                    "No active session is running for kiosk exit.",
                );
            }

            let input_guard_restore = deactivate_input_guard();
            let taskbar_restore = show_taskbar(
                state
                    .desktop_state_snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.taskbar_visible)
                    .unwrap_or(true),
            );
            let result = build_exit_kiosk_result(
                now_ms(),
                &state.protection_status,
                &taskbar_restore,
                &input_guard_restore,
            );
            state.session_state = SESSION_STATE_IDLE.to_string();
            state.protection_status = result.protection_status.clone();
            state.desktop_state_snapshot = None;
            state.active_session_id = None;
            value_from_serializable(&request.request_id, &result)
        }
        "force_restore_desktop" => {
            let input_guard_restore = deactivate_input_guard();
            let taskbar_restore = show_taskbar(
                state
                    .desktop_state_snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.taskbar_visible)
                    .unwrap_or(true),
            );
            let _ = build_exit_kiosk_result(
                now_ms(),
                &state.protection_status,
                &taskbar_restore,
                &input_guard_restore,
            );
            let result = build_exit_exam_session_result(
                now_ms(),
                &state.protection_status,
                Some("Emergency restore requested by the desktop shell.".to_string()),
            );
            state.session_state = SESSION_STATE_IDLE.to_string();
            state.protection_status = result.protection_status.clone();
            state.desktop_state_snapshot = None;
            state.active_session_id = None;
            value_from_serializable(&request.request_id, &result)
        }
        "get_protection_status" => success_response(
            &request.request_id,
            json!({
                "sessionState": state.session_state,
                "activeSessionId": state.active_session_id,
                "desktopStateCaptured": state.desktop_state_snapshot.is_some(),
                "protectionStatus": state.protection_status,
            }),
        ),
        "shutdown" => {
            let had_active_protection = state.active_session_id.is_some()
                || state.desktop_state_snapshot.is_some()
                || state.protection_status.taskbar_hidden
                || state.protection_status.keyboard_hook_active
                || state.protection_status.overlay_active
                || state.protection_status.exam_protection_active
                || state.protection_status.kiosk_active;

            if had_active_protection {
                let input_guard_restore = deactivate_input_guard();
                let taskbar_restore = show_taskbar(
                    state
                        .desktop_state_snapshot
                        .as_ref()
                        .map(|snapshot| snapshot.taskbar_visible)
                        .unwrap_or(true),
                );
                let _ = build_exit_kiosk_result(
                    now_ms(),
                    &state.protection_status,
                    &taskbar_restore,
                    &input_guard_restore,
                );
                let shutdown_restore_result = build_exit_exam_session_result(
                    now_ms(),
                    &state.protection_status,
                    Some("Rust core shutdown requested while protection was still active.".to_string()),
                );
                state.session_state = shutdown_restore_result.session_state.clone();
                state.protection_status = shutdown_restore_result.protection_status.clone();
                state.desktop_state_snapshot = None;
                state.active_session_id = None;
            }

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
        | "load_policy"
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

fn main() -> io::Result<()> {
    let ready_event = CoreEvent {
        event_id: format!("evt-ready-{}", now_ms()),
        event: "RUST_CORE_READY",
        severity: "INFO",
        timestamp: now_ms(),
        data: json!({
            "coreVersion": CORE_VERSION,
            "sessionState": SESSION_STATE_CORE_READY,
        }),
    };
    write_json_line(&ready_event)?;

    let stdin = io::stdin();
    let mut state = CoreRuntimeState {
        precheck_report: None,
        preflight_result: None,
        session_state: SESSION_STATE_INIT.to_string(),
        protection_status: build_idle_protection_status(),
        desktop_state_snapshot: None,
        active_session_id: None,
    };

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
        let _payload = &request.payload;
        write_json_line(&response)?;

        if should_exit {
            break;
        }
    }

    Ok(())
}
