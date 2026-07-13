mod emergency_widget;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use emergency_widget::{EmergencyWidgetManager, NativeWidgetEventKind, NativeWidgetState};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_HEARTBEAT_TIMEOUT_MS: u64 = 8_000;
const DEFAULT_STARTUP_GRACE_MS: u64 = 30_000;
const MONITOR_INTERVAL_MS: u64 = 500;
const MAX_HEARTBEAT_BYTES: u64 = 64 * 1024;
type HmacSha256 = Hmac<Sha256>;

const BOOTSTRAPPER_WIDGET_STATE_ENV: &str = "EDULEARN_BOOTSTRAPPER_WIDGET_STATE_PATH";
const BOOTSTRAPPER_WIDGET_EVENT_ENV: &str = "EDULEARN_BOOTSTRAPPER_WIDGET_EVENT_PATH";
const BOOTSTRAPPER_RESTORE_REQUEST_ENV: &str = "EDULEARN_BOOTSTRAPPER_RESTORE_REQUEST_PATH";
const BOOTSTRAPPER_EMERGENCY_REPORT_ENV: &str = "EDULEARN_BOOTSTRAPPER_EMERGENCY_REPORT";

#[derive(Debug, Clone)]
struct BootstrapperControlPaths {
    root_dir: PathBuf,
    widget_state_path: PathBuf,
    widget_event_path: PathBuf,
    restore_request_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct WidgetStateRecord {
    visible: bool,
    emergency_restore_widget_state: String,
    widget_id: Option<String>,
    correlation_id: Option<String>,
    require_hold_ms: u64,
    session_id: Option<String>,
    exam_id: Option<String>,
    runtime_id: Option<String>,
    kiosk_active: bool,
    desktop_isolation_active: bool,
    updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WidgetInteractionRecord {
    kind: String,
    session_id: Option<String>,
    exam_id: Option<String>,
    runtime_id: Option<String>,
    widget_id: Option<String>,
    correlation_id: Option<String>,
    requested_at: u64,
    desktop_isolation_active: bool,
    kiosk_active: bool,
    nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RestoreRequestRecord {
    trigger: String,
    session_id: Option<String>,
    exam_id: Option<String>,
    runtime_id: Option<String>,
    widget_id: Option<String>,
    correlation_id: Option<String>,
    requested_at: u64,
    desktop_isolation_active: bool,
    kiosk_active: bool,
    fallback_used: bool,
    timeout_used: bool,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct BootstrapperEmergencyReport {
    trigger: String,
    session_id: Option<String>,
    exam_id: Option<String>,
    runtime_id: Option<String>,
    widget_id: Option<String>,
    correlation_id: Option<String>,
    requested_at: u64,
    desktop_isolation_active: bool,
    fallback_used: bool,
    timeout_used: bool,
    desktop_switched_back: bool,
    desktop_destroyed: bool,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BootstrapConfig {
    electron_path: PathBuf,
    rust_core_path: PathBuf,
    heartbeat_timeout_ms: u64,
    startup_grace_ms: u64,
    electron_args: Vec<String>,
    desktop_isolation: DesktopIsolationConfig,
    /// Max number of times the Electron child may be relaunched if it dies
    /// unexpectedly during a session. Default 0 = disabled (the historical
    /// behaviour: any child death restores the desktop and exits). Enabling this
    /// requires validating the legitimate-exit flow on-device so a normal exam
    /// completion is not relaunched.
    electron_restart_max: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesktopIsolationConfig {
    enabled: bool,
    desktop_name: String,
    switch_desktop: bool,
}

impl Default for DesktopIsolationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            desktop_name: "EduLearnExamDesktop".to_string(),
            switch_desktop: true,
        }
    }
}

impl BootstrapConfig {
    fn parse<I>(arguments: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut arguments = arguments.into_iter();
        let _executable = arguments.next();
        let mut electron_path = None;
        let mut rust_core_path = None;
        let mut heartbeat_timeout_ms = DEFAULT_HEARTBEAT_TIMEOUT_MS;
        let mut startup_grace_ms = DEFAULT_STARTUP_GRACE_MS;
        let mut electron_args = Vec::new();
        let mut desktop_isolation = DesktopIsolationConfig::default();
        let mut electron_restart_max: u32 = 0;

        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--electron-restart-max" => {
                    let value = arguments.next().ok_or_else(|| {
                        "--electron-restart-max requires a value.".to_string()
                    })?;
                    electron_restart_max = value.parse::<u32>().map_err(|_| {
                        format!("--electron-restart-max must be a non-negative integer, got {value:?}.")
                    })?;
                }
                "--electron" => {
                    electron_path = Some(PathBuf::from(
                        arguments
                            .next()
                            .ok_or_else(|| "--electron requires a path.".to_string())?,
                    ));
                }
                "--rust-core" => {
                    rust_core_path = Some(PathBuf::from(
                        arguments
                            .next()
                            .ok_or_else(|| "--rust-core requires a path.".to_string())?,
                    ));
                }
                "--heartbeat-timeout-ms" => {
                    heartbeat_timeout_ms =
                        parse_duration_argument(&mut arguments, "--heartbeat-timeout-ms")?;
                }
                "--startup-grace-ms" => {
                    startup_grace_ms =
                        parse_duration_argument(&mut arguments, "--startup-grace-ms")?;
                }
                "--desktop-isolation" => {
                    desktop_isolation.enabled = true;
                }
                "--desktop-name" => {
                    desktop_isolation.desktop_name = arguments
                        .next()
                        .ok_or_else(|| "--desktop-name requires a value.".to_string())?;
                }
                "--no-desktop-switch" => {
                    desktop_isolation.switch_desktop = false;
                }
                "--" => {
                    electron_args.extend(arguments);
                    break;
                }
                unknown => return Err(format!("Unknown bootstrapper argument {unknown}.")),
            }
        }

        let config = Self {
            electron_path: electron_path
                .ok_or_else(|| "--electron is required.".to_string())?,
            rust_core_path: rust_core_path
                .ok_or_else(|| "--rust-core is required.".to_string())?,
            heartbeat_timeout_ms,
            startup_grace_ms,
            electron_args,
            desktop_isolation,
            electron_restart_max,
        };
        validate_desktop_name(&config.desktop_isolation.desktop_name)?;
        if config.electron_restart_max > 10 {
            return Err("electron restart max must be between 0 and 10.".to_string());
        }
        if config.heartbeat_timeout_ms < 2_000 || config.heartbeat_timeout_ms > 120_000 {
            return Err("heartbeat timeout must be between 2000 and 120000 ms.".to_string());
        }
        if config.startup_grace_ms < config.heartbeat_timeout_ms
            || config.startup_grace_ms > 300_000
        {
            return Err(
                "startup grace must be at least the heartbeat timeout and at most 300000 ms."
                    .to_string(),
            );
        }
        Ok(config)
    }
}

/// Minimum delay between Electron relaunches, so a child that crashes at startup
/// cannot spin the restart budget in a tight loop.
const RESTART_BACKOFF_MS: u64 = 1_500;

/// Whether the Electron child should be relaunched after it exited, given the
/// exit code and the remaining restart budget.
///
/// Only ABNORMAL exits (non-zero code) are restarted: a clean `exit 0` is how a
/// normally-completed exam quits, and relaunching it would trap the student back
/// on the locked desktop. A killed/crashed Electron exits non-zero, which is the
/// case we actually want to recover from.
fn should_restart_child(exit_code: i32, restarts_used: u32, restart_max: u32) -> bool {
    exit_code != 0 && restarts_used < restart_max
}

fn validate_desktop_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
    {
        return Err(
            "Desktop name must contain 1-64 ASCII letters, digits, '-' or '_'.".to_string(),
        );
    }
    Ok(())
}

fn parse_duration_argument<I>(arguments: &mut I, name: &str) -> Result<u64, String>
where
    I: Iterator<Item = String>,
{
    arguments
        .next()
        .ok_or_else(|| format!("{name} requires a value."))?
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an unsigned integer."))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HeartbeatRecord {
    version: u8,
    sequence: u64,
    timestamp_ms: u64,
    electron_pid: u32,
    process_path: String,
    process_sha256: String,
    process_started_at_ms: u64,
    native_core_connected: bool,
    session_state: String,
    session_id: Option<String>,
    challenge_response: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeartbeatHealth {
    Waiting,
    Healthy,
    Stale,
    Invalid,
}

fn evaluate_heartbeat(
    record: Option<&HeartbeatRecord>,
    expected_token: &str,
    expected_challenge: &str,
    expected_pid: u32,
    expected_process_path: &Path,
    expected_process_sha256: &str,
    last_healthy_sequence: Option<u64>,
    now_ms: u64,
    timeout_ms: u64,
    startup_elapsed_ms: u64,
    startup_grace_ms: u64,
) -> HeartbeatHealth {
    let Some(record) = record else {
        return if startup_elapsed_ms <= startup_grace_ms {
            HeartbeatHealth::Waiting
        } else {
            HeartbeatHealth::Stale
        };
    };
    let _telemetry = (
        record.sequence,
        record.native_core_connected,
        record.session_state.as_str(),
        record.session_id.as_deref().unwrap_or(""),
    );
    if record.version != 2
        || record.sequence == 0
        || last_healthy_sequence
            .map(|last| record.sequence <= last)
            .unwrap_or(false)
        || record.electron_pid != expected_pid
        || !paths_equal(Path::new(&record.process_path), expected_process_path)
        || !record
            .process_sha256
            .eq_ignore_ascii_case(expected_process_sha256)
        || record.process_started_at_ms == 0
        || record.process_started_at_ms > record.timestamp_ms.saturating_add(5_000)
        || record.timestamp_ms > now_ms.saturating_add(5_000)
        || !verify_heartbeat_response(record, expected_token, expected_challenge)
    {
        return HeartbeatHealth::Invalid;
    }
    if now_ms.saturating_sub(record.timestamp_ms) > timeout_ms {
        HeartbeatHealth::Stale
    } else {
        HeartbeatHealth::Healthy
    }
}

fn heartbeat_challenge_payload(record: &HeartbeatRecord, challenge: &str) -> String {
    format!(
        "v={}|seq={}|ts={}|pid={}|path={}|sha={}|started={}|native={}|state={}|session={}|challenge={}",
        record.version,
        record.sequence,
        record.timestamp_ms,
        record.electron_pid,
        record.process_path,
        record.process_sha256.to_ascii_lowercase(),
        record.process_started_at_ms,
        record.native_core_connected,
        record.session_state,
        record.session_id.as_deref().unwrap_or(""),
        challenge,
    )
}

fn hmac_sha256_hex(secret: &str, payload: &str) -> Option<String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(payload.as_bytes());
    Some(
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
}

fn verify_heartbeat_response(record: &HeartbeatRecord, token: &str, challenge: &str) -> bool {
    let Some(expected) = hmac_sha256_hex(token, &heartbeat_challenge_payload(record, challenge))
    else {
        return false;
    };
    constant_time_eq(
        expected.as_bytes(),
        record.challenge_response.as_bytes(),
    )
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("Unable to hash {}: {error}", path.display()))?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    let left = fs::canonicalize(left).unwrap_or_else(|_| left.to_path_buf());
    let right = fs::canonicalize(right).unwrap_or_else(|_| right.to_path_buf());
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn read_heartbeat(path: &Path) -> Option<HeartbeatRecord> {
    let metadata = fs::metadata(path).ok()?;
    if metadata.len() > MAX_HEARTBEAT_BYTES {
        return None;
    }
    let contents = fs::read_to_string(path).ok()?;
    serde_json::from_str(&contents).ok()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn bootstrapper_control_paths() -> BootstrapperControlPaths {
    let root_dir = std::env::temp_dir().join(format!(
        "edulearn-bootstrapper-control-{}-{}",
        std::process::id(),
        now_ms()
    ));
    BootstrapperControlPaths {
        widget_state_path: root_dir.join("widget-state.json"),
        widget_event_path: root_dir.join("widget-event.json"),
        restore_request_path: root_dir.join("restore-request.json"),
        root_dir,
    }
}

fn ensure_control_root(paths: &BootstrapperControlPaths) -> Result<(), String> {
    fs::create_dir_all(&paths.root_dir)
        .map_err(|error| format!("Failed to create bootstrapper control directory: {error}"))
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("Failed to serialize control payload: {error}"))?;
    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, bytes)
        .map_err(|error| format!("Failed to write control file {}: {error}", path.display()))?;
    fs::rename(&temp_path, path)
        .map_err(|error| format!("Failed to finalize control file {}: {error}", path.display()))
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, String> {
    if !path.is_file() {
        return Ok(None);
    }
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read control file {}: {error}", path.display()))?;
    let value = serde_json::from_str::<T>(&contents)
        .map_err(|error| format!("Failed to parse control file {}: {error}", path.display()))?;
    Ok(Some(value))
}

fn take_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, String> {
    let value = read_json_file(path)?;
    if value.is_some() {
        let _ = fs::remove_file(path);
    }
    Ok(value)
}

fn map_widget_state(record: WidgetStateRecord) -> NativeWidgetState {
    NativeWidgetState {
        visible: record.visible,
        widget_id: record.widget_id,
        correlation_id: record.correlation_id,
        require_hold_ms: record.require_hold_ms,
        desktop_isolation_active: record.desktop_isolation_active,
        updated_at_ms: record.updated_at_ms,
    }
}

fn build_widget_interaction_record(
    event_kind: &NativeWidgetEventKind,
    state: WidgetStateRecord,
) -> WidgetInteractionRecord {
    let requested_at = now_ms();
    WidgetInteractionRecord {
        kind: match event_kind {
            NativeWidgetEventKind::HoldStarted => "holdStarted",
            NativeWidgetEventKind::HoldCancelled => "holdCancelled",
            NativeWidgetEventKind::HoldCompleted => "restoreRequested",
        }
        .to_string(),
        session_id: state.session_id,
        exam_id: state.exam_id,
        runtime_id: state.runtime_id,
        widget_id: state.widget_id,
        correlation_id: state.correlation_id,
        requested_at,
        desktop_isolation_active: state.desktop_isolation_active,
        kiosk_active: state.kiosk_active,
        nonce: format!("bootstrapper-widget-{requested_at}"),
    }
}

fn generate_token() -> Result<String, String> {
    let mut token = [0_u8; 32];
    getrandom::getrandom(&mut token)
        .map_err(|error| format!("Unable to generate watchdog token: {error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(token))
}

fn heartbeat_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "edulearn-exam-watchdog-{}-{}.json",
        std::process::id(),
        now_ms()
    ))
}

fn quote_windows_argument(value: &str) -> String {
    if !value.is_empty()
        && !value
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return value.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for character in value.chars() {
        if character == '\\' {
            backslashes += 1;
        } else if character == '"' {
            quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
            quoted.push('"');
            backslashes = 0;
        } else {
            quoted.push_str(&"\\".repeat(backslashes));
            backslashes = 0;
            quoted.push(character);
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

fn build_command_line(application: &str, arguments: &[String]) -> String {
    std::iter::once(application)
        .chain(arguments.iter().map(String::as_str))
        .map(quote_windows_argument)
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesktopContext {
    desktop_name: String,
    switch_desktop: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DesktopSnapshot {
    desktop_name: String,
    created: bool,
    switched: bool,
    handle_count: usize,
    health: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DesktopRecoveryContext {
    reason: String,
    started_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DesktopRestorePlan {
    switch_back: bool,
    close_exam_desktop: bool,
    close_original_desktop: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DesktopTelemetry {
    desktop_created: bool,
    desktop_destroyed: bool,
    desktop_switched: bool,
    desktop_restored: bool,
    desktop_recovery_started: bool,
    desktop_recovery_completed: bool,
    desktop_crash_recovered: bool,
    desktop_handle_count: usize,
    desktop_lifetime_ms: u64,
    desktop_restore_latency_ms: u64,
    desktop_health: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopTelemetryRecord {
    event: String,
    timestamp_ms: u64,
    recovery_reason: Option<String>,
    telemetry: DesktopTelemetry,
}

fn append_desktop_telemetry(event: &str, telemetry: DesktopTelemetry) {
    append_desktop_telemetry_with_reason(event, telemetry, None);
}

fn append_desktop_telemetry_with_reason(
    event: &str,
    telemetry: DesktopTelemetry,
    recovery_reason: Option<&str>,
) {
    let Ok(path) = std::env::var("EDULEARN_DESKTOP_TELEMETRY_PATH") else {
        return;
    };
    let record = DesktopTelemetryRecord {
        event: event.to_string(),
        timestamp_ms: now_ms(),
        recovery_reason: recovery_reason.map(str::to_string),
        telemetry,
    };
    let Ok(line) = serde_json::to_string(&record) else {
        return;
    };
    use std::io::Write;
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line}");
    }
}

fn restore_desktop_session(
    session: &mut desktop_isolation::DesktopSession,
    reason: &str,
    terminal_event: &str,
) {
    append_desktop_telemetry_with_reason(
        "DesktopRecoveryStarted",
        session.telemetry(),
        Some(reason),
    );
    match session.restore(reason) {
        Ok(telemetry) => {
            append_desktop_telemetry_with_reason("DesktopRestored", telemetry.clone(), Some(reason));
            append_desktop_telemetry_with_reason("DesktopDestroyed", telemetry.clone(), Some(reason));
            append_desktop_telemetry_with_reason(
                "DesktopRecoveryCompleted",
                telemetry.clone(),
                Some(reason),
            );
            if terminal_event != "DesktopRecoveryCompleted" {
                append_desktop_telemetry_with_reason(terminal_event, telemetry, Some(reason));
            }
        }
        Err(_) => {
            append_desktop_telemetry_with_reason(
                "DesktopRecoveryFailed",
                session.telemetry(),
                Some(reason),
            );
        }
    }
}

impl DesktopRestorePlan {
    fn for_snapshot(snapshot: &DesktopSnapshot) -> Self {
        Self {
            switch_back: snapshot.switched,
            close_exam_desktop: snapshot.created,
            close_original_desktop: snapshot.handle_count > 0,
        }
    }

    fn can_close_handles(&self, still_switched_to_exam: bool) -> bool {
        !self.switch_back || !still_switched_to_exam
    }
}

#[cfg(target_os = "windows")]
mod desktop_isolation {
    use super::{
        now_ms, DesktopContext, DesktopRecoveryContext, DesktopRestorePlan, DesktopSnapshot,
        DesktopTelemetry,
    };
    use windows::core::PCWSTR;
    use windows::Win32::System::StationsAndDesktops::{
        CloseDesktop, CreateDesktopW, OpenInputDesktop, SwitchDesktop, DESKTOP_CONTROL_FLAGS,
        DESKTOP_ACCESS_FLAGS, DESKTOP_CREATEWINDOW, DESKTOP_ENUMERATE, DESKTOP_HOOKCONTROL,
        DESKTOP_JOURNALPLAYBACK, DESKTOP_JOURNALRECORD, DESKTOP_READOBJECTS, DESKTOP_SWITCHDESKTOP,
        DESKTOP_WRITEOBJECTS, HDESK,
    };

    pub struct DesktopManager;

    pub struct DesktopHandle {
        handle: HDESK,
        name: String,
        closed: bool,
    }

    pub struct DesktopSession {
        original: DesktopHandle,
        exam: DesktopHandle,
        context: DesktopContext,
        switched: bool,
        created_at_ms: u64,
        recovery_started_at_ms: Option<u64>,
        restored_at_ms: Option<u64>,
        destroyed: bool,
    }

    impl DesktopManager {
        pub fn create_session(context: DesktopContext) -> Result<DesktopSession, String> {
            let original = unsafe {
                OpenInputDesktop(
                    DESKTOP_CONTROL_FLAGS(0),
                    false,
                    DESKTOP_ACCESS_FLAGS(
                        DESKTOP_SWITCHDESKTOP.0 | DESKTOP_READOBJECTS.0 | DESKTOP_WRITEOBJECTS.0,
                    ),
                )
            }
            .map_err(|error| format!("OpenInputDesktop failed: {error}"))?;

            let name_wide = context
                .desktop_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            let access = DESKTOP_CREATEWINDOW.0
                | DESKTOP_ENUMERATE.0
                | DESKTOP_HOOKCONTROL.0
                | DESKTOP_JOURNALPLAYBACK.0
                | DESKTOP_JOURNALRECORD.0
                | DESKTOP_READOBJECTS.0
                | DESKTOP_WRITEOBJECTS.0
                | DESKTOP_SWITCHDESKTOP.0;
            let exam = unsafe {
                CreateDesktopW(
                    PCWSTR(name_wide.as_ptr()),
                    PCWSTR::null(),
                    None,
                    DESKTOP_CONTROL_FLAGS(0),
                    access,
                    None,
                )
            }
            .map_err(|error| {
                let _ = unsafe { CloseDesktop(original) };
                format!("CreateDesktopW failed: {error}")
            })?;

            Ok(DesktopSession {
                original: DesktopHandle {
                    handle: original,
                    name: "WinSta0\\Default".to_string(),
                    closed: false,
                },
                exam: DesktopHandle {
                    handle: exam,
                    name: context.desktop_name.clone(),
                    closed: false,
                },
                context,
                switched: false,
                created_at_ms: now_ms(),
                recovery_started_at_ms: None,
                restored_at_ms: None,
                destroyed: false,
            })
        }
    }

    impl DesktopSession {
        pub fn desktop_path(&self) -> String {
            format!("WinSta0\\{}", self.context.desktop_name)
        }

        pub fn switch_to_exam(&mut self) -> Result<(), String> {
            if !self.context.switch_desktop || self.switched {
                return Ok(());
            }
            unsafe { SwitchDesktop(self.exam.handle) }
                .map_err(|error| format!("SwitchDesktop(exam) failed: {error}"))?;
            self.switched = true;
            Ok(())
        }

        pub fn snapshot(&self) -> DesktopSnapshot {
            DesktopSnapshot {
                desktop_name: self.context.desktop_name.clone(),
                created: !self.exam.closed,
                switched: self.switched,
                handle_count: usize::from(!self.original.closed) + usize::from(!self.exam.closed),
                health: if self.destroyed {
                    "destroyed".to_string()
                } else if self.switched {
                    "switched".to_string()
                } else {
                    "created".to_string()
                },
            }
        }

        pub fn telemetry(&self) -> DesktopTelemetry {
            DesktopTelemetry {
                desktop_created: true,
                desktop_destroyed: self.destroyed,
                desktop_switched: self.switched,
                desktop_restored: self.restored_at_ms.is_some(),
                desktop_recovery_started: self.recovery_started_at_ms.is_some(),
                desktop_recovery_completed: self.restored_at_ms.is_some(),
                desktop_crash_recovered: self
                    .recovery_started_at_ms
                    .zip(self.restored_at_ms)
                    .is_some(),
                desktop_handle_count: self.snapshot().handle_count,
                desktop_lifetime_ms: now_ms().saturating_sub(self.created_at_ms),
                desktop_restore_latency_ms: self
                    .recovery_started_at_ms
                    .zip(self.restored_at_ms)
                    .map(|(started, restored)| restored.saturating_sub(started))
                    .unwrap_or(0),
                desktop_health: self.snapshot().health,
            }
        }

        pub fn restore(&mut self, reason: &str) -> Result<DesktopTelemetry, String> {
            self.recovery_started_at_ms = Some(now_ms());
            let _recovery = DesktopRecoveryContext {
                reason: reason.to_string(),
                started_at_ms: self.recovery_started_at_ms.unwrap_or(0),
            };
            let plan = DesktopRestorePlan::for_snapshot(&self.snapshot());

            if plan.switch_back && self.switched {
                unsafe { SwitchDesktop(self.original.handle) }
                    .map_err(|error| format!("SwitchDesktop(original) failed: {error}"))?;
                self.switched = false;
            }

            if !plan.can_close_handles(self.switched) {
                return Err(
                    "Desktop handles were preserved because the original desktop was not restored."
                        .to_string(),
                );
            }

            if plan.close_exam_desktop && !self.exam.closed {
                self.exam.close()?;
            }
            if plan.close_original_desktop && !self.original.closed {
                self.original.close()?;
            }

            self.destroyed = self.exam.closed;
            self.restored_at_ms = Some(now_ms());
            Ok(self.telemetry())
        }
    }

    impl DesktopHandle {
        fn close(&mut self) -> Result<(), String> {
            if self.closed {
                return Ok(());
            }
            unsafe { CloseDesktop(self.handle) }
                .map_err(|error| format!("CloseDesktop({}) failed: {error}", self.name))?;
            self.closed = true;
            Ok(())
        }
    }

    impl Drop for DesktopSession {
        fn drop(&mut self) {
            if self.switched || !self.exam.closed || !self.original.closed {
                let _ = self.restore("DesktopSession dropped before explicit restore.");
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod desktop_isolation {
    use super::{DesktopContext, DesktopSnapshot, DesktopTelemetry};

    pub struct DesktopManager;
    pub struct DesktopSession {
        context: DesktopContext,
    }

    impl DesktopManager {
        pub fn create_session(context: DesktopContext) -> Result<DesktopSession, String> {
            let _ = context;
            Err("Desktop isolation is only supported on Windows.".to_string())
        }
    }

    impl DesktopSession {
        pub fn desktop_path(&self) -> String {
            format!("WinSta0\\{}", self.context.desktop_name)
        }

        pub fn switch_to_exam(&mut self) -> Result<(), String> {
            Ok(())
        }

        pub fn snapshot(&self) -> DesktopSnapshot {
            DesktopSnapshot {
                desktop_name: self.context.desktop_name.clone(),
                created: false,
                switched: false,
                handle_count: 0,
                health: "unsupported".to_string(),
            }
        }

        pub fn telemetry(&self) -> DesktopTelemetry {
            DesktopTelemetry {
                desktop_created: false,
                desktop_destroyed: false,
                desktop_switched: false,
                desktop_restored: false,
                desktop_recovery_started: false,
                desktop_recovery_completed: false,
                desktop_crash_recovered: false,
                desktop_handle_count: 0,
                desktop_lifetime_ms: 0,
                desktop_restore_latency_ms: 0,
                desktop_health: "unsupported".to_string(),
            }
        }

        pub fn restore(&mut self, _reason: &str) -> Result<DesktopTelemetry, String> {
            Ok(self.telemetry())
        }
    }
}

enum ElectronChild {
    Std(Child),
    #[cfg(target_os = "windows")]
    Win32(Win32ElectronChild),
}

impl ElectronChild {
    fn id(&self) -> u32 {
        match self {
            Self::Std(child) => child.id(),
            #[cfg(target_os = "windows")]
            Self::Win32(child) => child.pid,
        }
    }

    fn try_wait(&mut self) -> Result<Option<i32>, String> {
        match self {
            Self::Std(child) => child
                .try_wait()
                .map(|status| status.map(|status| status.code().unwrap_or(1)))
                .map_err(|error| format!("Failed to query Electron status: {error}")),
            #[cfg(target_os = "windows")]
            Self::Win32(child) => child.try_wait(),
        }
    }

    fn wait(&mut self) -> Result<i32, String> {
        match self {
            Self::Std(child) => child
                .wait()
                .map(|status| status.code().unwrap_or(1))
                .map_err(|error| format!("Failed to wait for Electron: {error}")),
            #[cfg(target_os = "windows")]
            Self::Win32(child) => child.wait(),
        }
    }

    fn kill(&mut self) -> Result<(), String> {
        match self {
            Self::Std(child) => child
                .kill()
                .map_err(|error| format!("Failed to terminate Electron: {error}")),
            #[cfg(target_os = "windows")]
            Self::Win32(child) => child.kill(),
        }
    }

    #[cfg(target_os = "windows")]
    fn raw_process_handle(&self) -> windows::Win32::Foundation::HANDLE {
        match self {
            Self::Std(child) => {
                use std::os::windows::io::AsRawHandle;
                windows::Win32::Foundation::HANDLE(child.as_raw_handle())
            }
            Self::Win32(child) => child.handle,
        }
    }
}

#[cfg(target_os = "windows")]
struct Win32ElectronChild {
    handle: windows::Win32::Foundation::HANDLE,
    pid: u32,
    terminate_on_drop: bool,
}

#[cfg(target_os = "windows")]
impl Win32ElectronChild {
    fn try_wait(&mut self) -> Result<Option<i32>, String> {
        use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

        let wait = unsafe { WaitForSingleObject(self.handle, 0) };
        if wait == WAIT_TIMEOUT {
            return Ok(None);
        }
        if wait != WAIT_OBJECT_0 {
            return Err(format!("WaitForSingleObject returned {wait:?}."));
        }
        let mut exit_code = 1_u32;
        unsafe { GetExitCodeProcess(self.handle, &mut exit_code) }
            .map_err(|error| format!("GetExitCodeProcess failed: {error}"))?;
        self.terminate_on_drop = false;
        Ok(Some(exit_code as i32))
    }

    fn wait(&mut self) -> Result<i32, String> {
        use windows::Win32::Foundation::WAIT_OBJECT_0;
        use windows::Win32::System::Threading::{
            GetExitCodeProcess, WaitForSingleObject, INFINITE,
        };

        let wait = unsafe { WaitForSingleObject(self.handle, INFINITE) };
        if wait != WAIT_OBJECT_0 {
            return Err(format!("WaitForSingleObject returned {wait:?}."));
        }
        let mut exit_code = 1_u32;
        unsafe { GetExitCodeProcess(self.handle, &mut exit_code) }
            .map_err(|error| format!("GetExitCodeProcess failed: {error}"))?;
        self.terminate_on_drop = false;
        Ok(exit_code as i32)
    }

    fn kill(&mut self) -> Result<(), String> {
        use windows::Win32::System::Threading::TerminateProcess;
        unsafe { TerminateProcess(self.handle, 222) }
            .map_err(|error| format!("TerminateProcess(Electron) failed: {error}"))?;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl Drop for Win32ElectronChild {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::TerminateProcess;

        if self.terminate_on_drop {
            let _ = unsafe { TerminateProcess(self.handle, 222) };
        }
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

fn launch_electron(
    config: &BootstrapConfig,
    heartbeat_path: &Path,
    token: &str,
    challenge: &str,
    desktop_path: Option<&str>,
    control_paths: &BootstrapperControlPaths,
) -> Result<ElectronChild, String> {
    if let Some(desktop_path) = desktop_path {
        return launch_electron_on_desktop(
            config,
            heartbeat_path,
            token,
            challenge,
            desktop_path,
            control_paths,
        );
    }

    Command::new(&config.electron_path)
        .args(&config.electron_args)
        .env("EDULEARN_WATCHDOG_HEARTBEAT_PATH", heartbeat_path)
        .env("EDULEARN_WATCHDOG_TOKEN", token)
        .env("EDULEARN_WATCHDOG_CHALLENGE", challenge)
        .env(BOOTSTRAPPER_WIDGET_STATE_ENV, &control_paths.widget_state_path)
        .env(BOOTSTRAPPER_WIDGET_EVENT_ENV, &control_paths.widget_event_path)
        .env(BOOTSTRAPPER_RESTORE_REQUEST_ENV, &control_paths.restore_request_path)
        .env(
            "EDULEARN_EXAM_DESKTOP_ISOLATION_ACTIVE",
            if config.desktop_isolation.enabled { "1" } else { "0" },
        )
        .env(
            "EDULEARN_EXAM_DESKTOP_NAME",
            config.desktop_isolation.desktop_name.as_str(),
        )
        .spawn()
        .map(ElectronChild::Std)
        .map_err(|error| format!("Failed to launch Electron: {error}"))
}

#[cfg(not(target_os = "windows"))]
fn launch_electron_on_desktop(
    _config: &BootstrapConfig,
    _heartbeat_path: &Path,
    _token: &str,
    _challenge: &str,
    _desktop_path: &str,
    _control_paths: &BootstrapperControlPaths,
) -> Result<ElectronChild, String> {
    Err("Desktop isolation launch is only supported on Windows.".to_string())
}

#[cfg(target_os = "windows")]
fn launch_electron_on_desktop(
    config: &BootstrapConfig,
    heartbeat_path: &Path,
    token: &str,
    challenge: &str,
    desktop_path: &str,
    control_paths: &BootstrapperControlPaths,
) -> Result<ElectronChild, String> {
    use std::ffi::c_void;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        CreateProcessW, CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT,
        PROCESS_INFORMATION, STARTUPINFOW,
    };

    let application = config.electron_path.to_string_lossy().to_string();
    let mut application_wide = application
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut command_line_wide = build_command_line(&application, &config.electron_args)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut desktop_path_wide = desktop_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut environment = build_environment_block(&[
        (
            "EDULEARN_WATCHDOG_HEARTBEAT_PATH",
            heartbeat_path.to_string_lossy().as_ref(),
        ),
        ("EDULEARN_WATCHDOG_TOKEN", token),
        ("EDULEARN_WATCHDOG_CHALLENGE", challenge),
        (
            BOOTSTRAPPER_WIDGET_STATE_ENV,
            control_paths.widget_state_path.to_string_lossy().as_ref(),
        ),
        (
            BOOTSTRAPPER_WIDGET_EVENT_ENV,
            control_paths.widget_event_path.to_string_lossy().as_ref(),
        ),
        (
            BOOTSTRAPPER_RESTORE_REQUEST_ENV,
            control_paths.restore_request_path.to_string_lossy().as_ref(),
        ),
        ("EDULEARN_EXAM_DESKTOP_ISOLATION_ACTIVE", "1"),
        (
            "EDULEARN_EXAM_DESKTOP_NAME",
            config.desktop_isolation.desktop_name.as_str(),
        ),
    ]);

    let mut startup = STARTUPINFOW::default();
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    startup.lpDesktop = PWSTR(desktop_path_wide.as_mut_ptr());
    let mut process = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            PCWSTR(application_wide.as_mut_ptr()),
            PWSTR(command_line_wide.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
            Some(environment.as_mut_ptr() as *const c_void),
            PCWSTR::null(),
            &startup,
            &mut process,
        )
    }
    .map_err(|error| format!("CreateProcessW on isolated desktop failed: {error}"))?;
    let _ = unsafe { CloseHandle(process.hThread) };

    Ok(ElectronChild::Win32(Win32ElectronChild {
        handle: process.hProcess,
        pid: process.dwProcessId,
        terminate_on_drop: true,
    }))
}

#[cfg(target_os = "windows")]
fn build_environment_block(overrides: &[(&str, &str)]) -> Vec<u16> {
    let mut entries = std::env::vars().collect::<std::collections::BTreeMap<_, _>>();
    for (key, value) in overrides {
        entries.insert((*key).to_string(), (*value).to_string());
    }

    let mut block = Vec::new();
    for (key, value) in entries {
        block.extend(format!("{key}={value}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

fn terminate_child_after_launch_failure(child: &mut ElectronChild) {
    let _ = child.kill();
    let _ = child.wait();
}

fn run_emergency_restore(
    rust_core_path: &Path,
    report: Option<&BootstrapperEmergencyReport>,
) -> Result<(), String> {
    let mut command = Command::new(rust_core_path);
    command.arg("--emergency-restore");
    if let Some(report) = report {
        let encoded = serde_json::to_string(report)
            .map_err(|error| format!("Failed to serialize bootstrapper emergency report: {error}"))?;
        command.env(BOOTSTRAPPER_EMERGENCY_REPORT_ENV, encoded);
    }
    let status = command
        .status()
        .map_err(|error| format!("Failed to launch emergency restore: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("Emergency restore exited with status {status}."))
    }
}

#[cfg(target_os = "windows")]
mod job {
    use super::ElectronChild;
    use std::ffi::c_void;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    pub struct ProcessJob(HANDLE);

    impl ProcessJob {
        pub fn create() -> Result<Self, String> {
            let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
                .map_err(|error| format!("CreateJobObjectW failed: {error}"))?;
            let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            information.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    &information as *const _ as *const c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            }
            .map_err(|error| format!("SetInformationJobObject failed: {error}"))?;
            Ok(Self(handle))
        }

        pub fn assign(&self, child: &ElectronChild) -> Result<(), String> {
            unsafe { AssignProcessToJobObject(self.0, child.raw_process_handle()) }
                .map_err(|error| format!("AssignProcessToJobObject failed: {error}"))
        }

        pub fn terminate(&self) -> Result<(), String> {
            unsafe { TerminateJobObject(self.0, 222) }
                .map_err(|error| format!("TerminateJobObject failed: {error}"))
        }
    }

    impl Drop for ProcessJob {
        fn drop(&mut self) {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod job {
    use super::ElectronChild;

    pub struct ProcessJob;

    impl ProcessJob {
        pub fn create() -> Result<Self, String> {
            Ok(Self)
        }

        pub fn assign(&self, _child: &ElectronChild) -> Result<(), String> {
            Ok(())
        }

        pub fn terminate(&self) -> Result<(), String> {
            Ok(())
        }
    }
}

fn run(config: BootstrapConfig) -> Result<i32, String> {
    if !config.electron_path.is_file() {
        return Err(format!(
            "Electron executable does not exist: {}",
            config.electron_path.display()
        ));
    }
    if !config.rust_core_path.is_file() {
        return Err(format!(
            "Rust core executable does not exist: {}",
            config.rust_core_path.display()
        ));
    }

    let path = heartbeat_path();
    let control_paths = bootstrapper_control_paths();
    ensure_control_root(&control_paths)?;
    let token = generate_token()?;
    let challenge = generate_token()?;
    let expected_electron_hash = file_sha256(&config.electron_path)?;
    let mut widget_manager = EmergencyWidgetManager::new();
    let mut last_widget_state = WidgetStateRecord::default();
    let mut restore_report: Option<BootstrapperEmergencyReport> = None;
    let mut widget_restore_pending_since_ms: Option<u64> = None;
    let mut desktop_session = if config.desktop_isolation.enabled {
        let session = desktop_isolation::DesktopManager::create_session(DesktopContext {
            desktop_name: config.desktop_isolation.desktop_name.clone(),
            switch_desktop: config.desktop_isolation.switch_desktop,
        })?;
        append_desktop_telemetry("DesktopCreated", session.telemetry());
        Some(session)
    } else {
        None
    };
    let desktop_path = desktop_session
        .as_ref()
        .map(|session| session.desktop_path());
    let job = job::ProcessJob::create()?;
    let mut child = match launch_electron(
        &config,
        &path,
        &token,
        &challenge,
        desktop_path.as_deref(),
        &control_paths,
    ) {
        Ok(child) => child,
        Err(error) => {
            let _ = fs::remove_file(&path);
            if let Some(session) = desktop_session.as_mut() {
                restore_desktop_session(
                    session,
                    "Electron launch failed before desktop switch.",
                    "DesktopRecoveryCompleted",
                );
            }
            return Err(error);
        }
    };
    if let Err(error) = job.assign(&child) {
        terminate_child_after_launch_failure(&mut child);
        let _ = fs::remove_file(&path);
        if let Some(session) = desktop_session.as_mut() {
            restore_desktop_session(
                session,
                "Job assignment failed after isolated desktop launch.",
                "DesktopRecoveryCompleted",
            );
        }
        return Err(error);
    }
    if let Some(session) = desktop_session.as_mut() {
        if let Err(error) = session.switch_to_exam() {
            terminate_child_after_launch_failure(&mut child);
            let _ = fs::remove_file(&path);
            restore_desktop_session(
                session,
                "SwitchDesktop failed after Electron launch.",
                "DesktopRecoveryCompleted",
            );
            return Err(error);
        }
        append_desktop_telemetry("DesktopSwitched", session.telemetry());
    }
    let mut started_at = Instant::now();
    let mut last_healthy_sequence = None;
    let mut monitor_error = None;
    let mut restarts_used: u32 = 0;

    let result = loop {
        match read_json_file::<WidgetStateRecord>(&control_paths.widget_state_path) {
            Ok(Some(widget_state)) => {
                last_widget_state = widget_state.clone();
                widget_manager.update_state(map_widget_state(widget_state));
            }
            Ok(None) => {}
            Err(error) => {
                monitor_error = Some(error);
                let _ = job.terminate();
                let _ = child.wait();
                break 222;
            }
        }

        for event in widget_manager.drain_events() {
            if last_widget_state.widget_id.is_none() {
                continue;
            }
            let interaction = build_widget_interaction_record(&event.kind, last_widget_state.clone());
            let _ = write_json_file(&control_paths.widget_event_path, &interaction);
            if matches!(event.kind, NativeWidgetEventKind::HoldCompleted) {
                widget_restore_pending_since_ms = Some(now_ms());
            }
        }

        match take_json_file::<RestoreRequestRecord>(&control_paths.restore_request_path) {
            Ok(Some(request)) => {
                restore_report = Some(BootstrapperEmergencyReport {
                    trigger: request.trigger,
                    session_id: request.session_id,
                    exam_id: request.exam_id,
                    runtime_id: request.runtime_id,
                    widget_id: request.widget_id,
                    correlation_id: request.correlation_id,
                    requested_at: request.requested_at,
                    desktop_isolation_active: request.desktop_isolation_active,
                    fallback_used: request.fallback_used,
                    timeout_used: request.timeout_used,
                    desktop_switched_back: false,
                    desktop_destroyed: false,
                    detail: request.detail,
                });
                let _ = job.terminate();
                let _ = child.wait();
                break 222;
            }
            Ok(None) => {}
            Err(error) => {
                monitor_error = Some(error);
                let _ = job.terminate();
                let _ = child.wait();
                break 222;
            }
        }

        if let Some(pending_since_ms) = widget_restore_pending_since_ms {
            if now_ms().saturating_sub(pending_since_ms) >= 2_500 {
                restore_report = Some(BootstrapperEmergencyReport {
                    trigger: "bootstrapper-widget-fallback".to_string(),
                    session_id: last_widget_state.session_id.clone(),
                    exam_id: last_widget_state.exam_id.clone(),
                    runtime_id: last_widget_state.runtime_id.clone(),
                    widget_id: last_widget_state.widget_id.clone(),
                    correlation_id: last_widget_state.correlation_id.clone(),
                    requested_at: pending_since_ms,
                    desktop_isolation_active: last_widget_state.desktop_isolation_active,
                    fallback_used: true,
                    timeout_used: true,
                    desktop_switched_back: false,
                    desktop_destroyed: false,
                    detail: "Bootstrapper emergency restore fallback triggered because Rust did not acknowledge the widget request in time.".to_string(),
                });
                let _ = job.terminate();
                let _ = child.wait();
                break 222;
            }
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                // The Electron child exited. If auto-restart is enabled, the exit
                // was ABNORMAL (non-zero), and the budget allows, relaunch it onto
                // the same isolated desktop and keep supervising; otherwise fall
                // through to recovery. Default budget is 0, preserving the
                // historical exit-on-death behaviour. A clean exit (0) — how a
                // completed exam quits — is never restarted.
                if should_restart_child(status, restarts_used, config.electron_restart_max) {
                    // Drop the stale heartbeat so the relaunched child is not
                    // judged against the previous PID (which would be Invalid).
                    let _ = fs::remove_file(&path);
                    match launch_electron(
                        &config,
                        &path,
                        &token,
                        &challenge,
                        desktop_path.as_deref(),
                        &control_paths,
                    ) {
                        Ok(new_child) => match job.assign(&new_child) {
                            Ok(()) => {
                                restarts_used += 1;
                                eprintln!(
                                    "[bootstrapper] Electron exited abnormally ({status}); relaunched ({restarts_used}/{}).",
                                    config.electron_restart_max
                                );
                                child = new_child;
                                started_at = Instant::now();
                                last_healthy_sequence = None;
                                // Back off so a startup-crash loop cannot burn the
                                // whole budget in a tight spin.
                                thread::sleep(Duration::from_millis(RESTART_BACKOFF_MS));
                                continue;
                            }
                            Err(error) => {
                                let mut new_child = new_child;
                                terminate_child_after_launch_failure(&mut new_child);
                                eprintln!(
                                    "[bootstrapper] Failed to supervise relaunched Electron: {error}"
                                );
                                let _ = job.terminate();
                                break 222;
                            }
                        },
                        Err(error) => {
                            eprintln!("[bootstrapper] Failed to relaunch Electron: {error}");
                            let _ = job.terminate();
                            break 222;
                        }
                    }
                }
                break status;
            }
            Ok(None) => {}
            Err(error) => {
                monitor_error = Some(error);
                let _ = job.terminate();
                let _ = child.wait();
                break 222;
            }
        }

        let record = read_heartbeat(&path);
        let health = evaluate_heartbeat(
            record.as_ref(),
            &token,
            &challenge,
            child.id(),
            &config.electron_path,
            &expected_electron_hash,
            last_healthy_sequence,
            now_ms(),
            config.heartbeat_timeout_ms,
            started_at.elapsed().as_millis() as u64,
            config.startup_grace_ms,
        );
        if health == HeartbeatHealth::Healthy {
            last_healthy_sequence = record.as_ref().map(|record| record.sequence);
        }
        if matches!(health, HeartbeatHealth::Stale | HeartbeatHealth::Invalid) {
            let _ = job.terminate();
            let _ = child.wait();
            break 222;
        }
        thread::sleep(Duration::from_millis(MONITOR_INTERVAL_MS));
    };

    // Ensure no orphaned sidecar can re-apply a guard while recovery runs.
    let _ = job.terminate();
    if let Some(session) = desktop_session.as_mut() {
        let terminal_event = if result == 222 {
            "DesktopCrashRecovered"
        } else {
            "DesktopRecoveryCompleted"
        };
        restore_desktop_session(session, "Bootstrapper monitor loop completed.", terminal_event);
        if let Some(report) = restore_report.as_mut() {
            let telemetry = session.telemetry();
            report.desktop_switched_back = telemetry.desktop_restored;
            report.desktop_destroyed = telemetry.desktop_destroyed;
        }
    }
    widget_manager.shutdown();
    let restore_result = run_emergency_restore(&config.rust_core_path, restore_report.as_ref());
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir_all(&control_paths.root_dir);
    restore_result?;
    if let Some(error) = monitor_error {
        return Err(format!(
            "Electron monitor failed after emergency recovery completed: {error}"
        ));
    }
    Ok(result)
}

fn main() -> ExitCode {
    let config = match BootstrapConfig::parse(std::env::args()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("edulearn-bootstrapper: {error}");
            return ExitCode::from(2);
        }
    };
    match run(config) {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(error) => {
            eprintln!("edulearn-bootstrapper: {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bootstrapper_control_paths, build_widget_interaction_record,
        build_command_line, evaluate_heartbeat, heartbeat_challenge_payload, hmac_sha256_hex,
        should_restart_child, validate_desktop_name, BootstrapConfig, DesktopRestorePlan,
        DesktopSnapshot, HeartbeatHealth, HeartbeatRecord,
        NativeWidgetEventKind, WidgetStateRecord, DEFAULT_HEARTBEAT_TIMEOUT_MS,
    };
    use std::path::Path;

    #[test]
    fn auto_restart_is_disabled_by_default_and_only_on_abnormal_exit() {
        // Default budget 0 → never restart (historical exit-on-death behaviour).
        assert!(!should_restart_child(1, 0, 0));
        // A clean exit (0) — a normally-completed exam — is never restarted.
        assert!(!should_restart_child(0, 0, 3));
        // An abnormal exit restarts until the budget is exhausted.
        assert!(should_restart_child(1, 0, 3));
        assert!(should_restart_child(15, 2, 3));
        assert!(!should_restart_child(1, 3, 3));
    }

    #[test]
    fn restart_max_defaults_to_zero_and_parses_when_provided() {
        let default_config = BootstrapConfig::parse(
            ["b.exe", "--electron", "e.exe", "--rust-core", "c.exe"]
                .into_iter()
                .map(str::to_string),
        )
        .unwrap();
        assert_eq!(default_config.electron_restart_max, 0);

        let configured = BootstrapConfig::parse(
            [
                "b.exe",
                "--electron",
                "e.exe",
                "--rust-core",
                "c.exe",
                "--electron-restart-max",
                "3",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap();
        assert_eq!(configured.electron_restart_max, 3);

        // Out-of-range budgets are rejected.
        assert!(BootstrapConfig::parse(
            [
                "b.exe",
                "--electron",
                "e.exe",
                "--rust-core",
                "c.exe",
                "--electron-restart-max",
                "99",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .is_err());
    }

    #[test]
    fn parses_paths_timeouts_and_child_arguments_without_a_shell() {
        let config = BootstrapConfig::parse(
            [
                "bootstrapper.exe",
                "--electron",
                "electron.exe",
                "--rust-core",
                "rust-core.exe",
                "--heartbeat-timeout-ms",
                "9000",
                "--startup-grace-ms",
                "30000",
                "--",
                ".",
                "--inspect=0",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap();

        assert_eq!(config.electron_path.to_string_lossy(), "electron.exe");
        assert_eq!(config.rust_core_path.to_string_lossy(), "rust-core.exe");
        assert_eq!(config.heartbeat_timeout_ms, 9_000);
        assert_eq!(config.electron_args, vec![".", "--inspect=0"]);
        assert!(!config.desktop_isolation.enabled);
    }

    #[test]
    fn parses_desktop_isolation_flags_for_bootstrapper_owned_launch() {
        let config = BootstrapConfig::parse(
            [
                "bootstrapper.exe",
                "--desktop-isolation",
                "--desktop-name",
                "EduLearnExamLab",
                "--electron",
                "electron.exe",
                "--rust-core",
                "rust-core.exe",
                "--",
                ".",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap();

        assert!(config.desktop_isolation.enabled);
        assert_eq!(config.desktop_isolation.desktop_name, "EduLearnExamLab");
        assert!(config.desktop_isolation.switch_desktop);
    }

    #[test]
    fn rejects_unsafe_desktop_names() {
        assert!(validate_desktop_name("EduLearnExam_2026-01").is_ok());
        assert!(validate_desktop_name("WinSta0\\Default").is_err());
        assert!(validate_desktop_name("").is_err());
    }

    #[test]
    fn desktop_restore_plan_follows_snapshot_ownership() {
        let snapshot = DesktopSnapshot {
            desktop_name: "EduLearnExamLab".to_string(),
            created: true,
            switched: true,
            handle_count: 2,
            health: "switched".to_string(),
        };
        let plan = DesktopRestorePlan::for_snapshot(&snapshot);

        assert!(plan.switch_back);
        assert!(plan.close_exam_desktop);
        assert!(plan.close_original_desktop);
        assert!(!plan.can_close_handles(true));
        assert!(plan.can_close_handles(false));
    }

    #[test]
    fn quotes_desktop_launch_command_line_without_shell_expansion() {
        assert_eq!(
            build_command_line(
                "C:\\Program Files\\Electron\\electron.exe",
                &["C:\\app root".to_string(), "--flag=value".to_string()],
            ),
            "\"C:\\Program Files\\Electron\\electron.exe\" \"C:\\app root\" --flag=value"
        );
    }

    #[test]
    fn rejects_invalid_timeout_configuration() {
        let result = BootstrapConfig::parse(
            [
                "bootstrapper.exe",
                "--electron",
                "electron.exe",
                "--rust-core",
                "rust-core.exe",
                "--heartbeat-timeout-ms",
                "100",
            ]
            .into_iter()
            .map(str::to_string),
        );
        assert!(result.is_err());
    }

    #[test]
    fn control_paths_create_separate_widget_and_restore_files() {
        let paths = bootstrapper_control_paths();
        assert!(paths.widget_state_path.ends_with("widget-state.json"));
        assert!(paths.widget_event_path.ends_with("widget-event.json"));
        assert!(paths.restore_request_path.ends_with("restore-request.json"));
    }

    #[test]
    fn widget_interaction_records_preserve_bootstrapper_widget_context() {
        let record = build_widget_interaction_record(
            &NativeWidgetEventKind::HoldCompleted,
            WidgetStateRecord {
                visible: true,
                emergency_restore_widget_state: "visible".to_string(),
                widget_id: Some("widget-1".to_string()),
                correlation_id: Some("corr-1".to_string()),
                require_hold_ms: 2_000,
                session_id: Some("session-1".to_string()),
                exam_id: Some("exam-1".to_string()),
                runtime_id: Some("runtime-1".to_string()),
                kiosk_active: true,
                desktop_isolation_active: true,
                updated_at_ms: 1_000,
            },
        );
        assert_eq!(record.kind, "restoreRequested");
        assert_eq!(record.widget_id.as_deref(), Some("widget-1"));
        assert_eq!(record.runtime_id.as_deref(), Some("runtime-1"));
        assert!(record.desktop_isolation_active);
    }

    fn signed_record(token: &str, challenge: &str) -> HeartbeatRecord {
        let mut record = HeartbeatRecord {
            version: 2,
            sequence: 1,
            timestamp_ms: 10_000,
            electron_pid: 42,
            process_path: "C:\\app\\electron.exe".to_string(),
            process_sha256: "a".repeat(64),
            process_started_at_ms: 9_000,
            native_core_connected: true,
            session_state: "EXAM_RUNNING".to_string(),
            session_id: Some("session-1".to_string()),
            challenge_response: String::new(),
        };
        record.challenge_response =
            hmac_sha256_hex(token, &heartbeat_challenge_payload(&record, challenge)).unwrap();
        record
    }

    #[test]
    fn validates_token_pid_future_timestamp_and_staleness() {
        let token = "token";
        let challenge = "challenge";
        let record = signed_record(token, challenge);
        assert_eq!(
            evaluate_heartbeat(
                Some(&record),
                token,
                challenge,
                42,
                Path::new("C:\\app\\electron.exe"),
                &"a".repeat(64),
                None,
                11_000,
                DEFAULT_HEARTBEAT_TIMEOUT_MS,
                1_000,
                30_000,
            ),
            HeartbeatHealth::Healthy
        );
        assert_eq!(
            evaluate_heartbeat(
                Some(&record),
                "wrong",
                challenge,
                42,
                Path::new("C:\\app\\electron.exe"),
                &"a".repeat(64),
                None,
                11_000,
                DEFAULT_HEARTBEAT_TIMEOUT_MS,
                1_000,
                30_000,
            ),
            HeartbeatHealth::Invalid
        );
        assert_eq!(
            evaluate_heartbeat(
                Some(&record),
                token,
                challenge,
                42,
                Path::new("C:\\app\\electron.exe"),
                &"a".repeat(64),
                None,
                20_000,
                DEFAULT_HEARTBEAT_TIMEOUT_MS,
                1_000,
                30_000,
            ),
            HeartbeatHealth::Stale
        );

        let mut forged = record;
        forged.process_sha256 = "b".repeat(64);
        assert_eq!(
            evaluate_heartbeat(
                Some(&forged),
                token,
                challenge,
                42,
                Path::new("C:\\app\\electron.exe"),
                &"a".repeat(64),
                None,
                11_000,
                DEFAULT_HEARTBEAT_TIMEOUT_MS,
                1_000,
                30_000,
            ),
            HeartbeatHealth::Invalid
        );
    }

    #[test]
    fn rejects_wrong_pid_path_hash_and_replayed_sequence() {
        let token = "token";
        let challenge = "challenge";
        let record = signed_record(token, challenge);

        for (pid, path, hash, last_sequence) in [
            (41, "C:\\app\\electron.exe", "a".repeat(64), None),
            (42, "C:\\other\\electron.exe", "a".repeat(64), None),
            (42, "C:\\app\\electron.exe", "b".repeat(64), None),
            (42, "C:\\app\\electron.exe", "a".repeat(64), Some(1)),
        ] {
            assert_eq!(
                evaluate_heartbeat(
                    Some(&record),
                    token,
                    challenge,
                    pid,
                    Path::new(path),
                    &hash,
                    last_sequence,
                    11_000,
                    DEFAULT_HEARTBEAT_TIMEOUT_MS,
                    1_000,
                    30_000,
                ),
                HeartbeatHealth::Invalid
            );
        }
    }

    #[test]
    fn rejects_forged_challenge_response() {
        let mut record = signed_record("token", "challenge");
        record.challenge_response = "0".repeat(64);
        assert_eq!(
            evaluate_heartbeat(
                Some(&record),
                "token",
                "challenge",
                42,
                Path::new("C:\\app\\electron.exe"),
                &"a".repeat(64),
                None,
                11_000,
                DEFAULT_HEARTBEAT_TIMEOUT_MS,
                1_000,
                30_000,
            ),
            HeartbeatHealth::Invalid
        );
    }

    #[test]
    fn missing_heartbeat_is_allowed_only_during_startup_grace() {
        assert_eq!(
            evaluate_heartbeat(
                None,
                "token",
                "challenge",
                42,
                Path::new("electron.exe"),
                &"a".repeat(64),
                None,
                1,
                8_000,
                5_000,
                30_000,
            ),
            HeartbeatHealth::Waiting
        );
        assert_eq!(
            evaluate_heartbeat(
                None,
                "token",
                "challenge",
                42,
                Path::new("electron.exe"),
                &"a".repeat(64),
                None,
                1,
                8_000,
                31_000,
                30_000,
            ),
            HeartbeatHealth::Stale
        );
    }
}
