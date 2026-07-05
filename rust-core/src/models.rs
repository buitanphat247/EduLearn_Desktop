use serde::{Deserialize, Serialize};
use crate::exam_key::SignedExamReceipt;
use crate::policy_signature::SignedExamPolicy;
use crate::process_watcher::{
    ProcessCreationEvent, ProcessWatcherBatchReport, ProcessWatcherProducerStatus,
    ProcessWatcherSource,
};
use crate::runtime_events::RuntimeEvent;
use crate::runtime_state_engine::RuntimeStateEngineSnapshot;
use crate::runtime_telemetry::RuntimeTelemetrySnapshot;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleMetadata {
    pub rule_id: String,
    pub title: String,
    pub category: String,
    pub detector: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrecheckSummary {
    pub total_process_count: usize,
    pub monitor_count: usize,
    pub browser_app_count: usize,
    pub remote_app_count: usize,
    pub screen_capture_app_count: usize,
    pub vm_signal_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfo {
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub host_name: String,
    pub architecture: String,
    pub cpu_count: usize,
    pub total_memory_mb: u64,
    pub available_memory_mb: u64,
    pub uptime_seconds: u64,
    pub user_name: String,
    pub system_manufacturer: Option<String>,
    pub system_product_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorInfo {
    pub device_name: String,
    pub width: i32,
    pub height: i32,
    pub offset_x: i32,
    pub offset_y: i32,
    pub is_primary: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DisplayInfo {
    pub monitor_count: usize,
    pub monitors: Vec<MonitorInfo>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub executable_path: Option<String>,
    pub creation_time_ms: Option<u64>,
    pub memory_mb: u64,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessPolicyMatch {
    pub pid: u32,
    pub name: String,
    pub executable_path: Option<String>,
    pub creation_time_ms: Option<u64>,
    pub category: String,
    pub action: String,
    pub severity: String,
    pub allow_exam_start: bool,
    pub attempt_terminate: bool,
    pub audit_required: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessCategories {
    pub browser: Vec<ProcessInfo>,
    pub communication: Vec<ProcessInfo>,
    pub policy_blocked: Vec<ProcessInfo>,
    pub remote_desktop: Vec<ProcessInfo>,
    pub screen_capture: Vec<ProcessInfo>,
    pub virtual_machine: Vec<ProcessInfo>,
    pub debug_tools: Vec<ProcessInfo>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionSignal {
    pub id: String,
    pub label: String,
    pub detail: String,
    pub severity: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluationFinding {
    pub rule_id: String,
    pub severity: String,
    pub confidence: f32,
    pub risk_points: u32,
    pub summary: String,
    pub detail: String,
    pub recommendation: String,
    pub metadata: RuleMetadata,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrecheckEvaluation {
    pub status: String,
    pub total_risk_score: u32,
    pub primary_recommendation: String,
    pub secondary_recommendations: Vec<String>,
    pub findings: Vec<EvaluationFinding>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightDecision {
    pub status: String,
    pub can_enter_exam: bool,
    pub allow_review_continue: bool,
    pub primary_reason: String,
    pub primary_reason_code: String,
    pub reason_codes: Vec<String>,
    pub policy_version: String,
    pub recommendations: Vec<String>,
    pub hard_blocked_processes: Vec<ProcessPolicyMatch>,
    pub terminate_required_processes: Vec<ProcessPolicyMatch>,
    pub continue_with_audit_processes: Vec<ProcessPolicyMatch>,
    pub isolate_and_protect_processes: Vec<ProcessPolicyMatch>,
    pub warnings: Vec<ProcessPolicyMatch>,
    pub runtime_risk_level: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightLogLine {
    pub timestamp: u64,
    pub level: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrecheckSnapshot {
    pub collected_at: u64,
    pub summary: PrecheckSummary,
    pub system_info: SystemInfo,
    pub display_info: DisplayInfo,
    pub process_list: Vec<ProcessInfo>,
    pub process_categories: ProcessCategories,
    pub vm_signals: Vec<DetectionSignal>,
    pub remote_signals: Vec<DetectionSignal>,
    pub screen_capture_signals: Vec<DetectionSignal>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrecheckReport {
    pub collected_at: u64,
    pub snapshot: PrecheckSnapshot,
    pub evaluation: PrecheckEvaluation,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightResult {
    pub collected_at: u64,
    pub report: PrecheckReport,
    pub decision: PreflightDecision,
    pub log_lines: Vec<PreflightLogLine>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopStateSnapshot {
    pub captured_at: u64,
    pub monitor_count: usize,
    pub taskbar_visible: bool,
    pub start_menu_visible: bool,
    pub foreground_window_title: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionStatus {
    pub exam_protection_active: bool,
    pub protection_dry_run: bool,
    pub kiosk_active: bool,
    pub overlay_active: bool,
    pub taskbar_hidden: bool,
    pub keyboard_hook_active: bool,
    pub focus_lock_active: bool,
    pub input_hook_active: bool,
    pub mouse_hook_active: bool,
    pub focus_hook_active: bool,
    pub clipboard_listener_active: bool,
    pub overlay_heal_active: bool,
    pub capture_heal_active: bool,
    pub capture_protection_active: bool,
    pub capture_protection_status: String,
    pub electron_content_protection_active: bool,
    pub rust_overlay_capture_protection_active: bool,
    pub capture_protection_best_effort: bool,
    pub runtime_monitor_active: bool,
    pub active_monitor_count: usize,
    pub black_overlay_count: usize,
    pub last_runtime_event_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExamSessionContext {
    pub session_id: String,
    pub exam_id: Option<String>,
    pub room_code: Option<String>,
    pub started_at: u64,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionLogLine {
    pub timestamp: u64,
    pub level: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessRemediationAction {
    pub pid: u32,
    pub name: String,
    pub category: String,
    pub first_detected_at: u64,
    pub deadline_at: u64,
    pub action: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessRemediationReport {
    pub grace_period_ms: u64,
    pub pending_termination_count: usize,
    pub terminated_count: usize,
    pub failed_count: usize,
    pub actions: Vec<ProcessRemediationAction>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeMonitorSummary {
    pub total_process_count: usize,
    pub monitor_count: usize,
    pub remote_signal_count: usize,
    pub screen_capture_signal_count: usize,
    pub vm_signal_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartExamSessionPayload {
    pub session_id: String,
    pub exam_id: Option<String>,
    pub room_code: Option<String>,
    pub window_handle_hex: Option<String>,
    #[serde(default)]
    pub exam_key: Option<SignedExamReceipt>,
    #[serde(default)]
    pub service_authorization: Option<SignedExamReceipt>,
    #[serde(default = "default_true")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExitExamSessionPayload {
    pub session_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotifyVisualKioskReadyPayload {
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterKioskPayload {
    pub session_id: Option<String>,
    pub window_handle_hex: Option<String>,
    #[serde(default)]
    pub electron_content_protection_active: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeMonitorTickPayload {
    #[serde(default)]
    pub window_handle_hex: Option<String>,
    #[serde(default)]
    pub electron_content_protection_active: bool,
    #[serde(default)]
    pub process_creation_events: Vec<ProcessCreationEvent>,
    #[serde(default)]
    pub process_watcher_source: ProcessWatcherSource,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoadExamPolicyPayload {
    pub exam_id: String,
    pub envelope: SignedExamPolicy,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreflightKillPayload {
    #[serde(default)]
    pub service_authorization: Option<SignedExamReceipt>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartExamSessionResult {
    pub started_at: u64,
    pub session_state: String,
    pub session_context: ExamSessionContext,
    pub desktop_state: DesktopStateSnapshot,
    pub protection_status: ProtectionStatus,
    pub runtime_risk_level: String,
    pub process_policy: Vec<ProcessPolicyMatch>,
    pub log_lines: Vec<ProtectionLogLine>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionTransitionResult {
    pub transitioned_at: u64,
    pub session_state: String,
    pub protection_status: ProtectionStatus,
    pub restored_desktop: Option<bool>,
    pub log_lines: Vec<ProtectionLogLine>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExitExamSessionResult {
    pub exited_at: u64,
    pub session_state: String,
    pub protection_status: ProtectionStatus,
    pub restored_desktop: bool,
    pub log_lines: Vec<ProtectionLogLine>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeMonitorTickResult {
    pub collected_at: u64,
    pub session_state: String,
    pub summary: RuntimeMonitorSummary,
    pub process_watcher: ProcessWatcherBatchReport,
    pub process_watcher_producer: ProcessWatcherProducerStatus,
    pub runtime_state_engine: RuntimeStateEngineSnapshot,
    pub runtime_telemetry: RuntimeTelemetrySnapshot,
    pub runtime_events: Vec<RuntimeEvent>,
    pub display_info: DisplayInfo,
    pub remote_signals: Vec<DetectionSignal>,
    pub screen_capture_signals: Vec<DetectionSignal>,
    pub vm_signals: Vec<DetectionSignal>,
    pub process_remediation: ProcessRemediationReport,
    pub runtime_risk_level: String,
    pub process_policy: Vec<ProcessPolicyMatch>,
    pub protection_status: ProtectionStatus,
    pub log_lines: Vec<ProtectionLogLine>,
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::RuntimeMonitorTickPayload;

    #[test]
    fn runtime_tick_payload_accepts_missing_window_handle() {
        let payload: RuntimeMonitorTickPayload =
            serde_json::from_str("{}").expect("empty payload should be valid");

        assert!(payload.window_handle_hex.is_none());
    }
}
