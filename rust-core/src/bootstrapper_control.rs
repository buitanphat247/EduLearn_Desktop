use crate::emergency_widget::{
    EmergencyRestoreRequestPayload, EmergencyRestoreWidgetSnapshot,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const BOOTSTRAPPER_WIDGET_STATE_ENV: &str = "EDULEARN_BOOTSTRAPPER_WIDGET_STATE_PATH";
const BOOTSTRAPPER_WIDGET_EVENT_ENV: &str = "EDULEARN_BOOTSTRAPPER_WIDGET_EVENT_PATH";
const BOOTSTRAPPER_RESTORE_REQUEST_ENV: &str = "EDULEARN_BOOTSTRAPPER_RESTORE_REQUEST_PATH";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WidgetStateRecord {
    pub visible: bool,
    pub emergency_restore_widget_state: String,
    pub widget_id: Option<String>,
    pub correlation_id: Option<String>,
    pub require_hold_ms: u64,
    pub session_id: Option<String>,
    pub exam_id: Option<String>,
    pub runtime_id: Option<String>,
    pub kiosk_active: bool,
    pub desktop_isolation_active: bool,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WidgetInteractionRecord {
    pub kind: String,
    pub session_id: Option<String>,
    pub exam_id: Option<String>,
    pub runtime_id: Option<String>,
    pub widget_id: Option<String>,
    pub correlation_id: Option<String>,
    pub requested_at: u64,
    pub desktop_isolation_active: bool,
    pub kiosk_active: bool,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreRequestRecord {
    pub trigger: String,
    pub session_id: Option<String>,
    pub exam_id: Option<String>,
    pub runtime_id: Option<String>,
    pub widget_id: Option<String>,
    pub correlation_id: Option<String>,
    pub requested_at: u64,
    pub desktop_isolation_active: bool,
    pub kiosk_active: bool,
    pub fallback_used: bool,
    pub timeout_used: bool,
    pub detail: String,
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    let temp = path.with_extension("tmp");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&temp, bytes)?;
    fs::rename(temp, path)?;
    Ok(())
}

fn take_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> io::Result<Option<T>> {
    if !path.is_file() {
        return Ok(None);
    }
    let contents = fs::read_to_string(path)?;
    let parsed = serde_json::from_str(&contents).map_err(io::Error::other)?;
    let _ = fs::remove_file(path);
    Ok(Some(parsed))
}

pub fn sync_widget_state(
    snapshot: &EmergencyRestoreWidgetSnapshot,
    session_id: Option<&str>,
    exam_id: Option<&str>,
    runtime_id: &str,
    kiosk_active: bool,
    desktop_isolation_active: bool,
    updated_at_ms: u64,
) -> io::Result<bool> {
    let Some(path) = env_path(BOOTSTRAPPER_WIDGET_STATE_ENV) else {
        return Ok(false);
    };
    let record = WidgetStateRecord {
        visible: snapshot.emergency_restore_widget_visible,
        emergency_restore_widget_state: snapshot.emergency_restore_widget_state.clone(),
        widget_id: snapshot.widget_id.clone(),
        correlation_id: snapshot.correlation_id.clone(),
        require_hold_ms: snapshot.require_hold_ms,
        session_id: session_id.map(str::to_string),
        exam_id: exam_id.map(str::to_string),
        runtime_id: Some(runtime_id.to_string()),
        kiosk_active,
        desktop_isolation_active,
        updated_at_ms,
    };
    write_json_file(&path, &record)?;
    Ok(true)
}

pub fn take_widget_interaction() -> io::Result<Option<WidgetInteractionRecord>> {
    let Some(path) = env_path(BOOTSTRAPPER_WIDGET_EVENT_ENV) else {
        return Ok(None);
    };
    take_json_file(&path)
}

pub fn write_restore_request(
    payload: &EmergencyRestoreRequestPayload,
    exam_id: Option<&str>,
    runtime_id: &str,
    trigger: &str,
    detail: &str,
    fallback_used: bool,
    timeout_used: bool,
) -> io::Result<bool> {
    let Some(path) = env_path(BOOTSTRAPPER_RESTORE_REQUEST_ENV) else {
        return Ok(false);
    };
    let record = RestoreRequestRecord {
        trigger: trigger.to_string(),
        session_id: payload.session_id.clone(),
        exam_id: exam_id.map(str::to_string).or_else(|| payload.exam_id.clone()),
        runtime_id: Some(runtime_id.to_string()),
        widget_id: Some(payload.widget_id.clone()),
        correlation_id: Some(payload.correlation_id.clone()),
        requested_at: payload.requested_at,
        desktop_isolation_active: payload.desktop_isolation_active,
        kiosk_active: payload.kiosk_active,
        fallback_used,
        timeout_used,
        detail: detail.to_string(),
    };
    write_json_file(&path, &record)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{sync_widget_state, take_widget_interaction, write_restore_request};
    use crate::emergency_widget::EmergencyRestoreWidgetSnapshot;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "edulearn-bootstrapper-control-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn widget_state_sync_is_noop_without_env() {
        std::env::remove_var("EDULEARN_BOOTSTRAPPER_WIDGET_STATE_PATH");
        let wrote = sync_widget_state(
            &EmergencyRestoreWidgetSnapshot {
                emergency_restore_widget_visible: true,
                emergency_restore_widget_state: "visible".to_string(),
                last_emergency_restore_request_at: None,
                last_emergency_restore_result: None,
                emergency_restore_attempt_count: 0,
                emergency_restore_last_error: None,
                widget_id: Some("widget-1".to_string()),
                correlation_id: Some("corr-1".to_string()),
                require_hold_ms: 2_000,
            },
            Some("session-1"),
            None,
            "runtime-1",
            true,
            false,
            1_000,
        )
        .unwrap();
        assert!(!wrote);
    }

    #[test]
    fn restore_request_and_widget_events_use_configured_files() {
        let root = temp_root();
        let widget_event = root.join("widget-event.json");
        let widget_state = root.join("widget-state.json");
        let restore_request = root.join("restore-request.json");
        std::fs::create_dir_all(&root).unwrap();
        std::env::set_var("EDULEARN_BOOTSTRAPPER_WIDGET_EVENT_PATH", &widget_event);
        std::env::set_var("EDULEARN_BOOTSTRAPPER_WIDGET_STATE_PATH", &widget_state);
        std::env::set_var("EDULEARN_BOOTSTRAPPER_RESTORE_REQUEST_PATH", &restore_request);
        std::fs::write(
            &widget_event,
            r#"{"kind":"holdStarted","sessionId":"s1","examId":"e1","runtimeId":"r1","widgetId":"w1","correlationId":"c1","requestedAt":1000,"desktopIsolationActive":true,"kioskActive":true,"nonce":"n1"}"#,
        )
        .unwrap();

        let event = take_widget_interaction().unwrap().unwrap();
        assert_eq!(event.kind, "holdStarted");
        assert!(!widget_event.exists());

        let payload = crate::emergency_widget::EmergencyRestoreRequestPayload {
            session_id: Some("s1".to_string()),
            exam_id: Some("e1".to_string()),
            runtime_id: Some("r1".to_string()),
            reason: "user_emergency_widget".to_string(),
            widget_id: "w1".to_string(),
            requested_at: 2_000,
            desktop_isolation_active: true,
            kiosk_active: true,
            correlation_id: "c1".to_string(),
            nonce: "n2".to_string(),
        };
        let wrote = write_restore_request(
            &payload,
            Some("e1"),
            "r1",
            "trusted-widget",
            "detail",
            false,
            false,
        )
        .unwrap();
        assert!(wrote);
        assert!(restore_request.exists());
    }
}
