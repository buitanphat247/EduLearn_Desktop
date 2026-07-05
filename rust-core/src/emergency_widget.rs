use crate::policy_model::EmergencyRestoreWidgetPolicy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const WIDGET_STATE_HIDDEN: &str = "hidden";
pub const WIDGET_STATE_VISIBLE: &str = "visible";
#[allow(dead_code)]
pub const WIDGET_STATE_HOLDING: &str = "holding";
#[allow(dead_code)]
pub const WIDGET_STATE_REQUESTED: &str = "requested";
pub const WIDGET_STATE_ACCEPTED: &str = "accepted";
pub const WIDGET_STATE_REJECTED: &str = "rejected";
pub const WIDGET_STATE_RESTORING: &str = "restoring";
pub const WIDGET_STATE_COMPLETED: &str = "completed";
#[allow(dead_code)]
pub const WIDGET_STATE_FAILED: &str = "failed";

pub const EVENT_WIDGET_SHOWN: &str = "EmergencyRestoreWidgetShown";
#[allow(dead_code)]
pub const EVENT_HOLD_STARTED: &str = "EmergencyRestoreHoldStarted";
#[allow(dead_code)]
pub const EVENT_HOLD_CANCELLED: &str = "EmergencyRestoreHoldCancelled";
pub const EVENT_RESTORE_REQUESTED: &str = "EmergencyRestoreRequested";
pub const EVENT_RESTORE_ACCEPTED: &str = "EmergencyRestoreAccepted";
pub const EVENT_RESTORE_REJECTED: &str = "EmergencyRestoreRejected";
pub const EVENT_RESTORE_STARTED: &str = "EmergencyRestoreStarted";
pub const EVENT_RESTORE_COMPLETED: &str = "EmergencyRestoreCompleted";
#[allow(dead_code)]
pub const EVENT_RESTORE_FAILED: &str = "EmergencyRestoreFailed";
pub const EVENT_RESTORE_TIMEOUT: &str = "EmergencyRestoreTimeout";
pub const EVENT_RESTORE_BOOTSTRAPPER_FALLBACK: &str = "EmergencyRestoreBootstrapperFallback";
pub const EVENT_RESTORE_DESKTOP_SWITCH: &str = "EmergencyRestoreDesktopSwitch";
pub const EVENT_RESTORE_DESKTOP_DESTROYED: &str = "EmergencyRestoreDesktopDestroyed";
pub const EVENT_WIDGET_DESTROYED: &str = "EmergencyRestoreWidgetDestroyed";

const REQUEST_TTL_MS: u64 = 30_000;
const MAX_RECENT_NONCES: usize = 64;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyRestoreWidgetSnapshot {
    pub emergency_restore_widget_visible: bool,
    pub emergency_restore_widget_state: String,
    pub last_emergency_restore_request_at: Option<u64>,
    pub last_emergency_restore_result: Option<String>,
    pub emergency_restore_attempt_count: usize,
    pub emergency_restore_last_error: Option<String>,
    pub widget_id: Option<String>,
    pub correlation_id: Option<String>,
    pub require_hold_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyRestoreRequestPayload {
    pub session_id: Option<String>,
    pub exam_id: Option<String>,
    pub runtime_id: Option<String>,
    pub reason: String,
    pub widget_id: String,
    pub requested_at: u64,
    pub desktop_isolation_active: bool,
    pub kiosk_active: bool,
    pub correlation_id: String,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyRestoreDecision {
    pub accepted: bool,
    pub state: String,
    pub reason: String,
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EmergencyRestoreValidationContext<'a> {
    pub active_session_id: Option<&'a str>,
    pub current_session_state: &'a str,
    pub expected_runtime_id: &'a str,
    pub kiosk_active: bool,
    pub desktop_isolation_active: bool,
    pub now_ms: u64,
    pub policy: &'a EmergencyRestoreWidgetPolicy,
}

#[derive(Debug, Clone)]
pub struct EmergencyRestoreWidgetController {
    visible: bool,
    state: String,
    widget_id: Option<String>,
    correlation_id: Option<String>,
    hold_started_at: Option<u64>,
    require_hold_ms: u64,
    last_request_at: Option<u64>,
    last_result: Option<String>,
    last_error: Option<String>,
    attempt_count: usize,
    recent_nonces: BTreeSet<String>,
}

impl Default for EmergencyRestoreWidgetController {
    fn default() -> Self {
        Self {
            visible: false,
            state: WIDGET_STATE_HIDDEN.to_string(),
            widget_id: None,
            correlation_id: None,
            hold_started_at: None,
            require_hold_ms: EmergencyRestoreWidgetPolicy::default().require_hold_ms,
            last_request_at: None,
            last_result: None,
            last_error: None,
            attempt_count: 0,
            recent_nonces: BTreeSet::new(),
        }
    }
}

impl EmergencyRestoreWidgetController {
    pub fn snapshot(&self) -> EmergencyRestoreWidgetSnapshot {
        EmergencyRestoreWidgetSnapshot {
            emergency_restore_widget_visible: self.visible,
            emergency_restore_widget_state: self.state.clone(),
            last_emergency_restore_request_at: self.last_request_at,
            last_emergency_restore_result: self.last_result.clone(),
            emergency_restore_attempt_count: self.attempt_count,
            emergency_restore_last_error: self.last_error.clone(),
            widget_id: self.widget_id.clone(),
            correlation_id: self.correlation_id.clone(),
            require_hold_ms: self.require_hold_ms,
        }
    }

    pub fn should_show(
        session_state: &str,
        kiosk_active: bool,
        desktop_isolation_active: bool,
        policy: &EmergencyRestoreWidgetPolicy,
    ) -> bool {
        if !policy.enabled {
            return false;
        }
        if !(kiosk_active || desktop_isolation_active) {
            return false;
        }
        matches!(
            session_state,
            "STARTING_EXAM_SESSION" | "EXAM_RUNNING" | "RECOVERING" | "RECOVERY_REQUIRED"
        )
    }

    pub fn sync_visibility(
        &mut self,
        session_state: &str,
        kiosk_active: bool,
        desktop_isolation_active: bool,
        policy: &EmergencyRestoreWidgetPolicy,
        now_ms: u64,
    ) -> Option<&'static str> {
        self.require_hold_ms = policy.require_hold_ms;
        if Self::should_show(session_state, kiosk_active, desktop_isolation_active, policy) {
            if !self.visible {
                self.visible = true;
                self.state = WIDGET_STATE_VISIBLE.to_string();
                self.widget_id = Some(format!("emergency-widget-{now_ms}"));
                self.correlation_id = Some(format!("emergency-restore-{now_ms}"));
                self.last_error = None;
                return Some(EVENT_WIDGET_SHOWN);
            }
            return None;
        }

        if self.visible || self.state != WIDGET_STATE_HIDDEN {
            self.visible = false;
            self.state = WIDGET_STATE_HIDDEN.to_string();
            self.widget_id = None;
            self.correlation_id = None;
            self.hold_started_at = None;
            return Some(EVENT_WIDGET_DESTROYED);
        }
        None
    }

    #[allow(dead_code)]
    pub fn start_hold(&mut self, now_ms: u64) -> Result<&'static str, String> {
        if !self.visible {
            return Err("Emergency restore widget is not visible.".to_string());
        }
        self.hold_started_at = Some(now_ms);
        self.state = WIDGET_STATE_HOLDING.to_string();
        Ok(EVENT_HOLD_STARTED)
    }

    #[allow(dead_code)]
    pub fn cancel_hold(&mut self) -> Option<&'static str> {
        if self.state == WIDGET_STATE_HOLDING {
            self.state = WIDGET_STATE_VISIBLE.to_string();
            self.hold_started_at = None;
            return Some(EVENT_HOLD_CANCELLED);
        }
        None
    }

    #[allow(dead_code)]
    pub fn complete_hold(&mut self, now_ms: u64) -> Result<EmergencyRestoreRequestPayload, String> {
        let Some(started_at) = self.hold_started_at else {
            return Err("Emergency restore hold was not started.".to_string());
        };
        if now_ms.saturating_sub(started_at) < self.require_hold_ms {
            self.cancel_hold();
            return Err("Emergency restore hold was released before the required duration.".to_string());
        }
        let widget_id = self
            .widget_id
            .clone()
            .ok_or_else(|| "Emergency restore widget id is missing.".to_string())?;
        let correlation_id = self
            .correlation_id
            .clone()
            .unwrap_or_else(|| format!("emergency-restore-{now_ms}"));
        self.hold_started_at = None;
        self.state = WIDGET_STATE_REQUESTED.to_string();
        self.last_request_at = Some(now_ms);
        self.attempt_count = self.attempt_count.saturating_add(1);
        Ok(EmergencyRestoreRequestPayload {
            session_id: None,
            exam_id: None,
            runtime_id: None,
            reason: "user_emergency_widget".to_string(),
            widget_id,
            requested_at: now_ms,
            desktop_isolation_active: false,
            kiosk_active: false,
            correlation_id,
            nonce: format!("emergency-nonce-{now_ms}-{}", self.attempt_count),
        })
    }

    pub fn validate_request(
        &mut self,
        payload: &EmergencyRestoreRequestPayload,
        context: &EmergencyRestoreValidationContext,
    ) -> EmergencyRestoreDecision {
        let rejection = |reason: String, state: &mut Self| {
            state.state = WIDGET_STATE_REJECTED.to_string();
            state.last_result = Some("rejected".to_string());
            state.last_error = Some(reason.clone());
            EmergencyRestoreDecision {
                accepted: false,
                state: WIDGET_STATE_REJECTED.to_string(),
                reason,
                correlation_id: Some(payload.correlation_id.clone()),
            }
        };

        if !context.policy.enabled || !context.policy.audit_required {
            return rejection("Emergency restore widget is disabled by policy.".to_string(), self);
        }
        if !context.policy.allow_during_exam {
            return rejection("Emergency restore is not allowed during the active exam.".to_string(), self);
        }
        if !Self::should_show(
            context.current_session_state,
            context.kiosk_active,
            context.desktop_isolation_active,
            context.policy,
        ) {
            return rejection("Emergency restore is not allowed in the current state.".to_string(), self);
        }
        if payload.reason != "user_emergency_widget" {
            return rejection("Emergency restore reason is not trusted.".to_string(), self);
        }
        if Some(payload.session_id.as_deref().unwrap_or_default()) != context.active_session_id {
            return rejection("Emergency restore session binding failed.".to_string(), self);
        }
        if payload.runtime_id.as_deref() != Some(context.expected_runtime_id) {
            return rejection("Emergency restore runtime binding failed.".to_string(), self);
        }
        if !payload.kiosk_active && !payload.desktop_isolation_active {
            return rejection("Emergency restore request did not prove kiosk or isolation state.".to_string(), self);
        }
        if context.now_ms.saturating_sub(payload.requested_at) > REQUEST_TTL_MS {
            return rejection("Emergency restore request is stale.".to_string(), self);
        }
        if self.recent_nonces.contains(&payload.nonce) {
            return rejection("Emergency restore nonce was replayed.".to_string(), self);
        }
        if Some(payload.widget_id.as_str()) != self.widget_id.as_deref() {
            return rejection("Emergency restore widget binding failed.".to_string(), self);
        }

        self.recent_nonces.insert(payload.nonce.clone());
        while self.recent_nonces.len() > MAX_RECENT_NONCES {
            if let Some(first) = self.recent_nonces.iter().next().cloned() {
                self.recent_nonces.remove(&first);
            }
        }
        self.state = WIDGET_STATE_ACCEPTED.to_string();
        self.last_result = Some("accepted".to_string());
        self.last_error = None;
        EmergencyRestoreDecision {
            accepted: true,
            state: WIDGET_STATE_ACCEPTED.to_string(),
            reason: "Emergency restore request accepted.".to_string(),
            correlation_id: Some(payload.correlation_id.clone()),
        }
    }

    pub fn mark_restoring(&mut self) {
        self.state = WIDGET_STATE_RESTORING.to_string();
    }

    pub fn mark_completed(&mut self) {
        self.visible = false;
        self.state = WIDGET_STATE_COMPLETED.to_string();
        self.last_result = Some("completed".to_string());
        self.last_error = None;
    }

    #[allow(dead_code)]
    pub fn mark_failed(&mut self, error: String) {
        self.visible = true;
        self.state = WIDGET_STATE_FAILED.to_string();
        self.last_result = Some("failed".to_string());
        self.last_error = Some(error);
    }
}

pub fn audit_payload(
    session_id: Option<&str>,
    exam_id: Option<&str>,
    runtime_id: &str,
    desktop_isolation_active: bool,
    kiosk_active: bool,
    runtime_state: &str,
    reason: &str,
    correlation_id: Option<&str>,
    extra: Value,
) -> Value {
    json!({
        "sessionId": session_id,
        "examId": exam_id,
        "runtimeId": runtime_id,
        "desktopIsolationActive": desktop_isolation_active,
        "kioskActive": kiosk_active,
        "runtimeState": runtime_state,
        "reason": reason,
        "correlationId": correlation_id,
        "extra": extra,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> EmergencyRestoreWidgetPolicy {
        EmergencyRestoreWidgetPolicy::default()
    }

    #[test]
    fn widget_is_visible_only_for_active_protection_states() {
        let policy = policy();
        assert!(EmergencyRestoreWidgetController::should_show(
            "EXAM_RUNNING",
            true,
            false,
            &policy
        ));
        assert!(EmergencyRestoreWidgetController::should_show(
            "STARTING_EXAM_SESSION",
            false,
            true,
            &policy
        ));
        assert!(!EmergencyRestoreWidgetController::should_show(
            "IDLE",
            true,
            false,
            &policy
        ));
        assert!(!EmergencyRestoreWidgetController::should_show(
            "EXAM_RUNNING",
            false,
            false,
            &policy
        ));
    }

    #[test]
    fn hold_requires_configured_duration() {
        let mut widget = EmergencyRestoreWidgetController::default();
        let policy = policy();
        widget.sync_visibility("EXAM_RUNNING", true, false, &policy, 1_000);
        assert_eq!(widget.start_hold(1_100).unwrap(), EVENT_HOLD_STARTED);

        let short = widget.complete_hold(2_000);
        assert!(short.is_err());
        assert_eq!(widget.snapshot().emergency_restore_widget_state, WIDGET_STATE_VISIBLE);

        widget.start_hold(2_100).unwrap();
        let request = widget.complete_hold(4_200).unwrap();
        assert_eq!(request.reason, "user_emergency_widget");
        assert_eq!(widget.snapshot().emergency_restore_widget_state, WIDGET_STATE_REQUESTED);
    }

    #[test]
    fn trusted_request_validation_rejects_replay_and_wrong_session() {
        let mut widget = EmergencyRestoreWidgetController::default();
        let policy = policy();
        widget.sync_visibility("EXAM_RUNNING", true, false, &policy, 1_000);
        widget.start_hold(1_100).unwrap();
        let mut request = widget.complete_hold(3_200).unwrap();
        request.session_id = Some("session-1".to_string());
        request.runtime_id = Some("runtime-1".to_string());
        request.kiosk_active = true;

        let context = EmergencyRestoreValidationContext {
            active_session_id: Some("session-1"),
            current_session_state: "EXAM_RUNNING",
            expected_runtime_id: "runtime-1",
            kiosk_active: true,
            desktop_isolation_active: false,
            now_ms: 3_250,
            policy: &policy,
        };

        let accepted = widget.validate_request(&request, &context);
        assert!(accepted.accepted);

        let replayed = widget.validate_request(&request, &context);
        assert!(!replayed.accepted);
        assert!(replayed.reason.contains("replayed"));

        let mut wrong_session = request.clone();
        wrong_session.nonce = "new-nonce".to_string();
        wrong_session.session_id = Some("session-2".to_string());
        let rejected = widget.validate_request(&wrong_session, &context);
        assert!(!rejected.accepted);
        assert!(rejected.reason.contains("session"));
    }
}
