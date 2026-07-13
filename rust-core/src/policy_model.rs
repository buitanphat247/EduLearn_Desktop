use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_POLICY_LIFETIME_MS: u64 = 31 * 24 * 60 * 60 * 1_000;
pub const MAX_POLICY_PROCESS_ENTRIES: usize = 512;
pub const REMEDIATION_FAILURE_CONTINUE_AND_AUDIT: &str = "continueAndAudit";
pub const REMEDIATION_FAILURE_RECOVERY_REQUIRED: &str = "recoveryRequired";

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ProcessPolicyAction {
    HardBlock,
    AttemptTerminateThenBlock,
    AttemptTerminateThenContinue,
    ContinueAndAudit,
    IsolateAndProtect,
    WarnOnly,
    Ignore,
}

impl ProcessPolicyAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HardBlock => "hardBlock",
            Self::AttemptTerminateThenBlock => "attemptTerminateThenBlock",
            Self::AttemptTerminateThenContinue => "attemptTerminateThenContinue",
            Self::ContinueAndAudit => "continueAndAudit",
            Self::IsolateAndProtect => "isolateAndProtect",
            Self::WarnOnly => "warnOnly",
            Self::Ignore => "ignore",
        }
    }

    pub fn blocks_exam_start(self) -> bool {
        matches!(self, Self::HardBlock | Self::AttemptTerminateThenBlock)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessRule {
    pub name: String,
    pub category: String,
    pub action: ProcessPolicyAction,
    pub severity: String,
    pub allow_exam_start: bool,
    pub attempt_terminate: bool,
    pub audit_required: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmergencyRestoreWidgetPolicy {
    pub enabled: bool,
    pub require_hold_ms: u64,
    pub allow_during_exam: bool,
    pub allow_in_production: bool,
    pub admin_unlock_required: bool,
    pub audit_required: bool,
}

impl Default for EmergencyRestoreWidgetPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            require_hold_ms: 2_000,
            allow_during_exam: true,
            allow_in_production: true,
            admin_unlock_required: false,
            audit_required: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExamPolicy {
    pub policy_version: String,
    pub exam_id: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    #[serde(default)]
    pub blocked_processes: Vec<String>,
    #[serde(default)]
    pub allowed_processes: Vec<String>,
    #[serde(default)]
    pub browser_processes: Vec<String>,
    #[serde(default)]
    pub communication_processes: Vec<String>,
    #[serde(default)]
    pub remote_processes: Vec<String>,
    #[serde(default)]
    pub screen_capture_processes: Vec<String>,
    #[serde(default)]
    pub virtual_machine_processes: Vec<String>,
    #[serde(default)]
    pub debug_processes: Vec<String>,
    #[serde(default)]
    pub process_rules: Vec<ProcessRule>,
    pub instant_kill: bool,
    pub allow_vm: bool,
    pub max_monitor_count: usize,
    pub capture_protection_required: bool,
    #[serde(default = "default_remediation_failure_mode")]
    pub remediation_failure_mode: String,
    #[serde(default)]
    pub emergency_restore_widget: EmergencyRestoreWidgetPolicy,
}

impl ExamPolicy {
    pub fn strict_builtin() -> Self {
        Self {
            policy_version: "strict-exam-v2-builtin".to_string(),
            exam_id: "*".to_string(),
            issued_at_ms: 0,
            expires_at_ms: u64::MAX,
            blocked_processes: Vec::new(),
            allowed_processes: Vec::new(),
            browser_processes: strings(&[
                "chrome.exe",
                "msedge.exe",
                "firefox.exe",
                "opera.exe",
                "brave.exe",
                "safari.exe",
            ]),
            communication_processes: strings(&[
                "discord.exe",
                "slack.exe",
                "telegram.exe",
                "wechat.exe",
                "zalo.exe",
                "line.exe",
                "teams.exe",
                "zoom.exe",
            ]),
            remote_processes: strings(&[
                "mstsc.exe",
                "rdpclip.exe",
                "anydesk.exe",
                "anydeskmsi.exe",
                "teamviewer.exe",
                "teamviewer_service.exe",
                "teamviewer_desktop.exe",
                "rustdesk.exe",
                "vncviewer.exe",
                "vncserver.exe",
                "winvnc.exe",
                "tvnserver.exe",
                "radmin.exe",
                "radminserver.exe",
                "aeroadmin.exe",
                "supremo.exe",
                "aa_v3.exe",
                "nomachine.exe",
                "nxplayer.exe",
                "nxserver.exe",
                "remoting_host.exe",
                "chrome_remote_desktop.exe",
                "parsecd.exe",
                "parsec.exe",
                "sunshine.exe",
                "moonlight.exe",
                "scrcpy.exe",
                "ultraviewer.exe",
                "aweray_remote.exe",
                "msrdc.exe",
                "deskin.exe",
                "deskin_service.exe",
                "todesk.exe",
                "todesk_service.exe",
                "anyviewer.exe",
                "rcsvc.exe",
                "splashtop.exe",
                "srserver.exe",
                "strwinclt.exe",
                "getscreen.exe",
                "dwservice.exe",
                "dwagent.exe",
                "iperiusremote.exe",
                "logmein.exe",
                "lmiguardiansvc.exe",
                "gotoassist.exe",
                "g2mcomm.exe",
                "screenconnect.exe",
                "connectwisecontrol.exe",
                "zohoassist.exe",
                "rutserv.exe",
                "rutview.exe",
                "litemanager.exe",
                "romserver.exe",
                "romviewer.exe",
                "airdroid.exe",
                "spacedesk.exe",
                "uvnc_service.exe",
                "winvnc4.exe",
                "dwrcs.exe",
                "glidex.exe",
                "glidexremoteservice.exe",
                "glidexservice.exe",
                "glidexnearservice.exe",
                "glidexserviceext.exe",
            ]),
            screen_capture_processes: strings(&[
                "obs64.exe",
                "obs32.exe",
                "obs.exe",
                "bdcam.exe",
                "bandicam.exe",
                "camtasiastudio.exe",
                "snagit32.exe",
                "snagit64.exe",
                "sharex.exe",
                "streamlabs.exe",
                "xsplit.core.exe",
                "screenrec.exe",
                "loom.exe",
                "camtasiarecorder.exe",
                "nvidia share.exe",
                "nvidia overlay.exe",
                "gamebar.exe",
                "gamebarftserver.exe",
                "xboxgamebar.exe",
                "discord.exe",
                "teams.exe",
                "ms-teams.exe",
                "zoom.exe",
                "skype.exe",
                "webex.exe",
                "webexmta.exe",
                "snippingtool.exe",
                "screenclip.exe",
                "psr.exe",
                "stepsrecorder.exe",
                "lightshot.exe",
                "greenshot.exe",
                "flameshot.exe",
                "kazam.exe",
                "action.exe",
                "fraps.exe",
                "dbrecorder.exe",
                "screentogif.exe",
                "hypercam.exe",
                "ocam.exe",
                "activepresenter.exe",
                "apowerrec.exe",
                "flashbackrecorder.exe",
                "ezvid.exe",
                "captura.exe",
                "gyazo.exe",
                "monosnap.exe",
                "screenpresso.exe",
                "vokoscreen.exe",
                "simplescreenrecorder.exe",
                "recexperts.exe",
            ]),
            virtual_machine_processes: strings(&[
                "vmtoolsd.exe",
                "vmwaretray.exe",
                "vmwareuser.exe",
                "vboxservice.exe",
                "vboxtray.exe",
                "prl_tools.exe",
                "qemu-ga.exe",
            ]),
            debug_processes: strings(&[
                "processhacker.exe",
                "procmon.exe",
                "procexp.exe",
                "windbg.exe",
                "x64dbg.exe",
                "x32dbg.exe",
                "ollydbg.exe",
                "ida64.exe",
                "ida.exe",
            ]),
            process_rules: default_process_rules(),
            instant_kill: true,
            allow_vm: false,
            max_monitor_count: 1,
            capture_protection_required: true,
            remediation_failure_mode: REMEDIATION_FAILURE_RECOVERY_REQUIRED.to_string(),
            emergency_restore_widget: EmergencyRestoreWidgetPolicy::default(),
        }
    }

    pub fn validate_for(&self, expected_exam_id: &str, now_ms: u64) -> Result<(), String> {
        validate_identifier("policyVersion", &self.policy_version)?;
        validate_identifier("examId", &self.exam_id)?;

        if self.exam_id != "*" && self.exam_id != expected_exam_id {
            return Err(format!(
                "Policy examId {} does not match requested exam {}.",
                self.exam_id, expected_exam_id
            ));
        }
        if self.issued_at_ms > now_ms {
            return Err("Policy is not active yet.".to_string());
        }
        if self.expires_at_ms <= now_ms {
            return Err("Policy has expired.".to_string());
        }
        if self.expires_at_ms <= self.issued_at_ms {
            return Err("Policy expiresAtMs must be greater than issuedAtMs.".to_string());
        }
        if self.issued_at_ms != 0
            && self.expires_at_ms.saturating_sub(self.issued_at_ms) > MAX_POLICY_LIFETIME_MS
        {
            return Err("Policy lifetime exceeds the maximum supported duration.".to_string());
        }
        if !(1..=8).contains(&self.max_monitor_count) {
            return Err("maxMonitorCount must be between 1 and 8.".to_string());
        }
        if self.remediation_failure_mode != REMEDIATION_FAILURE_CONTINUE_AND_AUDIT
            && self.remediation_failure_mode != REMEDIATION_FAILURE_RECOVERY_REQUIRED
        {
            return Err(
                "remediationFailureMode must be continueAndAudit or recoveryRequired.".to_string(),
            );
        }
        if self.emergency_restore_widget.enabled {
            if !(500..=10_000).contains(&self.emergency_restore_widget.require_hold_ms) {
                return Err(
                    "emergencyRestoreWidget.requireHoldMs must be between 500 and 10000."
                        .to_string(),
                );
            }
            if !self.emergency_restore_widget.audit_required {
                return Err("emergencyRestoreWidget.auditRequired must be true.".to_string());
            }
            if self.emergency_restore_widget.admin_unlock_required
                && self.emergency_restore_widget.allow_during_exam
            {
                return Err(
                    "emergencyRestoreWidget cannot require admin unlock for the emergency restore path."
                        .to_string(),
                );
            }
        }

        let lists = [
            ("blockedProcesses", &self.blocked_processes),
            ("allowedProcesses", &self.allowed_processes),
            ("browserProcesses", &self.browser_processes),
            ("communicationProcesses", &self.communication_processes),
            ("remoteProcesses", &self.remote_processes),
            ("screenCaptureProcesses", &self.screen_capture_processes),
            ("virtualMachineProcesses", &self.virtual_machine_processes),
            ("debugProcesses", &self.debug_processes),
        ];
        let total_entries = lists.iter().map(|(_, entries)| entries.len()).sum::<usize>()
            + self.process_rules.len();
        if total_entries > MAX_POLICY_PROCESS_ENTRIES {
            return Err(format!(
                "Policy contains more than {MAX_POLICY_PROCESS_ENTRIES} process entries."
            ));
        }

        for (name, entries) in lists {
            validate_process_list(name, entries)?;
        }

        let mut rule_names = BTreeSet::new();
        for rule in &self.process_rules {
            validate_process_name("processRules.name", &rule.name)?;
            validate_rule_label("processRules.category", &rule.category)?;
            validate_rule_label("processRules.severity", &rule.severity)?;
            if !rule_names.insert(normalize_process_name(&rule.name)) {
                return Err(format!(
                    "processRules contains a duplicate rule for {}.",
                    rule.name
                ));
            }

            let expected_allow = !rule.action.blocks_exam_start();
            if rule.allow_exam_start != expected_allow {
                return Err(format!(
                    "processRules entry {} has allowExamStart={} inconsistent with action {}.",
                    rule.name,
                    rule.allow_exam_start,
                    rule.action.as_str()
                ));
            }
            let expected_terminate = matches!(
                rule.action,
                ProcessPolicyAction::AttemptTerminateThenBlock
                    | ProcessPolicyAction::AttemptTerminateThenContinue
            );
            if rule.attempt_terminate != expected_terminate {
                return Err(format!(
                    "processRules entry {} has attemptTerminate={} inconsistent with action {}.",
                    rule.name,
                    rule.attempt_terminate,
                    rule.action.as_str()
                ));
            }
            if !rule.audit_required && !matches!(rule.action, ProcessPolicyAction::Ignore) {
                return Err(format!(
                    "processRules entry {} must require audit unless its action is ignore.",
                    rule.name
                ));
            }
        }

        let allowed = normalized_set(&self.allowed_processes);
        let prohibited = normalized_set(&self.blocked_processes);
        if let Some(conflict) = allowed.intersection(&prohibited).next() {
            return Err(format!(
                "Process {conflict} cannot be both allowed and prohibited."
            ));
        }

        Ok(())
    }

    pub fn is_explicitly_allowed(&self, name: &str) -> bool {
        list_contains(&self.allowed_processes, name)
    }

    pub fn is_explicitly_blocked(&self, name: &str) -> bool {
        !self.is_explicitly_allowed(name) && list_contains(&self.blocked_processes, name)
    }

    pub fn process_rule_for(&self, name: &str) -> Option<&ProcessRule> {
        let normalized = normalize_process_name(name);
        self.process_rules
            .iter()
            .find(|rule| normalize_process_name(&rule.name) == normalized)
    }
}

impl Default for ExamPolicy {
    fn default() -> Self {
        Self::strict_builtin()
    }
}

pub fn list_contains(entries: &[String], name: &str) -> bool {
    let normalized = normalize_process_name(name);
    entries
        .iter()
        .any(|entry| normalize_process_name(entry) == normalized)
}

pub fn normalize_process_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

fn strings(entries: &[&str]) -> Vec<String> {
    entries.iter().map(|entry| (*entry).to_string()).collect()
}

fn default_process_rules() -> Vec<ProcessRule> {
    vec![
        process_rule(
            "anydesk.exe",
            "remote-control",
            ProcessPolicyAction::IsolateAndProtect,
            "high",
        ),
        process_rule(
            "remoting_host.exe",
            "remote-control",
            ProcessPolicyAction::ContinueAndAudit,
            "high",
        ),
        process_rule(
            "parsecd.exe",
            "remote-control",
            ProcessPolicyAction::IsolateAndProtect,
            "high",
        ),
        process_rule(
            "parsec.exe",
            "remote-control",
            ProcessPolicyAction::IsolateAndProtect,
            "high",
        ),
        process_rule(
            "obs64.exe",
            "screen-capture",
            ProcessPolicyAction::IsolateAndProtect,
            "high",
        ),
        process_rule(
            "processhacker.exe",
            "debug-tools",
            ProcessPolicyAction::HardBlock,
            "critical",
        ),
        process_rule(
            "x64dbg.exe",
            "debug-tools",
            ProcessPolicyAction::HardBlock,
            "critical",
        ),
    ]
}

fn process_rule(
    name: &str,
    category: &str,
    action: ProcessPolicyAction,
    severity: &str,
) -> ProcessRule {
    ProcessRule {
        name: name.to_string(),
        category: category.to_string(),
        action,
        severity: severity.to_string(),
        allow_exam_start: !action.blocks_exam_start(),
        attempt_terminate: matches!(
            action,
            ProcessPolicyAction::AttemptTerminateThenBlock
                | ProcessPolicyAction::AttemptTerminateThenContinue
        ),
        audit_required: !matches!(action, ProcessPolicyAction::Ignore),
    }
}

fn default_remediation_failure_mode() -> String {
    REMEDIATION_FAILURE_RECOVERY_REQUIRED.to_string()
}

fn normalized_set(entries: &[String]) -> BTreeSet<String> {
    entries
        .iter()
        .map(|entry| normalize_process_name(entry))
        .collect()
}

fn validate_identifier(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 128 {
        return Err(format!("{field} must contain between 1 and 128 characters."));
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "._:-*".contains(character))
    {
        return Err(format!("{field} contains unsupported characters."));
    }
    Ok(())
}

fn validate_rule_label(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 64 {
        return Err(format!("{field} must contain between 1 and 64 characters."));
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "._:-".contains(character))
    {
        return Err(format!("{field} contains unsupported characters."));
    }
    Ok(())
}

fn validate_process_name(field: &str, value: &str) -> Result<(), String> {
    validate_process_list(field, &[value.to_string()])
}

fn validate_process_list(field: &str, entries: &[String]) -> Result<(), String> {
    let mut unique = BTreeSet::new();
    for entry in entries {
        let normalized = normalize_process_name(entry);
        if normalized.is_empty()
            || normalized.len() > 260
            || normalized.contains('\\')
            || normalized.contains('/')
            || !normalized.ends_with(".exe")
        {
            return Err(format!(
                "{field} contains invalid executable name {entry:?}."
            ));
        }
        if !unique.insert(normalized.clone()) {
            return Err(format!("{field} contains duplicate executable {normalized}."));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        EmergencyRestoreWidgetPolicy, ExamPolicy, ProcessPolicyAction, ProcessRule,
        MAX_POLICY_LIFETIME_MS,
        REMEDIATION_FAILURE_CONTINUE_AND_AUDIT, REMEDIATION_FAILURE_RECOVERY_REQUIRED,
    };
    use serde::Deserialize;
    use std::collections::BTreeSet;

    #[test]
    fn strict_policy_is_valid_as_builtin_fallback() {
        let policy = ExamPolicy::strict_builtin();
        assert!(policy.validate_for("exam-1", 100).is_ok());
    }

    #[test]
    fn rejects_expired_mismatched_and_overlong_policies() {
        let mut policy = ExamPolicy::strict_builtin();
        policy.exam_id = "exam-1".to_string();
        policy.issued_at_ms = 1_000;
        policy.expires_at_ms = 2_000;
        assert!(policy.validate_for("exam-2", 1_500).is_err());
        assert!(policy.validate_for("exam-1", 2_000).is_err());

        policy.expires_at_ms = policy.issued_at_ms + MAX_POLICY_LIFETIME_MS + 1;
        assert!(policy.validate_for("exam-1", 1_500).is_err());
    }

    #[test]
    fn rejects_conflicting_or_path_based_process_entries() {
        let mut policy = ExamPolicy::strict_builtin();
        policy.allowed_processes = vec!["custom.exe".to_string()];
        policy.blocked_processes = vec!["custom.exe".to_string()];
        assert!(policy.validate_for("exam-1", 100).is_err());

        policy.allowed_processes.clear();
        policy.blocked_processes = vec!["C:\\Tools\\custom.exe".to_string()];
        assert!(policy.validate_for("exam-1", 100).is_err());
    }

    #[test]
    fn validates_remediation_failure_mode() {
        let mut policy = ExamPolicy::strict_builtin();
        policy.remediation_failure_mode = REMEDIATION_FAILURE_CONTINUE_AND_AUDIT.to_string();
        assert!(policy.validate_for("exam-1", 100).is_ok());

        policy.remediation_failure_mode = "silentIgnore".to_string();
        assert!(policy.validate_for("exam-1", 100).is_err());
    }

    #[test]
    fn validates_emergency_restore_widget_policy() {
        let mut policy = ExamPolicy::strict_builtin();
        assert!(policy.emergency_restore_widget.enabled);
        assert_eq!(policy.emergency_restore_widget.require_hold_ms, 2_000);
        assert!(policy.validate_for("exam-1", 100).is_ok());

        policy.emergency_restore_widget.require_hold_ms = 100;
        assert!(policy.validate_for("exam-1", 100).is_err());

        policy.emergency_restore_widget.require_hold_ms = 2_000;
        policy.emergency_restore_widget.audit_required = false;
        assert!(policy.validate_for("exam-1", 100).is_err());
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SharedPolicyCatalog {
        blocked_processes: Vec<String>,
        allowed_processes: Vec<String>,
        browser_processes: Vec<String>,
        communication_processes: Vec<String>,
        remote_processes: Vec<String>,
        screen_capture_processes: Vec<String>,
        virtual_machine_processes: Vec<String>,
        debug_processes: Vec<String>,
        process_rules: Vec<ProcessRule>,
        instant_kill: bool,
        allow_vm: bool,
        max_monitor_count: usize,
        capture_protection_required: bool,
        remediation_failure_mode: String,
        emergency_restore_widget: EmergencyRestoreWidgetPolicy,
    }

    fn shared_catalog() -> SharedPolicyCatalog {
        serde_json::from_str(include_str!(
            "../../../shared/contracts/exam-guard-policy-catalog.json"
        ))
        .unwrap()
    }

    fn missing_entries(baseline: &[String], candidate: &[String]) -> Vec<String> {
        let candidate = candidate
            .iter()
            .map(|entry| entry.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        baseline
            .iter()
            .filter(|entry| !candidate.contains(&entry.to_ascii_lowercase()))
            .cloned()
            .collect()
    }

    fn assert_not_weaker_than_builtin(candidate: &SharedPolicyCatalog) -> Result<(), String> {
        let builtin = ExamPolicy::strict_builtin();
        for (name, baseline, candidate) in [
            (
                "blockedProcesses",
                &builtin.blocked_processes,
                &candidate.blocked_processes,
            ),
            (
                "browserProcesses",
                &builtin.browser_processes,
                &candidate.browser_processes,
            ),
            (
                "communicationProcesses",
                &builtin.communication_processes,
                &candidate.communication_processes,
            ),
            (
                "remoteProcesses",
                &builtin.remote_processes,
                &candidate.remote_processes,
            ),
            (
                "screenCaptureProcesses",
                &builtin.screen_capture_processes,
                &candidate.screen_capture_processes,
            ),
            (
                "virtualMachineProcesses",
                &builtin.virtual_machine_processes,
                &candidate.virtual_machine_processes,
            ),
            ("debugProcesses", &builtin.debug_processes, &candidate.debug_processes),
        ] {
            let missing = missing_entries(baseline, candidate);
            if !missing.is_empty() {
                return Err(format!("{name} is missing {}", missing.join(", ")));
            }
        }
        if !candidate.allowed_processes.is_empty() {
            return Err("shared catalog must not allow process exceptions by default".to_string());
        }
        for required_rule in &builtin.process_rules {
            let Some(candidate_rule) = candidate
                .process_rules
                .iter()
                .find(|rule| rule.name.eq_ignore_ascii_case(&required_rule.name))
            else {
                return Err(format!(
                    "processRules is missing {}",
                    required_rule.name
                ));
            };
            if candidate_rule != required_rule {
                return Err(format!(
                    "processRules entry {} differs from the Rust builtin",
                    required_rule.name
                ));
            }
        }
        if candidate.instant_kill != builtin.instant_kill
            || candidate.allow_vm != builtin.allow_vm
            || candidate.max_monitor_count != builtin.max_monitor_count
            || candidate.capture_protection_required != builtin.capture_protection_required
            || candidate.remediation_failure_mode != REMEDIATION_FAILURE_RECOVERY_REQUIRED
            || candidate.emergency_restore_widget != builtin.emergency_restore_widget
        {
            return Err("shared catalog protection flags are weaker than builtin".to_string());
        }
        Ok(())
    }

    #[test]
    fn shared_catalog_is_not_weaker_than_rust_builtin_policy() {
        assert_not_weaker_than_builtin(&shared_catalog()).unwrap();
    }

    #[test]
    fn shared_catalog_parity_test_fails_when_a_required_tool_is_missing() {
        let mut catalog = shared_catalog();
        catalog.remote_processes.retain(|entry| entry != "anydesk.exe");

        let error = assert_not_weaker_than_builtin(&catalog).unwrap_err();
        assert!(error.contains("remoteProcesses"));
        assert!(error.contains("anydesk.exe"));
    }

    #[test]
    fn validates_process_rule_action_invariants() {
        let mut policy = ExamPolicy::strict_builtin();
        policy.process_rules.push(ProcessRule {
            name: "custom-debugger.exe".to_string(),
            category: "debug-tools".to_string(),
            action: ProcessPolicyAction::AttemptTerminateThenBlock,
            severity: "critical".to_string(),
            allow_exam_start: false,
            attempt_terminate: false,
            audit_required: true,
        });

        assert!(policy.validate_for("exam-1", 100).is_err());
    }
}
