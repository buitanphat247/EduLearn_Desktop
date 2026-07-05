use crate::models::{ProcessInfo, ProcessPolicyMatch};
use crate::policy_model::{list_contains, ExamPolicy, ProcessPolicyAction};

pub const CATEGORY_BROWSER: &str = "browser";
pub const CATEGORY_COMMUNICATION: &str = "communication";
pub const CATEGORY_POLICY_BLOCKED: &str = "policyBlocked";
pub const CATEGORY_REMOTE_DESKTOP: &str = "remoteDesktop";
pub const CATEGORY_SCREEN_CAPTURE: &str = "screenCapture";
pub const CATEGORY_VIRTUAL_MACHINE: &str = "virtualMachine";
pub const CATEGORY_DEBUG_TOOLS: &str = "debugTools";

#[cfg(test)]
pub fn categorize_process_name(name: &str) -> Vec<String> {
    categorize_process_name_with_policy(name, &ExamPolicy::strict_builtin())
}

pub fn categorize_process_name_with_policy(name: &str, policy: &ExamPolicy) -> Vec<String> {
    let normalized = name.trim().to_ascii_lowercase();
    let mut categories = Vec::new();

    if policy.is_explicitly_blocked(&normalized) {
        categories.push(CATEGORY_POLICY_BLOCKED.to_string());
    }
    push_category_if_matches(
        &mut categories,
        &normalized,
        &policy.browser_processes,
        CATEGORY_BROWSER,
    );
    push_category_if_matches(
        &mut categories,
        &normalized,
        &policy.communication_processes,
        CATEGORY_COMMUNICATION,
    );
    push_category_if_matches(
        &mut categories,
        &normalized,
        &policy.remote_processes,
        CATEGORY_REMOTE_DESKTOP,
    );
    push_category_if_matches(
        &mut categories,
        &normalized,
        &policy.screen_capture_processes,
        CATEGORY_SCREEN_CAPTURE,
    );
    push_category_if_matches(
        &mut categories,
        &normalized,
        &policy.virtual_machine_processes,
        CATEGORY_VIRTUAL_MACHINE,
    );
    push_category_if_matches(
        &mut categories,
        &normalized,
        &policy.debug_processes,
        CATEGORY_DEBUG_TOOLS,
    );

    categories
}

pub fn is_process_prohibited(name: &str, policy: &ExamPolicy) -> bool {
    resolve_process_policy_name(name, policy)
        .map(|decision| decision.action != ProcessPolicyAction::Ignore.as_str())
        .unwrap_or(false)
}

pub fn evaluate_process_policy(
    processes: &[ProcessInfo],
    policy: &ExamPolicy,
) -> Vec<ProcessPolicyMatch> {
    let mut matches = processes
        .iter()
        .filter_map(|process| resolve_process_policy(process, policy))
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| {
        action_priority(&right.action)
            .cmp(&action_priority(&left.action))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.pid.cmp(&right.pid))
    });
    matches
}

pub fn resolve_process_policy(
    process: &ProcessInfo,
    policy: &ExamPolicy,
) -> Option<ProcessPolicyMatch> {
    resolve_process_policy_name(&process.name, policy).map(|decision| ProcessPolicyMatch {
        pid: process.pid,
        name: process.name.clone(),
        executable_path: process.executable_path.clone(),
        creation_time_ms: process.creation_time_ms,
        category: decision.category,
        action: decision.action,
        severity: decision.severity,
        allow_exam_start: decision.allow_exam_start,
        attempt_terminate: decision.attempt_terminate,
        audit_required: decision.audit_required,
    })
}

#[derive(Debug, Clone)]
struct ProcessPolicyDecision {
    category: String,
    action: String,
    severity: String,
    allow_exam_start: bool,
    attempt_terminate: bool,
    audit_required: bool,
}

fn resolve_process_policy_name(
    name: &str,
    policy: &ExamPolicy,
) -> Option<ProcessPolicyDecision> {
    if policy.is_explicitly_blocked(name) {
        return Some(decision(
            CATEGORY_POLICY_BLOCKED,
            ProcessPolicyAction::HardBlock,
            "critical",
        ));
    }

    if let Some(rule) = policy.process_rule_for(name) {
        return Some(ProcessPolicyDecision {
            category: rule.category.clone(),
            action: rule.action.as_str().to_string(),
            severity: rule.severity.clone(),
            allow_exam_start: rule.allow_exam_start,
            attempt_terminate: rule.attempt_terminate,
            audit_required: rule.audit_required,
        });
    }

    if policy.is_explicitly_allowed(name) {
        return None;
    }

    if list_contains(&policy.debug_processes, name) {
        return Some(decision(
            CATEGORY_DEBUG_TOOLS,
            ProcessPolicyAction::HardBlock,
            "critical",
        ));
    }
    if !policy.allow_vm && list_contains(&policy.virtual_machine_processes, name) {
        return Some(decision(
            CATEGORY_VIRTUAL_MACHINE,
            ProcessPolicyAction::HardBlock,
            "high",
        ));
    }

    let is_remote = list_contains(&policy.remote_processes, name);
    let is_capture = list_contains(&policy.screen_capture_processes, name);
    if is_remote || is_capture {
        let category = match (is_remote, is_capture) {
            (true, true) => "remote-control+screen-capture",
            (true, false) => "remote-control",
            (false, true) => "screen-capture",
            (false, false) => unreachable!(),
        };
        return Some(decision(
            category,
            ProcessPolicyAction::IsolateAndProtect,
            "high",
        ));
    }

    None
}

fn decision(
    category: &str,
    action: ProcessPolicyAction,
    severity: &str,
) -> ProcessPolicyDecision {
    ProcessPolicyDecision {
        category: category.to_string(),
        action: action.as_str().to_string(),
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

fn action_priority(action: &str) -> u8 {
    match action {
        "hardBlock" => 7,
        "attemptTerminateThenBlock" => 6,
        "attemptTerminateThenContinue" => 5,
        "isolateAndProtect" => 4,
        "continueAndAudit" => 3,
        "warnOnly" => 2,
        "ignore" => 1,
        _ => 0,
    }
}

pub fn contains_vm_vendor(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("vmware")
        || normalized.contains("virtualbox")
        || normalized.contains("virtual box")
        || normalized.contains("hyper-v")
        || normalized.contains("kvm")
        || normalized.contains("qemu")
        || normalized.contains("parallels")
}

fn push_category_if_matches(
    categories: &mut Vec<String>,
    executable_name: &str,
    prohibited_names: &[String],
    category: &str,
) {
    if prohibited_names
        .iter()
        .any(|candidate| executable_name == candidate)
    {
        categories.push(category.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        categorize_process_name, categorize_process_name_with_policy, contains_vm_vendor,
        is_process_prohibited, resolve_process_policy, CATEGORY_COMMUNICATION,
        CATEGORY_REMOTE_DESKTOP, CATEGORY_SCREEN_CAPTURE,
    };
    use crate::models::ProcessInfo;

    #[test]
    fn classification_is_case_insensitive_and_supports_multiple_categories() {
        let categories = categorize_process_name("Discord.EXE");

        assert!(categories.iter().any(|entry| entry == CATEGORY_COMMUNICATION));
        assert!(categories.iter().any(|entry| entry == CATEGORY_SCREEN_CAPTURE));
    }

    #[test]
    fn classifier_requires_an_exact_executable_name() {
        assert!(categorize_process_name("myobs.exe").is_empty());
        assert!(categorize_process_name("anydesk.exe.backup").is_empty());
        assert!(categorize_process_name("AnyDesk.exe")
            .iter()
            .any(|entry| entry == CATEGORY_REMOTE_DESKTOP));
    }

    #[test]
    fn detects_known_virtual_machine_vendors() {
        assert!(contains_vm_vendor("VMware, Inc."));
        assert!(contains_vm_vendor("Virtual Box"));
        assert!(!contains_vm_vendor("Dell Inc."));
    }

    #[test]
    fn classifies_added_remote_and_capture_tools() {
        for name in ["ultraviewer.exe", "aweray_remote.exe", "msrdc.exe"] {
            assert!(categorize_process_name(name)
                .iter()
                .any(|entry| entry == CATEGORY_REMOTE_DESKTOP));
        }

        for name in [
            "lightshot.exe",
            "greenshot.exe",
            "flameshot.exe",
            "kazam.exe",
        ] {
            assert!(categorize_process_name(name)
                .iter()
                .any(|entry| entry == CATEGORY_SCREEN_CAPTURE));
        }
    }

    #[test]
    fn signed_policy_can_replace_categories_and_allow_an_exception() {
        let mut policy = crate::policy_model::ExamPolicy::strict_builtin();
        policy.remote_processes = vec!["custom-remote.exe".to_string()];
        policy.allowed_processes = vec!["custom-remote.exe".to_string()];

        assert!(categorize_process_name_with_policy("AnyDesk.exe", &policy).is_empty());
        assert!(categorize_process_name_with_policy("custom-remote.exe", &policy)
            .iter()
            .any(|entry| entry == CATEGORY_REMOTE_DESKTOP));
        assert!(!is_process_prohibited("custom-remote.exe", &policy));
    }

    #[test]
    fn remote_and_capture_defaults_are_allowed_under_isolation() {
        let policy = crate::policy_model::ExamPolicy::strict_builtin();
        for name in ["AnyDesk.exe", "parsecd.exe", "obs64.exe"] {
            let decision = resolve_process_policy(
                &ProcessInfo {
                    pid: 42,
                    name: name.to_string(),
                    executable_path: None,
                    creation_time_ms: Some(1),
                    memory_mb: 1,
                    categories: Vec::new(),
                },
                &policy,
            )
            .unwrap();

            assert!(decision.allow_exam_start);
            assert!(!decision.attempt_terminate);
            assert_eq!(decision.action, "isolateAndProtect");
        }
    }

    #[test]
    fn debugger_defaults_remain_hard_blocked() {
        let policy = crate::policy_model::ExamPolicy::strict_builtin();
        let decision = resolve_process_policy(
            &ProcessInfo {
                pid: 43,
                name: "windbg.exe".to_string(),
                executable_path: None,
                creation_time_ms: Some(1),
                memory_mb: 1,
                categories: Vec::new(),
            },
            &policy,
        )
        .unwrap();

        assert!(!decision.allow_exam_start);
        assert_eq!(decision.action, "hardBlock");
    }
}
