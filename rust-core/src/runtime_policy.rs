use crate::policy_model::{ExamPolicy, REMEDIATION_FAILURE_CONTINUE_AND_AUDIT};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePolicyInput {
    pub vm_signal_count: usize,
    pub monitor_count: usize,
    pub capture_protection_best_effort: bool,
    pub pending_termination_count: usize,
    pub failed_termination_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePolicyDecision {
    pub recovery_required: bool,
    pub reason_codes: Vec<&'static str>,
}

pub fn evaluate_runtime_policy(
    input: &RuntimePolicyInput,
    policy: &ExamPolicy,
) -> RuntimePolicyDecision {
    let mut reason_codes = Vec::new();

    if input.vm_signal_count > 0 {
        reason_codes.push("VM_SIGNAL");
    }
    if input.monitor_count > policy.max_monitor_count {
        reason_codes.push("DISPLAY_POLICY");
    }
    if policy.capture_protection_required && !input.capture_protection_best_effort {
        reason_codes.push("CAPTURE_PROTECTION_REQUIRED");
    }
    if (input.pending_termination_count > 0 || input.failed_termination_count > 0)
        && policy.remediation_failure_mode != REMEDIATION_FAILURE_CONTINUE_AND_AUDIT
    {
        reason_codes.push("PROCESS_REMEDIATION_UNRESOLVED");
    }

    RuntimePolicyDecision {
        recovery_required: !reason_codes.is_empty(),
        reason_codes,
    }
}

#[cfg(test)]
mod tests {
    use super::{evaluate_runtime_policy, RuntimePolicyInput};
    use crate::policy_model::ExamPolicy;

    fn clean_input() -> RuntimePolicyInput {
        RuntimePolicyInput {
            vm_signal_count: 0,
            monitor_count: 1,
            capture_protection_best_effort: true,
            pending_termination_count: 0,
            failed_termination_count: 0,
        }
    }

    #[test]
    fn clean_runtime_policy_allows_exam_to_continue() {
        let decision = evaluate_runtime_policy(&clean_input(), &ExamPolicy::strict_builtin());
        assert!(!decision.recovery_required);
        assert!(decision.reason_codes.is_empty());
    }

    #[test]
    fn failed_remediation_recovers_by_default() {
        let mut input = clean_input();
        input.failed_termination_count = 1;
        let decision = evaluate_runtime_policy(&input, &ExamPolicy::strict_builtin());

        assert!(decision.recovery_required);
        assert_eq!(decision.reason_codes, vec!["PROCESS_REMEDIATION_UNRESOLVED"]);
    }

    #[test]
    fn failed_remediation_can_continue_and_audit() {
        let mut policy = ExamPolicy::strict_builtin();
        policy.remediation_failure_mode = "continueAndAudit".to_string();
        let mut input = clean_input();
        input.failed_termination_count = 1;
        let decision = evaluate_runtime_policy(&input, &policy);

        assert!(!decision.recovery_required);
        assert!(decision.reason_codes.is_empty());
    }

    #[test]
    fn report_only_pending_processes_still_follow_recovery_policy() {
        let mut policy = ExamPolicy::strict_builtin();
        policy.instant_kill = false;
        let mut input = clean_input();
        input.pending_termination_count = 1;
        let decision = evaluate_runtime_policy(&input, &policy);

        assert!(decision.recovery_required);
        assert_eq!(decision.reason_codes, vec!["PROCESS_REMEDIATION_UNRESOLVED"]);
    }
}
