#[cfg(test)]
use crate::models::PrecheckSnapshot;
use crate::policy_model::ExamPolicy;

#[derive(Debug, Clone)]
pub struct PrecheckPolicy {
    pub policy_version: String,
    pub review_threshold: u32,
    pub block_threshold: u32,
    pub max_monitor_count: usize,
    pub allow_continue_on_review: bool,
    pub allow_remote_processes: bool,
    pub allow_screen_capture_processes: bool,
    pub allow_debug_tools: bool,
    pub allow_vm: bool,
}

impl Default for PrecheckPolicy {
    fn default() -> Self {
        Self {
            policy_version: "strict-exam-v1".to_string(),
            review_threshold: 25,
            block_threshold: 60,
            max_monitor_count: 1,
            allow_continue_on_review: false,
            allow_remote_processes: false,
            allow_screen_capture_processes: false,
            allow_debug_tools: false,
            allow_vm: false,
        }
    }
}

impl PrecheckPolicy {
    #[cfg(test)]
    pub fn for_snapshot(_snapshot: &PrecheckSnapshot) -> Self {
        // Detection remains strict. The signed process action model decides
        // whether a finding blocks, terminates, audits, or runs under isolation.
        Self::default()
    }

    pub fn from_exam_policy(policy: &ExamPolicy) -> Self {
        Self {
            policy_version: policy.policy_version.clone(),
            max_monitor_count: policy.max_monitor_count,
            allow_vm: policy.allow_vm,
            ..Self::default()
        }
    }
}
