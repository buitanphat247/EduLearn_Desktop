use crate::models::{EvaluationFinding, PrecheckSnapshot, ProcessInfo, RuleMetadata};
use crate::policy::PrecheckPolicy;
use crate::rules::PrecheckRule;

pub struct PolicyBlockedProcessRule;

impl PrecheckRule for PolicyBlockedProcessRule {
    fn evaluate(
        &self,
        snapshot: &PrecheckSnapshot,
        _policy: &PrecheckPolicy,
    ) -> Vec<EvaluationFinding> {
        snapshot
            .process_categories
            .policy_blocked
            .iter()
            .map(build_finding)
            .collect()
    }
}

fn build_finding(process: &ProcessInfo) -> EvaluationFinding {
    EvaluationFinding {
        rule_id: format!("process.policy_blocked.{}", process.pid),
        severity: "block".to_string(),
        confidence: 1.0,
        risk_points: 90,
        summary: format!("Exam policy blocked process: {}", process.name),
        detail: format!(
            "{} is running with pid {} and is explicitly prohibited by the signed exam policy.",
            process.name, process.pid
        ),
        recommendation: "Close the process required by the exam policy and run preflight again."
            .to_string(),
        metadata: RuleMetadata {
            rule_id: "process.policy_blocked".to_string(),
            title: "Policy blocked process".to_string(),
            category: "process".to_string(),
            detector: "signed-policy".to_string(),
        },
    }
}
