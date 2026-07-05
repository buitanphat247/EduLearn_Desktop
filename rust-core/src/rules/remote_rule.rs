use crate::models::{EvaluationFinding, PrecheckSnapshot, ProcessInfo, RuleMetadata};
use crate::policy::PrecheckPolicy;
use crate::rules::PrecheckRule;

pub struct RemoteSessionRule;

impl PrecheckRule for RemoteSessionRule {
    fn evaluate(&self, snapshot: &PrecheckSnapshot, policy: &PrecheckPolicy) -> Vec<EvaluationFinding> {
        if policy.allow_remote_processes {
            return Vec::new();
        }

        snapshot
            .process_categories
            .remote_desktop
            .iter()
            .map(|process| build_remote_finding(process))
            .collect()
    }
}

fn build_remote_finding(process: &ProcessInfo) -> EvaluationFinding {
    EvaluationFinding {
        rule_id: format!("process.remote.{}", process.pid),
        severity: "warn".to_string(),
        confidence: 0.98,
        risk_points: 45,
        summary: format!("Remote access process detected: {}", process.name),
        detail: format!(
            "{} is running with pid {}. The signed process action decides whether to block, terminate, or continue under isolation.",
            process.name, process.pid
        ),
        recommendation: "Close remote-control software when possible; otherwise the signed policy may continue with monitoring and isolation."
            .to_string(),
        metadata: RuleMetadata {
            rule_id: "process.remote".to_string(),
            title: "Remote access process".to_string(),
            category: "process".to_string(),
            detector: "process-scan".to_string(),
        },
    }
}
