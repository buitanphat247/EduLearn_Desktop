use crate::models::{EvaluationFinding, PrecheckSnapshot, ProcessInfo, RuleMetadata};
use crate::policy::PrecheckPolicy;
use crate::rules::PrecheckRule;

pub struct DebugToolsRule;

impl PrecheckRule for DebugToolsRule {
    fn evaluate(&self, snapshot: &PrecheckSnapshot, policy: &PrecheckPolicy) -> Vec<EvaluationFinding> {
        if policy.allow_debug_tools {
            return Vec::new();
        }

        snapshot
            .process_categories
            .debug_tools
            .iter()
            .map(build_debug_finding)
            .collect()
    }
}

fn build_debug_finding(process: &ProcessInfo) -> EvaluationFinding {
    EvaluationFinding {
        rule_id: format!("process.debug.{}", process.pid),
        severity: "block".to_string(),
        confidence: 0.99,
        risk_points: 90,
        summary: format!("Debug or inspection tool detected: {}", process.name),
        detail: format!(
            "{} is running with pid {}. Debugging tools are not compatible with the exam environment.",
            process.name, process.pid
        ),
        recommendation: "Close debugging or inspection tools before continuing.".to_string(),
        metadata: RuleMetadata {
            rule_id: "process.debug".to_string(),
            title: "Debug tool process".to_string(),
            category: "process".to_string(),
            detector: "process-scan".to_string(),
        },
    }
}
