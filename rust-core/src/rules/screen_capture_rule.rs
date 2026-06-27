use crate::models::{EvaluationFinding, PrecheckSnapshot, ProcessInfo, RuleMetadata};
use crate::policy::PrecheckPolicy;
use crate::rules::PrecheckRule;

pub struct ScreenCaptureRule;

impl PrecheckRule for ScreenCaptureRule {
    fn evaluate(&self, snapshot: &PrecheckSnapshot, policy: &PrecheckPolicy) -> Vec<EvaluationFinding> {
        if policy.allow_screen_capture_processes {
            return Vec::new();
        }

        snapshot
            .process_categories
            .screen_capture
            .iter()
            .map(build_capture_finding)
            .collect()
    }
}

fn build_capture_finding(process: &ProcessInfo) -> EvaluationFinding {
    EvaluationFinding {
        rule_id: format!("process.capture.{}", process.pid),
        severity: "warn".to_string(),
        confidence: 0.95,
        risk_points: 35,
        summary: format!("Screen capture process detected: {}", process.name),
        detail: format!(
            "{} is active with pid {}. Recording software should be closed before the exam session.",
            process.name, process.pid
        ),
        recommendation: "Close screen capture or recording tools before entering the exam room."
            .to_string(),
        metadata: RuleMetadata {
            rule_id: "process.capture".to_string(),
            title: "Screen capture process".to_string(),
            category: "process".to_string(),
            detector: "process-scan".to_string(),
        },
    }
}
