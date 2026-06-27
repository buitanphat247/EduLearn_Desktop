use crate::models::{EvaluationFinding, PrecheckSnapshot, RuleMetadata};
use crate::policy::PrecheckPolicy;
use crate::rules::PrecheckRule;

pub struct MonitorCountRule;

impl PrecheckRule for MonitorCountRule {
    fn evaluate(&self, snapshot: &PrecheckSnapshot, policy: &PrecheckPolicy) -> Vec<EvaluationFinding> {
        if snapshot.display_info.monitor_count <= policy.max_monitor_count {
            return Vec::new();
        }

        vec![EvaluationFinding {
            rule_id: "monitor.multiple_displays".to_string(),
            severity: "warn".to_string(),
            confidence: 1.0,
            risk_points: 25,
            summary: "Multiple active displays detected.".to_string(),
            detail: format!(
                "{} monitors are active. The exam flow is designed for a single focused display.",
                snapshot.display_info.monitor_count
            ),
            recommendation: "Disconnect extra monitors before entering the exam room.".to_string(),
            metadata: RuleMetadata {
                rule_id: "monitor.multiple_displays".to_string(),
                title: "Multiple displays".to_string(),
                category: "display".to_string(),
                detector: "display-collector".to_string(),
            },
        }]
    }
}
