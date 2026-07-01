use crate::models::{EvaluationFinding, PrecheckSnapshot, RuleMetadata};
use crate::policy::PrecheckPolicy;
use crate::rules::PrecheckRule;

pub struct VirtualMachineRule;

impl PrecheckRule for VirtualMachineRule {
    fn evaluate(&self, snapshot: &PrecheckSnapshot, policy: &PrecheckPolicy) -> Vec<EvaluationFinding> {
        if policy.allow_vm || snapshot.vm_signals.is_empty() {
            return Vec::new();
        }

        let risk_points = if snapshot.vm_signals.len() >= 2 { 80 } else { 55 };
        let severity = if snapshot.vm_signals.len() >= 2 { "block" } else { "warn" };

        vec![EvaluationFinding {
            rule_id: "environment.virtual_machine".to_string(),
            severity: severity.to_string(),
            confidence: 0.72,
            risk_points,
            summary: "Virtual machine related signals were detected.".to_string(),
            detail: format!(
                "{} VM related signal(s) were collected. VM detection is probabilistic and should be reviewed carefully.",
                snapshot.vm_signals.len()
            ),
            recommendation:
                "Use a physical Windows device for the exam, or review the VM-related signals before continuing."
                    .to_string(),
            metadata: RuleMetadata {
                rule_id: "environment.virtual_machine".to_string(),
                title: "Virtual machine signal".to_string(),
                category: "environment".to_string(),
                detector: "vm-detector".to_string(),
            },
        }]
    }
}
