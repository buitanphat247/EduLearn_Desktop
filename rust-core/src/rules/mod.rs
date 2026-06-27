mod debug_tools_rule;
mod monitor_rule;
mod remote_rule;
mod screen_capture_rule;
mod vm_rule;

use crate::models::{EvaluationFinding, PrecheckSnapshot};
use crate::policy::PrecheckPolicy;

pub trait PrecheckRule {
    fn evaluate(&self, snapshot: &PrecheckSnapshot, policy: &PrecheckPolicy) -> Vec<EvaluationFinding>;
}

pub fn run_precheck_rules(
    snapshot: &PrecheckSnapshot,
    policy: &PrecheckPolicy,
) -> Vec<EvaluationFinding> {
    let rules: Vec<Box<dyn PrecheckRule>> = vec![
        Box::new(monitor_rule::MonitorCountRule),
        Box::new(remote_rule::RemoteSessionRule),
        Box::new(screen_capture_rule::ScreenCaptureRule),
        Box::new(debug_tools_rule::DebugToolsRule),
        Box::new(vm_rule::VirtualMachineRule),
    ];

    let mut findings = Vec::new();
    for rule in rules {
        findings.extend(rule.evaluate(snapshot, policy));
    }

    findings.sort_by(|left, right| {
        right
            .risk_points
            .cmp(&left.risk_points)
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });

    findings
}
