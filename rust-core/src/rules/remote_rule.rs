use crate::models::{DetectionSignal, EvaluationFinding, PrecheckSnapshot, ProcessInfo, RuleMetadata};
use crate::policy::PrecheckPolicy;
use crate::rules::PrecheckRule;

pub struct RemoteSessionRule;

impl PrecheckRule for RemoteSessionRule {
    fn evaluate(&self, snapshot: &PrecheckSnapshot, policy: &PrecheckPolicy) -> Vec<EvaluationFinding> {
        if policy.allow_remote_processes {
            return Vec::new();
        }

        let mut findings = snapshot
            .process_categories
            .remote_desktop
            .iter()
            .map(build_remote_finding)
            .collect::<Vec<_>>();

        // Environment-level remote signals (RDP session, remote-control ports,
        // mirror display drivers) that are not tied to a named process. These
        // catch TeamViewer/AnyDesk/RustDesk even when the process name is hidden
        // or renamed. Process-sourced signals are skipped here to avoid double
        // counting the per-process findings above.
        findings.extend(
            snapshot
                .remote_signals
                .iter()
                .filter(|signal| signal.source != "process")
                .map(build_remote_signal_finding),
        );

        findings
    }
}

fn build_remote_signal_finding(signal: &DetectionSignal) -> EvaluationFinding {
    EvaluationFinding {
        rule_id: format!("environment.remote.{}", signal.id),
        severity: "warn".to_string(),
        confidence: 0.9,
        risk_points: 40,
        summary: format!("Remote access signal detected: {}", signal.label),
        detail: signal.detail.clone(),
        recommendation:
            "Disable remote-control software and remote sessions before starting the exam."
                .to_string(),
        metadata: RuleMetadata {
            rule_id: "environment.remote".to_string(),
            title: "Remote access signal".to_string(),
            category: "environment".to_string(),
            detector: signal.source.clone(),
        },
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
