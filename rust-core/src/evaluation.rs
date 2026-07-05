use crate::models::{
    EvaluationFinding, PrecheckEvaluation, PrecheckReport, PrecheckSnapshot, PreflightDecision,
    PreflightLogLine, PreflightResult,
};
use crate::policy::PrecheckPolicy;
use crate::policy_model::ExamPolicy;
use crate::process_policy::evaluate_process_policy;
use crate::rules::run_precheck_rules;
use std::collections::BTreeSet;

#[cfg(test)]
pub fn evaluate_precheck_snapshot(snapshot: &PrecheckSnapshot) -> PrecheckEvaluation {
    let policy = PrecheckPolicy::for_snapshot(snapshot);
    evaluate_precheck_snapshot_with_policy(snapshot, &policy)
}

fn evaluate_precheck_snapshot_with_policy(
    snapshot: &PrecheckSnapshot,
    policy: &PrecheckPolicy,
) -> PrecheckEvaluation {
    let findings = run_precheck_rules(snapshot, &policy);
    let total_risk_score = findings
        .iter()
        .fold(0u32, |accumulator, finding| accumulator.saturating_add(finding.risk_points))
        .min(100);

    let has_blocking_finding = findings.iter().any(|finding| finding.severity == "block");
    let status = if has_blocking_finding || total_risk_score >= policy.block_threshold {
        "block"
    } else if !findings.is_empty() || total_risk_score >= policy.review_threshold {
        "review"
    } else {
        "ready"
    };

    let primary_recommendation = match status {
        "block" => "Resolve blocking findings before starting the exam.".to_string(),
        "review" => "Review the findings and reduce risk before entering the exam room.".to_string(),
        _ => "The environment looks acceptable for the current desktop pre-check.".to_string(),
    };

    let secondary_recommendations = collect_recommendations(&findings);

    PrecheckEvaluation {
        status: status.to_string(),
        total_risk_score,
        primary_recommendation,
        secondary_recommendations,
        findings,
    }
}

pub fn build_precheck_report_with_policy(
    snapshot: PrecheckSnapshot,
    exam_policy: &ExamPolicy,
) -> PrecheckReport {
    let policy = PrecheckPolicy::from_exam_policy(exam_policy);
    let evaluation = evaluate_precheck_snapshot_with_policy(&snapshot, &policy);

    PrecheckReport {
        collected_at: snapshot.collected_at,
        snapshot,
        evaluation,
    }
}

#[cfg(test)]
pub fn build_preflight_result(snapshot: PrecheckSnapshot) -> PreflightResult {
    build_preflight_result_with_policy(snapshot, &ExamPolicy::strict_builtin())
}

pub fn build_preflight_result_with_policy(
    snapshot: PrecheckSnapshot,
    exam_policy: &ExamPolicy,
) -> PreflightResult {
    let policy = PrecheckPolicy::from_exam_policy(exam_policy);
    let report = build_precheck_report_with_policy(snapshot, exam_policy);
    let decision = build_preflight_decision(&report, &policy, exam_policy);
    let log_lines = build_preflight_log_lines(&report, &decision);

    PreflightResult {
        collected_at: report.collected_at,
        report,
        decision,
        log_lines,
    }
}

fn collect_recommendations(findings: &[EvaluationFinding]) -> Vec<String> {
    let mut unique_recommendations = BTreeSet::new();
    for finding in findings {
        unique_recommendations.insert(finding.recommendation.clone());
    }

    unique_recommendations.into_iter().collect()
}

fn build_preflight_decision(
    report: &PrecheckReport,
    policy: &PrecheckPolicy,
    exam_policy: &ExamPolicy,
) -> PreflightDecision {
    let process_policy = evaluate_process_policy(&report.snapshot.process_list, exam_policy);
    let hard_blocked_processes = process_policy
        .iter()
        .filter(|process| process.action == "hardBlock")
        .cloned()
        .collect::<Vec<_>>();
    let terminate_required_processes = process_policy
        .iter()
        .filter(|process| process.action == "attemptTerminateThenBlock")
        .cloned()
        .collect::<Vec<_>>();
    let continue_with_audit_processes = process_policy
        .iter()
        .filter(|process| {
            process.action == "continueAndAudit"
                || process.action == "attemptTerminateThenContinue"
        })
        .cloned()
        .collect::<Vec<_>>();
    let isolate_and_protect_processes = process_policy
        .iter()
        .filter(|process| process.action == "isolateAndProtect")
        .cloned()
        .collect::<Vec<_>>();
    let warnings = process_policy
        .iter()
        .filter(|process| process.action == "warnOnly")
        .cloned()
        .collect::<Vec<_>>();
    let is_soft_environment_review =
        |finding: &EvaluationFinding| finding.metadata.rule_id == "monitor.multiple_displays";
    let has_non_process_blocking_finding = report
        .evaluation
        .findings
        .iter()
        .any(|finding| finding.severity == "block" && finding.metadata.category != "process");
    let has_non_process_review_finding = !policy.allow_continue_on_review
        && report
            .evaluation
            .findings
            .iter()
            .any(|finding| {
                finding.metadata.category != "process"
                    && !is_soft_environment_review(finding)
                    && (finding.severity == "review" || finding.severity == "warn")
            });
    let has_process_blocker =
        !hard_blocked_processes.is_empty() || !terminate_required_processes.is_empty();
    let can_enter_exam = !has_process_blocker
        && !has_non_process_blocking_finding
        && !has_non_process_review_finding;
    let has_elevated_risk = !continue_with_audit_processes.is_empty()
        || !isolate_and_protect_processes.is_empty()
        || !warnings.is_empty();
    let decision_status = if !can_enter_exam {
        "block"
    } else if has_elevated_risk || report.evaluation.status != "ready" {
        "review"
    } else {
        "ready"
    };
    let primary_non_process_finding = report
        .evaluation
        .findings
        .iter()
        .find(|finding| finding.metadata.category != "process");

    let primary_reason_code = if !hard_blocked_processes.is_empty() {
        "PROCESS_HARD_BLOCKED".to_string()
    } else if !terminate_required_processes.is_empty() {
        "PROCESS_TERMINATION_REQUIRED".to_string()
    } else if has_non_process_blocking_finding || has_non_process_review_finding {
        report
            .evaluation
            .findings
            .iter()
            .find(|finding| {
                finding.severity == "block" && finding.metadata.category != "process"
            })
            .map(|finding| finding.metadata.rule_id.clone())
            .unwrap_or_else(|| "PREFLIGHT_ENVIRONMENT_BLOCK".to_string())
    } else if let Some(finding) = primary_non_process_finding {
        finding.metadata.rule_id.clone()
    } else if has_elevated_risk {
        "PROCESS_ALLOWED_UNDER_ISOLATION".to_string()
    } else if report.evaluation.status == "ready" {
        "PREFLIGHT_READY".to_string()
    } else {
        report
            .evaluation
            .findings
            .first()
            .map(|finding| finding.metadata.rule_id.clone())
            .unwrap_or_else(|| "PREFLIGHT_WARNING_REVIEW".to_string())
    };

    let primary_reason = if !hard_blocked_processes.is_empty() {
        "Exam entry is blocked by a signed hardBlock process rule.".to_string()
    } else if !terminate_required_processes.is_empty() {
        "Exam entry requires policy-authorized process termination before startup.".to_string()
    } else if has_non_process_blocking_finding || has_non_process_review_finding {
        "Exam entry is blocked by a non-process environment protection rule.".to_string()
    } else if primary_non_process_finding.is_some() {
        "A non-process environment warning was detected. The exam may continue, but the session will remain under review."
            .to_string()
    } else if has_elevated_risk {
        "Remote-control or capture software is present. The exam may continue under monitored isolation and best-effort capture protection."
            .to_string()
    } else if report.evaluation.status == "ready" {
        "System check passed. The exam room can be opened.".to_string()
    } else {
        "Warnings were detected and will be recorded while the protected session continues."
            .to_string()
    };

    let reason_codes = collect_reason_codes(&report.evaluation.findings);
    let recommendations = if report.evaluation.secondary_recommendations.is_empty() {
        vec![primary_reason.clone()]
    } else {
        report.evaluation.secondary_recommendations.clone()
    };

    PreflightDecision {
        status: decision_status.to_string(),
        can_enter_exam,
        allow_review_continue: policy.allow_continue_on_review,
        primary_reason,
        primary_reason_code,
        reason_codes,
        policy_version: policy.policy_version.clone(),
        recommendations,
        hard_blocked_processes,
        terminate_required_processes,
        continue_with_audit_processes,
        isolate_and_protect_processes,
        warnings,
        runtime_risk_level: if has_elevated_risk {
            "elevated".to_string()
        } else {
            "normal".to_string()
        },
    }
}

fn build_preflight_log_lines(
    report: &PrecheckReport,
    decision: &PreflightDecision,
) -> Vec<PreflightLogLine> {
    let mut timestamp = report.collected_at.saturating_sub(12_000);
    let mut lines = Vec::new();

    push_log_line(
        &mut lines,
        &mut timestamp,
        "info",
        "PREFLIGHT_START",
        "Starting desktop preflight check.",
    );
    push_log_line(
        &mut lines,
        &mut timestamp,
        "info",
        "SYSTEM_INFO_COLLECTED",
        format!(
            "System detected: {} {}",
            report.snapshot.system_info.os_name, report.snapshot.system_info.os_version
        ),
    );
    push_log_line(
        &mut lines,
        &mut timestamp,
        if report.snapshot.summary.monitor_count > 1 {
            "warn"
        } else {
            "success"
        },
        "DISPLAY_SUMMARY",
        format!(
            "Display check: {} monitor(s) active.",
            report.snapshot.summary.monitor_count
        ),
    );
    push_log_line(
        &mut lines,
        &mut timestamp,
        "info",
        "PROCESS_SUMMARY",
        format!(
            "Process scan: {} running process(es), {} browser(s), {} remote app(s), {} capture app(s).",
            report.snapshot.summary.total_process_count,
            report.snapshot.summary.browser_app_count,
            report.snapshot.summary.remote_app_count,
            report.snapshot.summary.screen_capture_app_count
        ),
    );

    for finding in &report.evaluation.findings {
        let level = match finding.severity.as_str() {
            "block" => "block",
            "review" | "warn" => "warn",
            _ => "info",
        };

        push_log_line(
            &mut lines,
            &mut timestamp,
            level,
            finding.metadata.rule_id.to_uppercase(),
            format!(
                "{} | risk {} | confidence {}%",
                finding.summary,
                finding.risk_points,
                (finding.confidence * 100.0).round()
            ),
        );
    }

    for recommendation in &decision.recommendations {
        push_log_line(
            &mut lines,
            &mut timestamp,
            if decision.status == "block" {
                "block"
            } else if decision.status == "review" {
                "warn"
            } else {
                "success"
            },
            "ACTION_REQUIRED",
            recommendation.clone(),
        );
    }

    push_log_line(
        &mut lines,
        &mut timestamp,
        if report.evaluation.status == "ready" {
            "success"
        } else {
            "warn"
        },
        decision.primary_reason_code.to_uppercase(),
        format!(
            "Final gate: {} | sourceEvaluation={} | canEnterExam={} | risk {}/100 | policy {}",
            decision.status.to_uppercase(),
            report.evaluation.status.to_uppercase(),
            decision.can_enter_exam,
            report.evaluation.total_risk_score,
            decision.policy_version
        ),
    );

    lines
}

fn push_log_line(
    lines: &mut Vec<PreflightLogLine>,
    timestamp: &mut u64,
    level: &str,
    code: impl Into<String>,
    message: impl Into<String>,
) {
    lines.push(PreflightLogLine {
        timestamp: *timestamp,
        level: level.to_string(),
        code: code.into(),
        message: message.into(),
    });
    *timestamp = timestamp.saturating_add(1_000);
}

fn collect_reason_codes(findings: &[EvaluationFinding]) -> Vec<String> {
    let mut unique_codes = BTreeSet::new();
    for finding in findings {
        unique_codes.insert(finding.metadata.rule_id.clone());
    }

    unique_codes.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::{build_preflight_result, evaluate_precheck_snapshot};
    use crate::models::{
        DetectionSignal, DisplayInfo, MonitorInfo, PrecheckSnapshot, PrecheckSummary, ProcessCategories, ProcessInfo,
        SystemInfo,
    };

    fn base_system_info() -> SystemInfo {
        SystemInfo {
            os_name: "Windows".to_string(),
            os_version: "11".to_string(),
            kernel_version: "10.0.26100".to_string(),
            host_name: "test-host".to_string(),
            architecture: "x86_64".to_string(),
            cpu_count: 12,
            total_memory_mb: 16_384,
            available_memory_mb: 8_192,
            uptime_seconds: 36_000,
            user_name: "student".to_string(),
            system_manufacturer: Some("Test".to_string()),
            system_product_name: Some("Physical Device".to_string()),
        }
    }

    fn base_categories() -> ProcessCategories {
        ProcessCategories {
            browser: Vec::new(),
            communication: Vec::new(),
            policy_blocked: Vec::new(),
            remote_desktop: Vec::new(),
            screen_capture: Vec::new(),
            virtual_machine: Vec::new(),
            debug_tools: Vec::new(),
        }
    }

    fn build_snapshot(
        monitor_count: usize,
        remote_processes: Vec<ProcessInfo>,
        vm_signals: Vec<DetectionSignal>,
    ) -> PrecheckSnapshot {
        PrecheckSnapshot {
            collected_at: 1_782_600_500_000,
            summary: PrecheckSummary {
                total_process_count: remote_processes.len(),
                monitor_count,
                browser_app_count: 0,
                remote_app_count: remote_processes.len(),
                screen_capture_app_count: 0,
                vm_signal_count: vm_signals.len(),
            },
            system_info: base_system_info(),
            display_info: DisplayInfo {
                monitor_count,
                monitors: (0..monitor_count)
                    .map(|index| MonitorInfo {
                        device_name: format!("DISPLAY{}", index + 1),
                        width: 1920,
                        height: 1080,
                        offset_x: (index as i32) * 1920,
                        offset_y: 0,
                        is_primary: index == 0,
                    })
                    .collect(),
            },
            process_list: remote_processes.clone(),
            process_categories: ProcessCategories {
                remote_desktop: remote_processes,
                ..base_categories()
            },
            vm_signals,
            remote_signals: Vec::new(),
            screen_capture_signals: Vec::new(),
        }
    }

    #[test]
    fn ready_snapshot_stays_ready_without_findings() {
        let snapshot = build_snapshot(1, Vec::new(), Vec::new());
        let evaluation = evaluate_precheck_snapshot(&snapshot);

        assert_eq!(evaluation.status, "ready");
        assert_eq!(evaluation.total_risk_score, 0);
        assert!(evaluation.findings.is_empty());
    }

    #[test]
    fn multiple_displays_stay_reviewable_without_blocking_exam_entry() {
        let snapshot = build_snapshot(
            3,
            vec![ProcessInfo {
                pid: 1234,
                name: "AnyDesk.exe".to_string(),
                executable_path: Some("C:\\AnyDesk.exe".to_string()),
                creation_time_ms: Some(1_000),
                memory_mb: 32,
                categories: vec!["remote_desktop".to_string()],
            }],
            Vec::new(),
        );

        let result = build_preflight_result(snapshot);

        assert_eq!(result.report.evaluation.status, "review");
        assert_eq!(result.report.evaluation.total_risk_score, 55);
        assert_eq!(result.decision.status, "review");
        assert!(result.decision.can_enter_exam);
        assert_eq!(result.decision.primary_reason_code, "monitor.multiple_displays");
        assert!(result
            .log_lines
            .iter()
            .any(|line| line.code == "PROCESS.REMOTE" || line.code == "PROCESS.REMOTE.1234"));
    }

    #[test]
    fn remote_process_alone_continues_under_isolation() {
        let snapshot = build_snapshot(
            1,
            vec![ProcessInfo {
                pid: 1234,
                name: "AnyDesk.exe".to_string(),
                executable_path: Some("C:\\AnyDesk.exe".to_string()),
                creation_time_ms: Some(1_000),
                memory_mb: 32,
                categories: vec!["remoteDesktop".to_string()],
            }],
            Vec::new(),
        );

        let result = build_preflight_result(snapshot);

        assert_eq!(result.decision.status, "review");
        assert!(result.decision.can_enter_exam);
        assert_eq!(result.decision.runtime_risk_level, "elevated");
        assert_eq!(result.decision.isolate_and_protect_processes.len(), 1);
        assert!(result.decision.hard_blocked_processes.is_empty());
    }

    #[test]
    fn debugger_process_remains_fail_closed() {
        let mut snapshot = build_snapshot(1, Vec::new(), Vec::new());
        let debugger = ProcessInfo {
            pid: 4321,
            name: "windbg.exe".to_string(),
            executable_path: Some("C:\\windbg.exe".to_string()),
            creation_time_ms: Some(2_000),
            memory_mb: 40,
            categories: vec!["debugTools".to_string()],
        };
        snapshot.process_list.push(debugger.clone());
        snapshot.process_categories.debug_tools.push(debugger);
        snapshot.summary.total_process_count = 1;

        let result = build_preflight_result(snapshot);

        assert_eq!(result.decision.status, "block");
        assert!(!result.decision.can_enter_exam);
        assert_eq!(result.decision.hard_blocked_processes.len(), 1);
    }
}
