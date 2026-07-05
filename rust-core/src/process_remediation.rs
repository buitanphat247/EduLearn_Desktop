use crate::models::{
    ProcessInfo, ProcessPolicyMatch, ProcessRemediationAction, ProcessRemediationReport,
};
use crate::policy_model::ExamPolicy;
use crate::process_policy::{evaluate_process_policy, resolve_process_policy};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub const DEFAULT_PROCESS_REMEDIATION_GRACE_PERIOD_MS: u64 = 0;
pub const PREFLIGHT_REMEDIATION_MAX_ATTEMPTS: usize = 3;
pub const PREFLIGHT_REMEDIATION_RETRY_DELAY_MS: u64 = 1_000;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightKillReport {
    pub all_clear: bool,
    pub killed_count: usize,
    pub remaining_count: usize,
    pub killed_names: Vec<String>,
    pub remaining_names: Vec<String>,
    pub retry_count: usize,
    pub attempt_count: usize,
    pub failures: Vec<String>,
    pub actions: Vec<ProcessRemediationAction>,
    pub hard_blocked_processes: Vec<ProcessPolicyMatch>,
    pub terminate_required_processes: Vec<ProcessPolicyMatch>,
    pub continue_with_audit_processes: Vec<ProcessPolicyMatch>,
    pub isolate_and_protect_processes: Vec<ProcessPolicyMatch>,
    pub warnings: Vec<ProcessPolicyMatch>,
    pub runtime_risk_level: String,
}

#[derive(Debug, Default)]
pub struct RuntimeProcessRemediator;

impl RuntimeProcessRemediator {
    pub fn new() -> Self {
        Self
    }

    pub fn observe_policy_and_remediate_using<F>(
        &mut self,
        now_ms: u64,
        processes: &[ProcessInfo],
        policy: &ExamPolicy,
        terminate_process: F,
    ) -> ProcessRemediationReport
    where
        F: FnMut(u32) -> Result<(), String>,
    {
        let policy_matches = evaluate_process_policy(processes, policy);
        self.remediate_policy_matches_with(now_ms, policy_matches, policy, terminate_process)
    }

    fn remediate_policy_matches_with<F>(
        &mut self,
        now_ms: u64,
        policy_matches: Vec<ProcessPolicyMatch>,
        policy: &ExamPolicy,
        mut terminate_process: F,
    ) -> ProcessRemediationReport
    where
        F: FnMut(u32) -> Result<(), String>,
    {
        let mut actions = Vec::new();
        for process in policy_matches {
            if !process.attempt_terminate {
                let (status, detail) = if process.action == "hardBlock" {
                    (
                        "blocked",
                        "A hard-blocked process appeared during the protected session.",
                    )
                } else if process.action == "isolateAndProtect" {
                    (
                        "allowed-under-isolation",
                        "Process remains active under kiosk isolation and best-effort capture protection.",
                    )
                } else {
                    (
                        "allowed-with-audit",
                        "Process remains active under signed continue-and-audit policy.",
                    )
                };
                actions.push(ProcessRemediationAction {
                    pid: process.pid,
                    name: process.name,
                    category: process.category,
                    first_detected_at: now_ms,
                    deadline_at: now_ms,
                    action: process.action,
                    status: status.to_string(),
                    detail: detail.to_string(),
                });
                continue;
            }

            if !policy.instant_kill {
                actions.push(ProcessRemediationAction {
                    pid: process.pid,
                    name: process.name,
                    category: process.category,
                    first_detected_at: now_ms,
                    deadline_at: now_ms,
                    action: process.action,
                    status: "detected".to_string(),
                    detail: "Termination is required by the process rule, but instantKill is disabled."
                        .to_string(),
                });
                continue;
            }

            match terminate_process(process.pid) {
                Ok(()) => actions.push(ProcessRemediationAction {
                    pid: process.pid,
                    name: process.name,
                    category: process.category,
                    first_detected_at: now_ms,
                    deadline_at: now_ms,
                    action: process.action,
                    status: "terminated".to_string(),
                    detail: "Process was terminated by its explicit signed process rule.".to_string(),
                }),
                Err(error) => {
                    let continue_after_failure =
                        process.action == "attemptTerminateThenContinue";
                    actions.push(ProcessRemediationAction {
                        pid: process.pid,
                        name: process.name,
                        category: process.category,
                        first_detected_at: now_ms,
                        deadline_at: now_ms,
                        action: process.action,
                        status: if continue_after_failure {
                            "allowed-after-termination-failure".to_string()
                        } else {
                            "failed".to_string()
                        },
                        detail: format!(
                            "Rule-authorized process termination failed: {error}. {}",
                            if continue_after_failure {
                                "The signed rule permits the exam to continue with audit."
                            } else {
                                "The signed rule requires fail-closed recovery."
                            }
                        ),
                    })
                }
            }
        }
        let terminated_count = actions
            .iter()
            .filter(|action| action.status == "terminated")
            .count();
        let failed_count = actions
            .iter()
            .filter(|action| action.status == "failed")
            .count();
        let pending_termination_count = actions
            .iter()
            .filter(|action| {
                action.status == "blocked"
                    || (action.status == "detected"
                        && action.action == "attemptTerminateThenBlock")
            })
            .count();
        ProcessRemediationReport {
            grace_period_ms: DEFAULT_PROCESS_REMEDIATION_GRACE_PERIOD_MS,
            pending_termination_count,
            terminated_count,
            failed_count,
            actions,
        }
    }

    #[cfg(test)]
    fn observe_and_remediate_with<F>(
        &mut self,
        now_ms: u64,
        remote_processes: &[ProcessInfo],
        screen_capture_processes: &[ProcessInfo],
        mut terminate_process: F,
    ) -> ProcessRemediationReport
    where
        F: FnMut(u32) -> Result<(), String>,
    {
        let suspicious_processes =
            collect_suspicious_processes(remote_processes, screen_capture_processes);
        let mut actions = Vec::new();

        for process in suspicious_processes {
            match terminate_process(process.pid) {
                Ok(()) => actions.push(ProcessRemediationAction {
                    pid: process.pid,
                    name: process.name,
                    category: process.category,
                    first_detected_at: now_ms,
                    deadline_at: now_ms,
                    action: "terminate".to_string(),
                    status: "terminated".to_string(),
                    detail: "Prohibited process was terminated immediately by runtime policy."
                        .to_string(),
                }),
                Err(error) => actions.push(ProcessRemediationAction {
                    pid: process.pid,
                    name: process.name,
                    category: process.category,
                    first_detected_at: now_ms,
                    deadline_at: now_ms,
                    action: "terminate".to_string(),
                    status: "failed".to_string(),
                    detail: format!(
                        "Immediate termination of prohibited process failed: {error}"
                    ),
                }),
            }
        }

        let terminated_count = actions.iter().filter(|action| action.status == "terminated").count();
        let failed_count = actions.iter().filter(|action| action.status == "failed").count();

        ProcessRemediationReport {
            grace_period_ms: DEFAULT_PROCESS_REMEDIATION_GRACE_PERIOD_MS,
            pending_termination_count: 0,
            terminated_count,
            failed_count,
            actions,
        }
    }
}

fn collect_policy_processes(
    processes: &[ProcessInfo],
    policy: &ExamPolicy,
) -> Vec<ProcessInfo> {
    let mut selected = BTreeMap::<u32, ProcessInfo>::new();
    for process in processes {
        if resolve_process_policy(process, policy).is_some() {
            selected.insert(process.pid, process.clone());
        }
    }
    selected.into_values().collect()
}

pub fn preflight_remediate_policy_processes_using<Scan, Terminate>(
    policy: &ExamPolicy,
    mut scan_processes: Scan,
    terminate_process: Terminate,
) -> PreflightKillReport
where
    Scan: FnMut() -> Vec<ProcessInfo>,
    Terminate: FnMut(u32) -> Result<(), String>,
{
    preflight_remediate_policy_processes_with(
        policy,
        PREFLIGHT_REMEDIATION_MAX_ATTEMPTS,
        &mut scan_processes,
        terminate_process,
        || thread_sleep(Duration::from_millis(PREFLIGHT_REMEDIATION_RETRY_DELAY_MS)),
    )
}

fn preflight_remediate_policy_processes_with<Scan, Terminate, Sleep>(
    policy: &ExamPolicy,
    max_attempts: usize,
    scan_processes: &mut Scan,
    mut terminate_process: Terminate,
    mut wait_before_rescan: Sleep,
) -> PreflightKillReport
where
    Scan: FnMut() -> Vec<ProcessInfo>,
    Terminate: FnMut(u32) -> Result<(), String>,
    Sleep: FnMut(),
{
    let mut remaining_processes = collect_policy_processes(&scan_processes(), policy);
    let mut killed_processes = BTreeMap::<u32, String>::new();
    let mut failures = BTreeMap::<u32, String>::new();
    let mut actions = Vec::new();
    let mut attempt_count = 0;

    let mut termination_targets = collect_termination_targets(&remaining_processes, policy);
    while !termination_targets.is_empty() && attempt_count < max_attempts {
        attempt_count += 1;
        for process in &termination_targets {
            let policy_match = resolve_process_policy(process, policy);
            match terminate_process(process.pid) {
                Ok(()) => {
                    killed_processes.insert(process.pid, process.name.clone());
                    failures.remove(&process.pid);
                    if let Some(policy_match) = policy_match {
                        actions.push(ProcessRemediationAction {
                            pid: process.pid,
                            name: process.name.clone(),
                            category: policy_match.category,
                            first_detected_at: 0,
                            deadline_at: 0,
                            action: policy_match.action,
                            status: "terminated".to_string(),
                            detail: "Policy-authorized preflight termination succeeded.".to_string(),
                        });
                    }
                }
                Err(error) => {
                    failures.insert(
                        process.pid,
                        format!("{} (pid {}): {error}", process.name, process.pid),
                    );
                    if let Some(policy_match) = policy_match {
                        actions.push(ProcessRemediationAction {
                            pid: process.pid,
                            name: process.name.clone(),
                            category: policy_match.category,
                            first_detected_at: 0,
                            deadline_at: 0,
                            action: policy_match.action,
                            status: "failed".to_string(),
                            detail: format!(
                                "Policy-authorized preflight termination failed: {error}"
                            ),
                        });
                    }
                }
            }
        }
        wait_before_rescan();
        remaining_processes = collect_policy_processes(&scan_processes(), policy);
        termination_targets = collect_termination_targets(&remaining_processes, policy);
    }

    let remaining_termination_pids = termination_targets
        .iter()
        .map(|process| process.pid)
        .collect::<BTreeSet<_>>();
    failures.retain(|pid, _| remaining_termination_pids.contains(pid));
    for process in &termination_targets {
        failures.entry(process.pid).or_insert_with(|| {
            format!(
                "{} (pid {}) remained active after the termination request.",
                process.name, process.pid
            )
        });
    }

    build_preflight_report(
        policy,
        remaining_processes,
        killed_processes,
        failures,
        actions,
        attempt_count,
    )
}

fn collect_termination_targets(
    processes: &[ProcessInfo],
    policy: &ExamPolicy,
) -> Vec<ProcessInfo> {
    processes
        .iter()
        .filter(|process| {
            resolve_process_policy(process, policy)
                .map(|decision| decision.attempt_terminate)
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

fn build_preflight_report(
    policy: &ExamPolicy,
    remaining_processes: Vec<ProcessInfo>,
    killed_processes: BTreeMap<u32, String>,
    failures: BTreeMap<u32, String>,
    actions: Vec<ProcessRemediationAction>,
    attempt_count: usize,
) -> PreflightKillReport {
    let decisions = evaluate_process_policy(&remaining_processes, policy);
    let hard_blocked_processes = decisions
        .iter()
        .filter(|process| process.action == "hardBlock")
        .cloned()
        .collect::<Vec<_>>();
    let terminate_required_processes = decisions
        .iter()
        .filter(|process| process.action == "attemptTerminateThenBlock")
        .cloned()
        .collect::<Vec<_>>();
    let continue_with_audit_processes = decisions
        .iter()
        .filter(|process| {
            process.action == "continueAndAudit"
                || process.action == "attemptTerminateThenContinue"
        })
        .cloned()
        .collect::<Vec<_>>();
    let isolate_and_protect_processes = decisions
        .iter()
        .filter(|process| process.action == "isolateAndProtect")
        .cloned()
        .collect::<Vec<_>>();
    let warnings = decisions
        .iter()
        .filter(|process| process.action == "warnOnly")
        .cloned()
        .collect::<Vec<_>>();
    let blocking = hard_blocked_processes
        .iter()
        .chain(terminate_required_processes.iter())
        .cloned()
        .collect::<Vec<_>>();
    let runtime_risk_level = if isolate_and_protect_processes.is_empty()
        && continue_with_audit_processes.is_empty()
        && warnings.is_empty()
    {
        "normal"
    } else {
        "elevated"
    };

    PreflightKillReport {
        all_clear: blocking.is_empty(),
        killed_count: killed_processes.len(),
        remaining_count: blocking.len(),
        killed_names: killed_processes.into_values().collect(),
        remaining_names: blocking
            .iter()
            .map(|process| process.name.clone())
            .collect(),
        retry_count: attempt_count.saturating_sub(1),
        attempt_count,
        failures: failures.into_values().collect(),
        actions,
        hard_blocked_processes,
        terminate_required_processes,
        continue_with_audit_processes,
        isolate_and_protect_processes,
        warnings,
        runtime_risk_level: runtime_risk_level.to_string(),
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct SuspiciousProcess {
    pid: u32,
    name: String,
    category: String,
}

#[cfg(test)]
fn collect_suspicious_processes(
    remote_processes: &[ProcessInfo],
    screen_capture_processes: &[ProcessInfo],
) -> Vec<SuspiciousProcess> {
    let mut processes = BTreeMap::<u32, SuspiciousProcess>::new();

    for process in remote_processes {
        processes.insert(process.pid, SuspiciousProcess {
            pid: process.pid,
            name: process.name.clone(),
            category: "remoteDesktop".to_string(),
        });
    }

    for process in screen_capture_processes {
        processes
            .entry(process.pid)
            .and_modify(|existing| {
                existing.category = "remoteDesktop+screenCapture".to_string();
            })
            .or_insert_with(|| SuspiciousProcess {
                pid: process.pid,
                name: process.name.clone(),
                category: "screenCapture".to_string(),
            });
    }

    processes.into_values().collect()
}

#[cfg(test)]
fn preflight_kill_prohibited_processes_with<Scan, Terminate, Sleep>(
    max_attempts: usize,
    mut scan_processes: Scan,
    mut terminate_process: Terminate,
    mut wait_before_rescan: Sleep,
) -> PreflightKillReport
where
    Scan: FnMut() -> (Vec<ProcessInfo>, Vec<ProcessInfo>),
    Terminate: FnMut(u32) -> Result<(), String>,
    Sleep: FnMut(),
{
    let (remote_processes, screen_capture_processes) = scan_processes();
    let mut remaining_processes =
        collect_suspicious_processes(&remote_processes, &screen_capture_processes);
    let mut killed_processes = BTreeMap::<u32, String>::new();
    let mut failures = BTreeMap::<u32, String>::new();
    let mut attempt_count = 0;

    // Each attempt is followed by a fresh OS scan. A successful API call is not
    // treated as proof that the process exited until it disappears from that scan.
    while !remaining_processes.is_empty() && attempt_count < max_attempts {
        attempt_count += 1;

        for process in &remaining_processes {
            match terminate_process(process.pid) {
                Ok(()) => {
                    killed_processes.insert(process.pid, process.name.clone());
                    failures.remove(&process.pid);
                }
                Err(error) => {
                    failures.insert(
                        process.pid,
                        format!("{} (pid {}): {error}", process.name, process.pid),
                    );
                }
            }
        }

        wait_before_rescan();
        let (remote_processes, screen_capture_processes) = scan_processes();
        remaining_processes =
            collect_suspicious_processes(&remote_processes, &screen_capture_processes);
    }

    let remaining_pids = remaining_processes
        .iter()
        .map(|process| process.pid)
        .collect::<BTreeSet<_>>();
    failures.retain(|pid, _error| remaining_pids.contains(pid));
    for process in &remaining_processes {
        failures.entry(process.pid).or_insert_with(|| {
            format!(
                "{} (pid {}) remained active after the termination request.",
                process.name, process.pid
            )
        });
    }

    PreflightKillReport {
        all_clear: remaining_processes.is_empty(),
        killed_count: killed_processes.len(),
        remaining_count: remaining_processes.len(),
        killed_names: killed_processes.into_values().collect(),
        remaining_names: remaining_processes
            .iter()
            .map(|process| process.name.clone())
            .collect(),
        retry_count: attempt_count.saturating_sub(1),
        attempt_count,
        failures: failures.into_values().collect(),
        actions: Vec::new(),
        hard_blocked_processes: Vec::new(),
        terminate_required_processes: Vec::new(),
        continue_with_audit_processes: Vec::new(),
        isolate_and_protect_processes: Vec::new(),
        warnings: Vec::new(),
        runtime_risk_level: if remaining_processes.is_empty() {
            "normal".to_string()
        } else {
            "elevated".to_string()
        },
    }
}

fn thread_sleep(duration: Duration) {
    std::thread::sleep(duration);
}

#[cfg(target_os = "windows")]
fn terminate_process_best_effort(pid: u32) -> Result<(), String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    let process_handle = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) }
        .map_err(|error| format!("OpenProcess(PROCESS_TERMINATE) failed for pid {pid}: {error}"))?;

    let terminate_result = unsafe { TerminateProcess(process_handle, 1) };
    let _ = unsafe { CloseHandle(process_handle) };

    terminate_result.map_err(|error| format!("TerminateProcess failed for pid {pid}: {error}"))
}

pub fn terminate_process_user_mode(pid: u32) -> Result<(), String> {
    terminate_process_best_effort(pid)
}

#[cfg(not(target_os = "windows"))]
fn terminate_process_best_effort(pid: u32) -> Result<(), String> {
    Err(format!("Process termination is only supported on Windows. pid={pid}"))
}

#[cfg(test)]
mod tests {
    use super::{
        preflight_kill_prohibited_processes_with,
        preflight_remediate_policy_processes_with, RuntimeProcessRemediator,
    };
    use crate::models::ProcessInfo;
    use std::cell::{Cell, RefCell};

    fn process(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: name.to_string(),
            executable_path: None,
            creation_time_ms: Some(pid as u64),
            memory_mb: 10,
            categories: vec!["screenCapture".to_string()],
        }
    }

    #[test]
    fn default_policy_terminates_on_first_detection() {
        let mut remediator = RuntimeProcessRemediator::new();
        let killed = RefCell::new(Vec::<u32>::new());

        let report = remediator.observe_and_remediate_with(
            1_000,
            &[],
            &[process(42, "OBS.exe")],
            |pid| {
                killed.borrow_mut().push(pid);
                Ok(())
            },
        );

        assert_eq!(report.pending_termination_count, 0);
        assert_eq!(report.terminated_count, 1);
        assert_eq!(*killed.borrow(), vec![42]);
        assert_eq!(report.actions[0].deadline_at, 1_000);
    }

    #[test]
    fn process_in_multiple_categories_is_terminated_once() {
        let mut remediator = RuntimeProcessRemediator::new();
        let killed = RefCell::new(Vec::<u32>::new());
        let suspicious_process = process(42, "dual-purpose.exe");

        let report = remediator.observe_and_remediate_with(
            1_000,
            &[suspicious_process.clone()],
            &[suspicious_process],
            |pid| {
                killed.borrow_mut().push(pid);
                Ok(())
            },
        );

        assert_eq!(report.terminated_count, 1);
        assert_eq!(*killed.borrow(), vec![42]);
        assert_eq!(report.actions[0].category, "remoteDesktop+screenCapture");
    }

    #[test]
    fn empty_runtime_scan_has_no_remediation_actions() {
        let mut remediator = RuntimeProcessRemediator::new();
        let report = remediator.observe_and_remediate_with(
            2_000,
            &[],
            &[],
            |_pid| panic!("terminate should not be called"),
        );

        assert!(report.actions.is_empty());
        assert_eq!(report.pending_termination_count, 0);
    }

    #[test]
    fn runtime_reports_immediate_termination_failure() {
        let mut remediator = RuntimeProcessRemediator::new();
        let report = remediator.observe_and_remediate_with(
            2_000,
            &[],
            &[process(42, "OBS.exe")],
            |_pid| Err("access denied".to_string()),
        );

        assert_eq!(report.failed_count, 1);
        assert_eq!(report.actions[0].status, "failed");
        assert!(report.actions[0].detail.contains("access denied"));
    }

    #[test]
    fn preflight_is_clear_without_termination_when_no_process_is_prohibited() {
        let report = preflight_kill_prohibited_processes_with(
            3,
            || (Vec::new(), Vec::new()),
            |_pid| panic!("terminate should not be called"),
            || panic!("wait should not be called"),
        );

        assert!(report.all_clear);
        assert_eq!(report.attempt_count, 0);
        assert_eq!(report.killed_count, 0);
    }

    #[test]
    fn preflight_terminates_and_verifies_process_exit() {
        let process_running = Cell::new(true);
        let wait_count = Cell::new(0);
        let report = preflight_kill_prohibited_processes_with(
            3,
            || {
                if process_running.get() {
                    (Vec::new(), vec![process(42, "OBS.exe")])
                } else {
                    (Vec::new(), Vec::new())
                }
            },
            |_pid| {
                process_running.set(false);
                Ok(())
            },
            || wait_count.set(wait_count.get() + 1),
        );

        assert!(report.all_clear);
        assert_eq!(report.attempt_count, 1);
        assert_eq!(report.retry_count, 0);
        assert_eq!(report.killed_names, vec!["OBS.exe"]);
        assert_eq!(wait_count.get(), 1);
    }

    #[test]
    fn preflight_stops_after_bounded_retries_and_reports_remaining_processes() {
        let terminate_count = Cell::new(0);
        let report = preflight_kill_prohibited_processes_with(
            3,
            || (vec![process(99, "AnyDesk.exe")], Vec::new()),
            |_pid| {
                terminate_count.set(terminate_count.get() + 1);
                Err("access denied".to_string())
            },
            || {},
        );

        assert!(!report.all_clear);
        assert_eq!(report.attempt_count, 3);
        assert_eq!(report.retry_count, 2);
        assert_eq!(report.remaining_names, vec!["AnyDesk.exe"]);
        assert_eq!(terminate_count.get(), 3);
        assert_eq!(report.failures.len(), 1);
    }

    #[test]
    fn signed_policy_controls_preflight_process_selection() {
        let mut policy = crate::policy_model::ExamPolicy::strict_builtin();
        policy.remote_processes.clear();
        policy.screen_capture_processes.clear();
        policy.debug_processes.clear();
        policy.virtual_machine_processes.clear();
        policy.blocked_processes.clear();
        policy.process_rules = vec![crate::policy_model::ProcessRule {
            name: "custom.exe".to_string(),
            category: "debug-tools".to_string(),
            action: crate::policy_model::ProcessPolicyAction::AttemptTerminateThenBlock,
            severity: "critical".to_string(),
            allow_exam_start: false,
            attempt_terminate: true,
            audit_required: true,
        }];
        let process_running = Cell::new(true);
        let mut scan = || {
            if process_running.get() {
                vec![process(77, "custom.exe"), process(78, "obs64.exe")]
            } else {
                vec![process(78, "obs64.exe")]
            }
        };

        let report = preflight_remediate_policy_processes_with(
            &policy,
            2,
            &mut scan,
            |pid| {
                assert_eq!(pid, 77);
                process_running.set(false);
                Ok(())
            },
            || {},
        );

        assert!(report.all_clear);
        assert_eq!(report.killed_names, vec!["custom.exe"]);
    }

    #[test]
    fn isolate_and_continue_rules_do_not_terminate_or_block_start() {
        let policy = crate::policy_model::ExamPolicy::strict_builtin();
        let mut scan = || {
            vec![
                process(77, "AnyDesk.exe"),
                process(78, "remoting_host.exe"),
                process(79, "parsecd.exe"),
            ]
        };

        let report = preflight_remediate_policy_processes_with(
            &policy,
            3,
            &mut scan,
            |_pid| panic!("allowed-under-isolation process must not be terminated"),
            || panic!("no termination means no retry wait"),
        );

        assert!(report.all_clear);
        assert_eq!(report.attempt_count, 0);
        assert_eq!(report.isolate_and_protect_processes.len(), 2);
        assert_eq!(report.continue_with_audit_processes.len(), 1);
        assert_eq!(report.runtime_risk_level, "elevated");
    }

    #[test]
    fn hard_block_process_blocks_without_arbitrary_termination() {
        let policy = crate::policy_model::ExamPolicy::strict_builtin();
        let mut scan = || vec![process(81, "windbg.exe")];

        let report = preflight_remediate_policy_processes_with(
            &policy,
            3,
            &mut scan,
            |_pid| panic!("hardBlock without attemptTerminate must not kill"),
            || panic!("no termination means no retry wait"),
        );

        assert!(!report.all_clear);
        assert_eq!(report.hard_blocked_processes.len(), 1);
        assert_eq!(report.remaining_names, vec!["windbg.exe"]);
    }

    #[test]
    fn required_termination_failure_still_blocks_exam() {
        let mut policy = crate::policy_model::ExamPolicy::strict_builtin();
        policy.process_rules.push(crate::policy_model::ProcessRule {
            name: "required-tool.exe".to_string(),
            category: "cheat-tool".to_string(),
            action: crate::policy_model::ProcessPolicyAction::AttemptTerminateThenBlock,
            severity: "critical".to_string(),
            allow_exam_start: false,
            attempt_terminate: true,
            audit_required: true,
        });
        let terminate_count = Cell::new(0);
        let mut scan = || vec![process(82, "required-tool.exe")];

        let report = preflight_remediate_policy_processes_with(
            &policy,
            2,
            &mut scan,
            |_pid| {
                terminate_count.set(terminate_count.get() + 1);
                Err("access denied".to_string())
            },
            || {},
        );

        assert!(!report.all_clear);
        assert_eq!(report.terminate_required_processes.len(), 1);
        assert_eq!(terminate_count.get(), 2);
        assert_eq!(report.actions.len(), 2);
    }

    #[test]
    fn runtime_only_terminates_processes_with_explicit_terminate_action() {
        let mut policy = crate::policy_model::ExamPolicy::strict_builtin();
        policy.process_rules.push(crate::policy_model::ProcessRule {
            name: "terminate-me.exe".to_string(),
            category: "cheat-tool".to_string(),
            action: crate::policy_model::ProcessPolicyAction::AttemptTerminateThenBlock,
            severity: "critical".to_string(),
            allow_exam_start: false,
            attempt_terminate: true,
            audit_required: true,
        });
        let terminated = RefCell::new(Vec::new());
        let mut remediator = RuntimeProcessRemediator::new();

        let report = remediator.observe_policy_and_remediate_using(
            1_000,
            &[process(90, "AnyDesk.exe"), process(91, "terminate-me.exe")],
            &policy,
            |pid| {
                terminated.borrow_mut().push(pid);
                Ok(())
            },
        );

        assert_eq!(*terminated.borrow(), vec![91]);
        assert!(report.actions.iter().any(|action| {
            action.name == "AnyDesk.exe" && action.status == "allowed-under-isolation"
        }));
        assert!(report.actions.iter().any(|action| {
            action.name == "terminate-me.exe" && action.status == "terminated"
        }));
    }
}
