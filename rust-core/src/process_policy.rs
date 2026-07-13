use crate::models::{ExecutableIdentity, ProcessInfo, ProcessPolicyMatch};
use crate::policy_model::{list_contains, normalize_process_name, ExamPolicy, ProcessPolicyAction};

pub const CATEGORY_BROWSER: &str = "browser";
pub const CATEGORY_COMMUNICATION: &str = "communication";
pub const CATEGORY_POLICY_BLOCKED: &str = "policyBlocked";
pub const CATEGORY_REMOTE_DESKTOP: &str = "remoteDesktop";
pub const CATEGORY_SCREEN_CAPTURE: &str = "screenCapture";
pub const CATEGORY_VIRTUAL_MACHINE: &str = "virtualMachine";
pub const CATEGORY_DEBUG_TOOLS: &str = "debugTools";

#[cfg(test)]
pub fn categorize_process_name(name: &str) -> Vec<String> {
    categorize_process_name_with_policy(name, &ExamPolicy::strict_builtin())
}

#[cfg(test)]
pub fn categorize_process_name_with_policy(name: &str, policy: &ExamPolicy) -> Vec<String> {
    categorize_process_with_identity(name, None, policy)
}

/// Category classification that also considers the executable's version-info
/// identity (e.g. `OriginalFilename`). Matching a renamed `game.exe` whose
/// embedded `OriginalFilename` is `obs64.exe` still yields the screen-capture
/// category, closing the rename-to-dodge-the-blacklist bypass. Falls back to
/// name-only classification when `identity` is `None`.
pub fn categorize_process_with_identity(
    name: &str,
    identity: Option<&ExecutableIdentity>,
    policy: &ExamPolicy,
) -> Vec<String> {
    let candidates = candidate_names(name, identity);
    let mut categories = Vec::new();

    if candidates
        .iter()
        .any(|candidate| policy.is_explicitly_blocked(candidate))
    {
        categories.push(CATEGORY_POLICY_BLOCKED.to_string());
    }
    push_category_if_any(&mut categories, &candidates, &policy.browser_processes, CATEGORY_BROWSER);
    push_category_if_any(
        &mut categories,
        &candidates,
        &policy.communication_processes,
        CATEGORY_COMMUNICATION,
    );
    push_category_if_any(
        &mut categories,
        &candidates,
        &policy.remote_processes,
        CATEGORY_REMOTE_DESKTOP,
    );
    push_category_if_any(
        &mut categories,
        &candidates,
        &policy.screen_capture_processes,
        CATEGORY_SCREEN_CAPTURE,
    );
    push_category_if_any(
        &mut categories,
        &candidates,
        &policy.virtual_machine_processes,
        CATEGORY_VIRTUAL_MACHINE,
    );
    push_category_if_any(&mut categories, &candidates, &policy.debug_processes, CATEGORY_DEBUG_TOOLS);

    match company_kind_of(identity) {
        Some(CompanyKind::Remote) => {
            if !categories.iter().any(|entry| entry == CATEGORY_REMOTE_DESKTOP) {
                categories.push(CATEGORY_REMOTE_DESKTOP.to_string());
            }
        }
        Some(CompanyKind::Capture) => {
            if !categories.iter().any(|entry| entry == CATEGORY_SCREEN_CAPTURE) {
                categories.push(CATEGORY_SCREEN_CAPTURE.to_string());
            }
        }
        None => {}
    }

    categories
}

#[cfg(test)]
pub fn is_process_prohibited(name: &str, policy: &ExamPolicy) -> bool {
    is_process_prohibited_with_identity(name, None, policy)
}

/// Identity-aware variant used by the live process watcher: a renamed prohibited
/// tool is still caught via its `OriginalFilename`.
pub fn is_process_prohibited_with_identity(
    name: &str,
    identity: Option<&ExecutableIdentity>,
    policy: &ExamPolicy,
) -> bool {
    resolve_process_policy_identity(name, identity, policy)
        .map(|decision| decision.action != ProcessPolicyAction::Ignore.as_str())
        .unwrap_or(false)
}

/// Normalized set of names to match a process against: its reported name plus,
/// when available, the `OriginalFilename` from its version resource.
fn candidate_names(name: &str, identity: Option<&ExecutableIdentity>) -> Vec<String> {
    let mut names = Vec::new();
    let primary = normalize_process_name(name);
    if !primary.is_empty() {
        names.push(primary);
    }
    if let Some(identity) = identity {
        if let Some(original) = identity.original_filename.as_deref() {
            let normalized = normalize_process_name(original);
            if !normalized.is_empty() && !names.contains(&normalized) {
                names.push(normalized);
            }
        }
    }
    names
}

/// Classification of a process by its version-info `CompanyName`. This catches a
/// prohibited tool that was renamed AND had its `OriginalFilename` stripped but
/// still carries a recognizable publisher string. Vendor tokens are distinctive
/// enough to avoid false positives on legitimate software.
#[derive(Clone, Copy)]
enum CompanyKind {
    Remote,
    Capture,
}

fn company_kind(company: &str) -> Option<CompanyKind> {
    let company = company.to_ascii_lowercase();
    const REMOTE: [&str; 8] = [
        "teamviewer",
        "anydesk",
        "rustdesk",
        "parsec",
        "ultraviewer",
        "aweray",
        "splashtop",
        "nomachine",
    ];
    const CAPTURE: [&str; 4] = ["obs project", "bandicam", "techsmith", "xsplit"];
    if REMOTE.iter().any(|needle| company.contains(needle)) {
        Some(CompanyKind::Remote)
    } else if CAPTURE.iter().any(|needle| company.contains(needle)) {
        Some(CompanyKind::Capture)
    } else {
        None
    }
}

fn company_kind_of(identity: Option<&ExecutableIdentity>) -> Option<CompanyKind> {
    company_kind(identity?.company_name.as_deref()?)
}

pub fn evaluate_process_policy(
    processes: &[ProcessInfo],
    policy: &ExamPolicy,
) -> Vec<ProcessPolicyMatch> {
    let mut matches = processes
        .iter()
        .filter_map(|process| resolve_process_policy(process, policy))
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| {
        action_priority(&right.action)
            .cmp(&action_priority(&left.action))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.pid.cmp(&right.pid))
    });
    matches
}

pub fn resolve_process_policy(
    process: &ProcessInfo,
    policy: &ExamPolicy,
) -> Option<ProcessPolicyMatch> {
    let decision = resolve_process_policy_identity(&process.name, process.identity.as_ref(), policy)
        // Path fallback: a remote-control / screen-recording tool whose name AND
        // version-resource identity were scrubbed is still caught if it runs from
        // its vendor's install folder (e.g. C:\Program Files\DeskIn\renamed.exe).
        // Skipped for explicitly-allowed processes so a signed exception still wins.
        .or_else(|| {
            if policy.is_explicitly_allowed(&process.name) {
                return None;
            }
            process
                .executable_path
                .as_deref()
                .and_then(resolve_process_policy_by_path)
        })?;
    Some(ProcessPolicyMatch {
        pid: process.pid,
        name: process.name.clone(),
        executable_path: process.executable_path.clone(),
        creation_time_ms: process.creation_time_ms,
        category: decision.category,
        action: decision.action,
        severity: decision.severity,
        allow_exam_start: decision.allow_exam_start,
        attempt_terminate: decision.attempt_terminate,
        audit_required: decision.audit_required,
    })
}

/// Distinctive vendor folder / product tokens for remote-control and screen-
/// recording tools. Kept product-specific (no short/generic words) so matching a
/// full executable path cannot false-positive on ordinary software.
const REMOTE_PATH_TOKENS: &[&str] = &[
    "anydesk",
    "teamviewer",
    "deskin",
    "todesk",
    "rustdesk",
    "ultraviewer",
    "parsec",
    "glidex",
    "getscreen",
    "dwservice",
    "dwagent",
    "iperius",
    "logmein",
    "gotoassist",
    "screenconnect",
    "connectwise",
    "zohoassist",
    "remoteutilities",
    "litemanager",
    "airdroid",
    "spacedesk",
    "splashtop",
    "aeroadmin",
    "supremo",
    "nomachine",
    "radmin",
    "aweray",
    "remotepc",
    "dameware",
    "chromeremotedesktop",
    "moonlight",
    "sunshine",
];
const CAPTURE_PATH_TOKENS: &[&str] = &[
    "obs-studio",
    "obsstudio",
    "bandicam",
    "camtasia",
    "sharex",
    "streamlabs",
    "xsplit",
    "screenrec",
    "flashback",
    "hypercam",
    "activepresenter",
    "screentogif",
    "screenpresso",
    "monosnap",
    "apowerrec",
    "vokoscreen",
];

/// Classify a process purely from its executable path's vendor folder. A remote-
/// control / screen-recording tool that runs from its vendor directory is
/// ISOLATED-AND-PROTECTED (allowed to run — the kiosk fullscreen window + capture
/// protection make the shared/recorded view black — rather than blocked/killed),
/// so entry is never blocked just because such a tool is present.
fn resolve_process_policy_by_path(path: &str) -> Option<ProcessPolicyDecision> {
    let lowered = path.to_ascii_lowercase();
    let is_remote = REMOTE_PATH_TOKENS.iter().any(|token| lowered.contains(token));
    let is_capture = CAPTURE_PATH_TOKENS.iter().any(|token| lowered.contains(token));
    if !is_remote && !is_capture {
        return None;
    }
    let category = match (is_remote, is_capture) {
        (true, true) => "remote-control+screen-capture",
        (true, false) => "remote-control",
        _ => "screen-capture",
    };
    Some(decision(
        category,
        ProcessPolicyAction::IsolateAndProtect,
        "high",
    ))
}

#[derive(Debug, Clone)]
struct ProcessPolicyDecision {
    category: String,
    action: String,
    severity: String,
    allow_exam_start: bool,
    attempt_terminate: bool,
    audit_required: bool,
}

/// Resolve the most severe policy decision across a process's candidate names
/// (reported name + `OriginalFilename`). A renamed prohibited tool is therefore
/// still caught by the identity carried in its version resource.
fn resolve_process_policy_identity(
    name: &str,
    identity: Option<&ExecutableIdentity>,
    policy: &ExamPolicy,
) -> Option<ProcessPolicyDecision> {
    // An explicit admin allow-list entry (in the signed policy) is a deliberate
    // exception for this exact process and wins over every identity-based
    // escalation below (OriginalFilename / CompanyName). Without this, an
    // authorized tool whose publisher/original name resembles a prohibited
    // vendor would still be forced into isolation.
    if policy.is_explicitly_allowed(name) {
        return None;
    }

    let mut best: Option<ProcessPolicyDecision> = None;
    for candidate in candidate_names(name, identity) {
        if let Some(decision) = resolve_process_policy_name(&candidate, policy) {
            let replace = match &best {
                Some(current) => action_priority(&decision.action) > action_priority(&current.action),
                None => true,
            };
            if replace {
                best = Some(decision);
            }
        }
    }

    // Publisher-based catch-all for renamed tools whose CompanyName still betrays
    // a prohibited vendor.
    if let Some(kind) = company_kind_of(identity) {
        let category = match kind {
            CompanyKind::Remote => "remote-control",
            CompanyKind::Capture => "screen-capture",
        };
        let company_decision = decision(category, ProcessPolicyAction::IsolateAndProtect, "high");
        let replace = match &best {
            Some(current) => {
                action_priority(&company_decision.action) > action_priority(&current.action)
            }
            None => true,
        };
        if replace {
            best = Some(company_decision);
        }
    }

    best
}

fn resolve_process_policy_name(
    name: &str,
    policy: &ExamPolicy,
) -> Option<ProcessPolicyDecision> {
    if policy.is_explicitly_blocked(name) {
        // Remote-control / screen-recording tools do NOT block entry, even when
        // listed in the blocklist: they are ISOLATED-AND-PROTECTED — allowed to run
        // while the kiosk fullscreen window + capture protection make anything a
        // remote viewer or recorder sees BLACK. This lets the candidate enter with
        // such tools present instead of being stuck at "close them manually".
        // Everything else in the blocklist (debuggers, misc.) stays HardBlock.
        let is_remote = list_contains(&policy.remote_processes, name);
        let is_capture = list_contains(&policy.screen_capture_processes, name);
        if is_remote || is_capture {
            let category = match (is_remote, is_capture) {
                (true, true) => "remote-control+screen-capture",
                (true, false) => "remote-control",
                _ => "screen-capture",
            };
            return Some(decision(
                category,
                ProcessPolicyAction::IsolateAndProtect,
                "high",
            ));
        }
        return Some(decision(
            CATEGORY_POLICY_BLOCKED,
            ProcessPolicyAction::HardBlock,
            "critical",
        ));
    }

    if let Some(rule) = policy.process_rule_for(name) {
        return Some(ProcessPolicyDecision {
            category: rule.category.clone(),
            action: rule.action.as_str().to_string(),
            severity: rule.severity.clone(),
            allow_exam_start: rule.allow_exam_start,
            attempt_terminate: rule.attempt_terminate,
            audit_required: rule.audit_required,
        });
    }

    if policy.is_explicitly_allowed(name) {
        return None;
    }

    if list_contains(&policy.debug_processes, name) {
        return Some(decision(
            CATEGORY_DEBUG_TOOLS,
            ProcessPolicyAction::HardBlock,
            "critical",
        ));
    }
    if !policy.allow_vm && list_contains(&policy.virtual_machine_processes, name) {
        return Some(decision(
            CATEGORY_VIRTUAL_MACHINE,
            ProcessPolicyAction::HardBlock,
            "high",
        ));
    }

    let is_remote = list_contains(&policy.remote_processes, name);
    let is_capture = list_contains(&policy.screen_capture_processes, name);
    if is_remote || is_capture {
        let category = match (is_remote, is_capture) {
            (true, true) => "remote-control+screen-capture",
            (true, false) => "remote-control",
            (false, true) => "screen-capture",
            (false, false) => unreachable!(),
        };
        // Every detected remote-control / screen-recording tool is ISOLATED-AND-
        // PROTECTED, not blocked/killed: the exam runs in a kiosk fullscreen window
        // with capture protection, so anything a remote viewer or recorder captures
        // shows BLACK. Entry is therefore never blocked just because such a tool is
        // running — the correct model for tools (RDP, KVM, phone camera, unkillable
        // services) that cannot reliably be terminated anyway.
        return Some(decision(
            category,
            ProcessPolicyAction::IsolateAndProtect,
            "high",
        ));
    }

    None
}

fn decision(
    category: &str,
    action: ProcessPolicyAction,
    severity: &str,
) -> ProcessPolicyDecision {
    ProcessPolicyDecision {
        category: category.to_string(),
        action: action.as_str().to_string(),
        severity: severity.to_string(),
        allow_exam_start: !action.blocks_exam_start(),
        attempt_terminate: matches!(
            action,
            ProcessPolicyAction::AttemptTerminateThenBlock
                | ProcessPolicyAction::AttemptTerminateThenContinue
        ),
        audit_required: !matches!(action, ProcessPolicyAction::Ignore),
    }
}

fn action_priority(action: &str) -> u8 {
    match action {
        "hardBlock" => 7,
        "attemptTerminateThenBlock" => 6,
        "attemptTerminateThenContinue" => 5,
        "isolateAndProtect" => 4,
        "continueAndAudit" => 3,
        "warnOnly" => 2,
        "ignore" => 1,
        _ => 0,
    }
}

pub fn contains_vm_vendor(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("vmware")
        || normalized.contains("virtualbox")
        || normalized.contains("virtual box")
        || normalized.contains("hyper-v")
        || normalized.contains("kvm")
        || normalized.contains("qemu")
        || normalized.contains("parallels")
}

fn push_category_if_any(
    categories: &mut Vec<String>,
    candidate_names: &[String],
    prohibited_names: &[String],
    category: &str,
) {
    if candidate_names
        .iter()
        .any(|candidate| list_contains(prohibited_names, candidate))
    {
        categories.push(category.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        categorize_process_name, categorize_process_name_with_policy,
        categorize_process_with_identity, contains_vm_vendor, is_process_prohibited,
        resolve_process_policy, CATEGORY_COMMUNICATION, CATEGORY_REMOTE_DESKTOP,
        CATEGORY_SCREEN_CAPTURE,
    };
    use crate::models::{ExecutableIdentity, ProcessInfo};

    fn identity(original_filename: &str) -> ExecutableIdentity {
        ExecutableIdentity {
            original_filename: Some(original_filename.to_string()),
            company_name: None,
        }
    }

    #[test]
    fn classification_is_case_insensitive_and_supports_multiple_categories() {
        let categories = categorize_process_name("Discord.EXE");

        assert!(categories.iter().any(|entry| entry == CATEGORY_COMMUNICATION));
        assert!(categories.iter().any(|entry| entry == CATEGORY_SCREEN_CAPTURE));
    }

    #[test]
    fn classifier_requires_an_exact_executable_name() {
        assert!(categorize_process_name("myobs.exe").is_empty());
        assert!(categorize_process_name("anydesk.exe.backup").is_empty());
        assert!(categorize_process_name("AnyDesk.exe")
            .iter()
            .any(|entry| entry == CATEGORY_REMOTE_DESKTOP));
    }

    #[test]
    fn renamed_capture_tool_is_caught_via_original_filename() {
        let policy = crate::policy_model::ExamPolicy::strict_builtin();
        // Attacker renamed obs64.exe -> game.exe but the version resource keeps
        // OriginalFilename = obs64.exe.
        let categories =
            categorize_process_with_identity("game.exe", Some(&identity("obs64.exe")), &policy);

        assert!(categories.iter().any(|entry| entry == CATEGORY_SCREEN_CAPTURE));
    }

    #[test]
    fn renamed_remote_tool_is_prohibited_via_identity() {
        let policy = crate::policy_model::ExamPolicy::strict_builtin();
        let process = ProcessInfo {
            pid: 77,
            name: "anydesk.exe.backup".to_string(),
            executable_path: Some("C:\\Temp\\anydesk.exe.backup".to_string()),
            creation_time_ms: Some(1),
            memory_mb: 1,
            categories: Vec::new(),
            identity: Some(identity("AnyDesk.exe")),
        };

        let decision = resolve_process_policy(&process, &policy).unwrap();
        assert_eq!(decision.action, "isolateAndProtect");
        assert!(!decision.attempt_terminate);
        assert!(!is_process_prohibited("anydesk.exe.backup", &policy)); // name-only misses it
        assert!(super::is_process_prohibited_with_identity(
            "anydesk.exe.backup",
            Some(&identity("AnyDesk.exe")),
            &policy
        ));
    }

    #[test]
    fn renamed_stripped_tool_caught_by_company_name() {
        let policy = crate::policy_model::ExamPolicy::strict_builtin();
        // Renamed with no OriginalFilename, but CompanyName still names the vendor.
        let remote = ExecutableIdentity {
            original_filename: None,
            company_name: Some("TeamViewer Germany GmbH".to_string()),
        };
        assert!(categorize_process_with_identity("svc32.exe", Some(&remote), &policy)
            .iter()
            .any(|entry| entry == CATEGORY_REMOTE_DESKTOP));

        let capture = ExecutableIdentity {
            original_filename: None,
            company_name: Some("OBS Project".to_string()),
        };
        assert!(categorize_process_with_identity("helper.exe", Some(&capture), &policy)
            .iter()
            .any(|entry| entry == CATEGORY_SCREEN_CAPTURE));

        // A benign publisher is not flagged.
        let benign = ExecutableIdentity {
            original_filename: None,
            company_name: Some("Microsoft Corporation".to_string()),
        };
        assert!(categorize_process_with_identity("notepad.exe", Some(&benign), &policy).is_empty());
    }

    #[test]
    fn explicit_allow_list_overrides_identity_escalation() {
        let mut policy = crate::policy_model::ExamPolicy::strict_builtin();
        policy.allowed_processes = vec!["supporttool.exe".to_string()];
        // An authorized tool whose publisher looks like a remote vendor must NOT
        // be prohibited once it is explicitly allow-listed.
        let process = ProcessInfo {
            pid: 55,
            name: "supporttool.exe".to_string(),
            executable_path: Some("C:\\Vendor\\supporttool.exe".to_string()),
            creation_time_ms: Some(1),
            memory_mb: 1,
            categories: Vec::new(),
            identity: Some(ExecutableIdentity {
                original_filename: Some("SplashtopStreamer.exe".to_string()),
                company_name: Some("Splashtop Inc.".to_string()),
            }),
        };
        assert!(resolve_process_policy(&process, &policy).is_none());
    }

    #[test]
    fn missing_identity_falls_back_to_name_only() {
        let policy = crate::policy_model::ExamPolicy::strict_builtin();
        // No identity: a renamed executable is NOT caught (documents the fallback).
        assert!(categorize_process_with_identity("game.exe", None, &policy).is_empty());
        // But a genuine name still classifies.
        assert!(categorize_process_with_identity("obs64.exe", None, &policy)
            .iter()
            .any(|entry| entry == CATEGORY_SCREEN_CAPTURE));
    }

    #[test]
    fn detects_known_virtual_machine_vendors() {
        assert!(contains_vm_vendor("VMware, Inc."));
        assert!(contains_vm_vendor("Virtual Box"));
        assert!(!contains_vm_vendor("Dell Inc."));
    }

    #[test]
    fn classifies_added_remote_and_capture_tools() {
        for name in ["ultraviewer.exe", "aweray_remote.exe", "msrdc.exe"] {
            assert!(categorize_process_name(name)
                .iter()
                .any(|entry| entry == CATEGORY_REMOTE_DESKTOP));
        }

        for name in [
            "lightshot.exe",
            "greenshot.exe",
            "flameshot.exe",
            "kazam.exe",
        ] {
            assert!(categorize_process_name(name)
                .iter()
                .any(|entry| entry == CATEGORY_SCREEN_CAPTURE));
        }
    }

    #[test]
    fn signed_policy_can_replace_categories_and_allow_an_exception() {
        let mut policy = crate::policy_model::ExamPolicy::strict_builtin();
        policy.remote_processes = vec!["custom-remote.exe".to_string()];
        policy.allowed_processes = vec!["custom-remote.exe".to_string()];

        assert!(categorize_process_name_with_policy("AnyDesk.exe", &policy).is_empty());
        assert!(categorize_process_name_with_policy("custom-remote.exe", &policy)
            .iter()
            .any(|entry| entry == CATEGORY_REMOTE_DESKTOP));
        assert!(!is_process_prohibited("custom-remote.exe", &policy));
    }

    #[test]
    fn remote_and_capture_defaults_are_allowed_under_isolation() {
        // Remote-control / screen-recording tools do NOT block entry: they are
        // isolated-and-protected (allowed to run; capture protection keeps the
        // remote/recorded view black), not killed or hard-blocked.
        let policy = crate::policy_model::ExamPolicy::strict_builtin();
        for name in ["AnyDesk.exe", "parsecd.exe", "obs64.exe"] {
            let decision = resolve_process_policy(
                &ProcessInfo {
                    pid: 42,
                    name: name.to_string(),
                    executable_path: None,
                    creation_time_ms: Some(1),
                    memory_mb: 1,
                    categories: Vec::new(),
                    identity: None,
                },
                &policy,
            )
            .unwrap();

            assert!(decision.allow_exam_start);
            assert!(!decision.attempt_terminate);
            assert_eq!(decision.action, "isolateAndProtect");
        }
    }

    #[test]
    fn renamed_tool_in_vendor_folder_is_caught_by_path() {
        let policy = crate::policy_model::ExamPolicy::strict_builtin();
        // Name + identity scrubbed, but it runs from the DeskIn install folder.
        let renamed = ProcessInfo {
            pid: 4242,
            name: "svc-helper.exe".to_string(),
            executable_path: Some("C:\\Program Files\\DeskIn\\svc-helper.exe".to_string()),
            creation_time_ms: Some(1),
            memory_mb: 10,
            categories: Vec::new(),
            identity: None,
        };
        let decision = resolve_process_policy(&renamed, &policy).unwrap();
        assert_eq!(decision.action, "isolateAndProtect");
        assert!(!decision.attempt_terminate);
        assert_eq!(decision.category, "remote-control");

        // A benign path is not matched.
        let benign = ProcessInfo {
            executable_path: Some("C:\\Program Files\\MyGame\\game.exe".to_string()),
            ..renamed.clone()
        };
        assert!(resolve_process_policy(&benign, &policy).is_none());

        // An explicit signed allow-list exception still wins over the path match.
        let mut allowed_policy = policy.clone();
        allowed_policy.allowed_processes = vec!["svc-helper.exe".to_string()];
        assert!(resolve_process_policy(&renamed, &allowed_policy).is_none());
    }

    #[test]
    fn debugger_defaults_remain_hard_blocked() {
        let policy = crate::policy_model::ExamPolicy::strict_builtin();
        let decision = resolve_process_policy(
            &ProcessInfo {
                pid: 43,
                name: "windbg.exe".to_string(),
                executable_path: None,
                creation_time_ms: Some(1),
                memory_mb: 1,
                categories: Vec::new(),
                identity: None,
            },
            &policy,
        )
        .unwrap();

        assert!(!decision.allow_exam_start);
        assert_eq!(decision.action, "hardBlock");
    }
}
