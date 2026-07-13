//! F-017 — report-only process heuristics beyond the filename blacklist.
//!
//! The existing policy already matches by name + `OriginalFilename` + `CompanyName`
//! (rename-resistant). This layer adds ADVISORY heuristics for processes that slip
//! past the blacklist:
//!   1. name / `OriginalFilename` MISMATCH — a classic "renamed to evade" tell.
//!   2. UNSIGNED executable with no publisher running from a VOLATILE (temp /
//!      user-writable) location — a common trait of dropped cheating tools.
//!
//! These are REPORT-ONLY signals: this module never terminates a process, so it
//! cannot false-kill an allowed app. It is gated by `EDULEARN_PROCESS_HEURISTICS`
//! (`off` to silence). The pure decision halves are unit-tested (a test matrix).

use crate::models::{DetectionSignal, ProcessInfo};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProcessHeuristicInput {
    pub name: String,
    pub original_filename: Option<String>,
    pub company: Option<String>,
    pub exe_path: Option<String>,
    /// Authenticode signature validity, when known.
    pub is_signed: Option<bool>,
}

fn normalize(name: &str) -> String {
    name.trim()
        .to_ascii_lowercase()
        .trim_end_matches(".exe")
        .to_string()
}

/// True when the running name and the embedded `OriginalFilename` disagree — a
/// classic "renamed to evade the blacklist" tell. Both must be present.
pub fn is_rename_mismatch(name: &str, original_filename: Option<&str>) -> bool {
    match original_filename {
        Some(original) if !original.trim().is_empty() => normalize(name) != normalize(original),
        _ => false,
    }
}

pub fn rename_mismatch_signal(
    name: &str,
    original_filename: Option<&str>,
) -> Option<DetectionSignal> {
    is_rename_mismatch(name, original_filename).then(|| DetectionSignal {
        id: "process_heuristics.rename_mismatch".to_string(),
        label: "Renamed executable".to_string(),
        detail: format!(
            "Process '{name}' does not match its embedded original filename — possible rename to evade detection."
        ),
        severity: "warning".to_string(),
        source: "process_heuristics".to_string(),
    })
}

const VOLATILE_MARKERS: [&str; 5] = [
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\temp\\",
    "\\downloads\\",
    "/tmp/",
];

/// True when an executable has NO publisher AND is UNSIGNED AND runs from a
/// volatile / user-writable location — all three, to keep false positives low.
pub fn is_volatile_unsigned(
    company: Option<&str>,
    exe_path: Option<&str>,
    is_signed: Option<bool>,
) -> bool {
    let no_company = company.map(|c| c.trim().is_empty()).unwrap_or(true);
    let unsigned = matches!(is_signed, Some(false));
    let volatile = exe_path
        .map(|path| {
            let lower = path.to_ascii_lowercase();
            VOLATILE_MARKERS.iter().any(|marker| lower.contains(marker))
        })
        .unwrap_or(false);
    no_company && unsigned && volatile
}

pub fn volatile_unsigned_signal(
    company: Option<&str>,
    exe_path: Option<&str>,
    is_signed: Option<bool>,
) -> Option<DetectionSignal> {
    is_volatile_unsigned(company, exe_path, is_signed).then(|| DetectionSignal {
        id: "process_heuristics.volatile_unsigned".to_string(),
        label: "Unsigned executable in volatile location".to_string(),
        detail: "An unsigned executable with no publisher is running from a temporary/user-writable folder."
            .to_string(),
        severity: "warning".to_string(),
        source: "process_heuristics".to_string(),
    })
}

/// Report-only heuristics on/off (default on). `EDULEARN_PROCESS_HEURISTICS=off`
/// silences them. This NEVER affects termination.
pub fn heuristics_enabled() -> bool {
    !matches!(
        std::env::var("EDULEARN_PROCESS_HEURISTICS").ok().as_deref(),
        Some("off")
    )
}

/// Aggregate the report-only heuristic signals for one process. Empty when
/// disabled. This function does not — and must never — terminate anything.
pub fn heuristic_signals(input: &ProcessHeuristicInput) -> Vec<DetectionSignal> {
    if !heuristics_enabled() {
        return Vec::new();
    }
    let mut signals = Vec::new();
    if let Some(s) = rename_mismatch_signal(&input.name, input.original_filename.as_deref()) {
        signals.push(s);
    }
    if let Some(s) = volatile_unsigned_signal(
        input.company.as_deref(),
        input.exe_path.as_deref(),
        input.is_signed,
    ) {
        signals.push(s);
    }
    signals
}

/// Adapt a runtime-collected `ProcessInfo` into the heuristic input. Signature
/// validity is not part of the runtime snapshot, so it stays `None` (unknown) —
/// which means the volatile-unsigned rule stays quiet and only the rename tell
/// can fire from the tick. Pure + testable so the proactive tick path is covered
/// without needing the live process collector.
pub fn heuristic_input_from_process(process: &ProcessInfo) -> ProcessHeuristicInput {
    let (original_filename, company) = match &process.identity {
        Some(identity) => (
            identity.original_filename.clone(),
            identity.company_name.clone(),
        ),
        None => (None, None),
    };
    ProcessHeuristicInput {
        name: process.name.clone(),
        original_filename,
        company,
        exe_path: process.executable_path.clone(),
        is_signed: None,
    }
}

/// P47-04: run the report-only heuristics across a batch of runtime-collected
/// processes. Used by the runtime monitor tick so heuristics fire proactively
/// (as pushed runtime events) instead of only on a client `scan_process_heuristics`.
pub fn heuristic_signals_for_processes(processes: &[ProcessInfo]) -> Vec<DetectionSignal> {
    if !heuristics_enabled() {
        return Vec::new();
    }
    processes
        .iter()
        .flat_map(|process| heuristic_signals(&heuristic_input_from_process(process)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ExecutableIdentity;

    fn process(name: &str, original: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            pid: 1,
            name: name.to_string(),
            executable_path: None,
            creation_time_ms: None,
            memory_mb: 0,
            categories: Vec::new(),
            identity: original.map(|o| ExecutableIdentity {
                original_filename: Some(o.to_string()),
                company_name: None,
            }),
        }
    }

    #[test]
    fn proactive_batch_flags_only_renamed_process() {
        // P47-04: a process renamed away from its embedded OriginalFilename is the
        // one tell that survives the runtime snapshot (no signature data), so the
        // proactive batch must flag exactly it and leave the honest process alone.
        let processes = vec![
            process("chrome.exe", Some("chrome.exe")),
            process("svchost.exe", Some("teamviewer.exe")),
        ];
        let signals = heuristic_signals_for_processes(&processes);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].id, "process_heuristics.rename_mismatch");
    }

    #[test]
    fn proactive_batch_silent_when_disabled() {
        std::env::set_var("EDULEARN_PROCESS_HEURISTICS", "off");
        let processes = vec![process("svchost.exe", Some("teamviewer.exe"))];
        let signals = heuristic_signals_for_processes(&processes);
        std::env::remove_var("EDULEARN_PROCESS_HEURISTICS");
        assert!(signals.is_empty());
    }

    fn allowed_browser() -> ProcessHeuristicInput {
        ProcessHeuristicInput {
            name: "chrome.exe".to_string(),
            original_filename: Some("chrome.exe".to_string()),
            company: Some("Google LLC".to_string()),
            exe_path: Some("C:\\Program Files\\Google\\Chrome\\chrome.exe".to_string()),
            is_signed: Some(true),
        }
    }

    #[test]
    fn allowed_app_produces_no_signals() {
        // Report-only heuristics must not fire on a normal signed app in Program Files.
        assert!(heuristic_signals(&allowed_browser()).is_empty());
    }

    #[test]
    fn rename_mismatch_detected_but_not_on_matching_names() {
        assert!(!is_rename_mismatch("anydesk.exe", Some("AnyDesk.exe"))); // case/ext only
        assert!(!is_rename_mismatch("svchost.exe", None)); // no original -> no claim
        assert!(is_rename_mismatch("svchost.exe", Some("AnyDesk.exe"))); // renamed!
        let s = rename_mismatch_signal("svchost.exe", Some("AnyDesk.exe")).unwrap();
        assert_eq!(s.id, "process_heuristics.rename_mismatch");
        assert_eq!(s.severity, "warning"); // advisory, never a kill
    }

    #[test]
    fn volatile_unsigned_requires_all_three_conditions() {
        // no company + unsigned + temp path -> fires
        assert!(is_volatile_unsigned(
            None,
            Some("C:\\Users\\x\\AppData\\Local\\Temp\\dropper.exe"),
            Some(false)
        ));
        // signed -> does not fire
        assert!(!is_volatile_unsigned(
            None,
            Some("C:\\Temp\\x.exe"),
            Some(true)
        ));
        // has company -> does not fire
        assert!(!is_volatile_unsigned(
            Some("Acme"),
            Some("C:\\Temp\\x.exe"),
            Some(false)
        ));
        // not a volatile path -> does not fire (e.g. a legit unsigned dev tool)
        assert!(!is_volatile_unsigned(
            None,
            Some("C:\\Tools\\devcli.exe"),
            Some(false)
        ));
        // unknown signature -> does not fire (avoid false positives)
        assert!(!is_volatile_unsigned(None, Some("C:\\Temp\\x.exe"), None));
    }

    #[test]
    fn heuristic_signals_matrix() {
        // Allowed app -> none. Renamed -> 1. Temp-unsigned-no-company -> 1.
        assert_eq!(heuristic_signals(&allowed_browser()).len(), 0);

        let renamed = ProcessHeuristicInput {
            name: "notepad.exe".to_string(),
            original_filename: Some("teamviewer.exe".to_string()),
            ..Default::default()
        };
        assert_eq!(heuristic_signals(&renamed).len(), 1);

        let dropper = ProcessHeuristicInput {
            name: "helper.exe".to_string(),
            company: None,
            exe_path: Some("C:\\Windows\\Temp\\helper.exe".to_string()),
            is_signed: Some(false),
            ..Default::default()
        };
        assert_eq!(heuristic_signals(&dropper).len(), 1);
    }
}
