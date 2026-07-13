//! F-004 — multi-technique anti-debug + self-integrity for the exam core.
//!
//! User-mode, best-effort (NOT kernel anti-kill). Three INDEPENDENT hard signals
//! plus one report-only heuristic and a self-integrity digest, so defeating one
//! technique does not blind the core:
//!   1. `IsDebuggerPresent`            (PEB BeingDebugged flag)
//!   2. `CheckRemoteDebuggerPresent`   (debug port on our own process)
//!   3. `NtQueryInformationProcess`    (ProcessDebugPort != 0)
//!   4. timing anomaly                 (report-only; advisory, never a hard signal)
//!   + self-integrity digest of the on-disk executable (server compares to the
//!     known-good hash of the signed release — F-001).
//!
//! Every decision half is a pure function so it is unit-tested; the Win32 probes
//! are thin. All signals are ADVISORY telemetry — the server decides (ADR-002).

use crate::models::DetectionSignal;
use sha2::{Digest, Sha256};

/// Report-only timing threshold: a trivial 1k-iteration loop taking longer than
/// this almost certainly means single-stepping / heavy instrumentation.
const TIMING_ANOMALY_MS: u128 = 50;

// --- Technique 1: IsDebuggerPresent ----------------------------------------
#[cfg(target_os = "windows")]
pub fn is_debugger_present() -> bool {
    use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
    // SAFETY: IsDebuggerPresent takes no args and only reads the PEB flag.
    unsafe { IsDebuggerPresent().as_bool() }
}
#[cfg(not(target_os = "windows"))]
pub fn is_debugger_present() -> bool {
    false
}

// --- Technique 2: CheckRemoteDebuggerPresent (own process) -----------------
#[cfg(target_os = "windows")]
pub fn check_remote_debugger_present() -> bool {
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent;
    use windows::Win32::System::Threading::GetCurrentProcess;
    let mut present = BOOL(0);
    // SAFETY: GetCurrentProcess() is a valid pseudo-handle; `present` is a valid
    // out-param. We do not close the pseudo-handle.
    let ok = unsafe { CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut present) };
    ok.is_ok() && present.as_bool()
}
#[cfg(not(target_os = "windows"))]
pub fn check_remote_debugger_present() -> bool {
    false
}

// --- Technique 3: NtQueryInformationProcess(ProcessDebugPort) ---------------
#[cfg(target_os = "windows")]
pub fn debug_port_present() -> bool {
    use windows::Win32::Foundation::{HANDLE, NTSTATUS};
    use windows::Win32::System::Threading::GetCurrentProcess;
    // `NtQueryInformationProcess` is not surfaced by the windows crate at a stable
    // path in this version, so bind it directly from ntdll (documented native API).
    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationProcess(
            process_handle: HANDLE,
            process_information_class: i32,
            process_information: *mut core::ffi::c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> NTSTATUS;
    }
    const PROCESS_DEBUG_PORT: i32 = 7;
    let mut debug_port: isize = 0;
    let mut ret_len: u32 = 0;
    // SAFETY: valid pseudo-handle + a correctly-sized out buffer for a pointer-sized
    // value; ProcessDebugPort writes one ISIZE.
    let status = unsafe {
        NtQueryInformationProcess(
            GetCurrentProcess(),
            PROCESS_DEBUG_PORT,
            (&mut debug_port as *mut isize).cast(),
            core::mem::size_of::<isize>() as u32,
            &mut ret_len,
        )
    };
    // NTSTATUS >= 0 == success (STATUS_SUCCESS is 0). A non-zero debug port means
    // a debugger is attached.
    status.0 >= 0 && debug_port != 0
}
#[cfg(not(target_os = "windows"))]
pub fn debug_port_present() -> bool {
    false
}

// --- Technique 4 (report-only): timing anomaly ------------------------------
fn measure_trivial_loop_ms() -> u128 {
    use std::time::Instant;
    let start = Instant::now();
    let mut acc: u64 = 0;
    for i in 0..1_000u64 {
        acc = acc.wrapping_add(i);
    }
    std::hint::black_box(acc);
    start.elapsed().as_millis()
}

// --- Self-integrity ---------------------------------------------------------
/// SHA-256 (hex) of the running executable on disk, for the server to compare to
/// the known-good hash of the signed release. `None` if the file cannot be read.
pub fn self_integrity_digest() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let bytes = std::fs::read(exe).ok()?;
    let digest = Sha256::digest(&bytes);
    Some(digest.iter().map(|b| format!("{b:02x}")).collect())
}

// --- Pure decision halves (unit-tested) -------------------------------------
fn signal(id: &str, label: &str, detail: &str, severity: &str) -> DetectionSignal {
    DetectionSignal {
        id: id.to_string(),
        label: label.to_string(),
        detail: detail.to_string(),
        severity: severity.to_string(),
        source: "anti_debug".to_string(),
    }
}

/// Pure: turn an `IsDebuggerPresent` observation into a signal (or none).
pub fn debugger_detection_signal(present: bool) -> Option<DetectionSignal> {
    present.then(|| {
        signal(
            "anti_debug.debugger_present",
            "Debugger attached to exam core",
            "A debugger is attached to the exam core process — possible tampering.",
            "critical",
        )
    })
}

pub fn remote_debugger_signal(present: bool) -> Option<DetectionSignal> {
    present.then(|| {
        signal(
            "anti_debug.remote_debugger_present",
            "Remote debugger detected",
            "CheckRemoteDebuggerPresent reports a debug port on the exam core.",
            "critical",
        )
    })
}

pub fn debug_port_signal(present: bool) -> Option<DetectionSignal> {
    present.then(|| {
        signal(
            "anti_debug.debug_port",
            "Process debug port set",
            "NtQueryInformationProcess(ProcessDebugPort) is non-zero — debugger attached.",
            "critical",
        )
    })
}

/// Report-only: advisory, never treated as a hard debugger signal.
pub fn timing_signal(elapsed_ms: u128) -> Option<DetectionSignal> {
    (elapsed_ms > TIMING_ANOMALY_MS).then(|| {
        signal(
            "anti_debug.timing_anomaly",
            "Execution timing anomaly",
            "A trivial loop ran far slower than expected — possible single-stepping (advisory).",
            "warning",
        )
    })
}

/// Aggregate anti-debug + self-integrity telemetry.
pub struct AntiDebugReport {
    /// True if any HARD technique (1–3) fired. The report-only timing heuristic
    /// does NOT set this, to avoid false positives.
    pub any: bool,
    pub signals: Vec<DetectionSignal>,
    pub self_hash: Option<String>,
}

pub fn anti_debug_report() -> AntiDebugReport {
    let mut signals = Vec::new();
    let mut any = false;
    if let Some(s) = debugger_detection_signal(is_debugger_present()) {
        signals.push(s);
        any = true;
    }
    if let Some(s) = remote_debugger_signal(check_remote_debugger_present()) {
        signals.push(s);
        any = true;
    }
    if let Some(s) = debug_port_signal(debug_port_present()) {
        signals.push(s);
        any = true;
    }
    // Report-only heuristic: measured but does not affect `any`.
    if let Some(s) = timing_signal(measure_trivial_loop_ms()) {
        signals.push(s);
    }
    AntiDebugReport {
        any,
        signals,
        self_hash: self_integrity_digest(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_technique_signals_only_when_it_fires() {
        // Three INDEPENDENT hard signals, each with a distinct id.
        assert!(debugger_detection_signal(false).is_none());
        assert!(remote_debugger_signal(false).is_none());
        assert!(debug_port_signal(false).is_none());

        let a = debugger_detection_signal(true).unwrap();
        let b = remote_debugger_signal(true).unwrap();
        let c = debug_port_signal(true).unwrap();
        assert_eq!(a.id, "anti_debug.debugger_present");
        assert_eq!(b.id, "anti_debug.remote_debugger_present");
        assert_eq!(c.id, "anti_debug.debug_port");
        for s in [&a, &b, &c] {
            assert_eq!(s.source, "anti_debug");
            assert_eq!(s.severity, "critical");
        }
        // All three ids are distinct -> independent signals.
        assert_ne!(a.id, b.id);
        assert_ne!(b.id, c.id);
        assert_ne!(a.id, c.id);
    }

    #[test]
    fn timing_signal_is_report_only_warning() {
        assert!(timing_signal(0).is_none());
        assert!(timing_signal(TIMING_ANOMALY_MS).is_none());
        let s = timing_signal(TIMING_ANOMALY_MS + 1).unwrap();
        assert_eq!(s.severity, "warning"); // advisory, not critical
        assert_eq!(s.id, "anti_debug.timing_anomaly");
    }

    #[test]
    fn self_integrity_digest_is_hex_sha256() {
        // The test binary is a real file on disk -> digest is Some 64-hex.
        let d = self_integrity_digest().expect("current_exe readable in tests");
        assert_eq!(d.len(), 64);
        assert!(d.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
