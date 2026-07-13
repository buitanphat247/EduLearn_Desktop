#[derive(Debug, Clone)]
pub struct AccessibilityGuardMutationResult {
    pub applied: bool,
    pub active: bool,
    pub detail: String,
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::AccessibilityGuardMutationResult;
    use serde::{Deserialize, Serialize};
    use std::env;
    use std::ffi::c_void;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::Win32::UI::Accessibility::{
        FILTERKEYS, SKF_CONFIRMHOTKEY, SKF_HOTKEYACTIVE, STICKYKEYS,
        STICKYKEYS_FLAGS, TOGGLEKEYS,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        SystemParametersInfoW, FKF_CONFIRMHOTKEY, FKF_HOTKEYACTIVE,
        SPI_GETFILTERKEYS, SPI_GETSTICKYKEYS, SPI_GETTOGGLEKEYS,
        SPI_SETFILTERKEYS, SPI_SETSTICKYKEYS, SPI_SETTOGGLEKEYS,
        SPIF_SENDCHANGE, SYSTEM_PARAMETERS_INFO_ACTION, TKF_CONFIRMHOTKEY,
        TKF_HOTKEYACTIVE,
    };

    #[derive(Debug, Clone, Copy)]
    struct AccessibilitySnapshot {
        sticky_keys: STICKYKEYS,
        filter_keys: FILTERKEYS,
        toggle_keys: TOGGLEKEYS,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase")]
    struct AccessibilityBackup {
        version: u32,
        owner_pid: u32,
        #[serde(default)]
        owner_process_started_at_ticks: Option<u64>,
        sticky_flags: u32,
        filter_flags: u32,
        filter_wait_ms: u32,
        filter_delay_ms: u32,
        filter_repeat_ms: u32,
        filter_bounce_ms: u32,
        toggle_flags: u32,
    }

    impl AccessibilityBackup {
        fn from_snapshot(snapshot: AccessibilitySnapshot) -> Self {
            Self {
                version: 2,
                owner_pid: std::process::id(),
                owner_process_started_at_ticks:
                    process_started_at_ticks(std::process::id()),
                sticky_flags: snapshot.sticky_keys.dwFlags.0,
                filter_flags: snapshot.filter_keys.dwFlags,
                filter_wait_ms: snapshot.filter_keys.iWaitMSec,
                filter_delay_ms: snapshot.filter_keys.iDelayMSec,
                filter_repeat_ms: snapshot.filter_keys.iRepeatMSec,
                filter_bounce_ms: snapshot.filter_keys.iBounceMSec,
                toggle_flags: snapshot.toggle_keys.dwFlags,
            }
        }

        fn to_snapshot(&self) -> Result<AccessibilitySnapshot, String> {
            if self.version != 1 && self.version != 2 {
                return Err(format!(
                    "Unsupported accessibility backup version {}.",
                    self.version
                ));
            }

            Ok(AccessibilitySnapshot {
                sticky_keys: STICKYKEYS {
                    cbSize: std::mem::size_of::<STICKYKEYS>() as u32,
                    dwFlags: STICKYKEYS_FLAGS(self.sticky_flags),
                },
                filter_keys: FILTERKEYS {
                    cbSize: std::mem::size_of::<FILTERKEYS>() as u32,
                    dwFlags: self.filter_flags,
                    iWaitMSec: self.filter_wait_ms,
                    iDelayMSec: self.filter_delay_ms,
                    iRepeatMSec: self.filter_repeat_ms,
                    iBounceMSec: self.filter_bounce_ms,
                },
                toggle_keys: TOGGLEKEYS {
                    cbSize: std::mem::size_of::<TOGGLEKEYS>() as u32,
                    dwFlags: self.toggle_flags,
                },
            })
        }
    }

    static ACCESSIBILITY_GUARD_STATE: OnceLock<
        Mutex<Option<AccessibilitySnapshot>>,
    > = OnceLock::new();

    fn accessibility_guard_state(
    ) -> &'static Mutex<Option<AccessibilitySnapshot>> {
        ACCESSIBILITY_GUARD_STATE.get_or_init(|| Mutex::new(None))
    }

    fn backup_path() -> PathBuf {
        let base = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        base.join("Edulearn")
            .join("ExamGuard")
            .join("accessibility-backup-v1.json")
    }

    fn persist_backup_at(
        path: &Path,
        snapshot: AccessibilitySnapshot,
    ) -> Result<(), String> {
        if path.exists() {
            return Err(format!(
                "Accessibility backup already exists at {}.",
                path.display()
            ));
        }

        let parent = path
            .parent()
            .ok_or_else(|| "Accessibility backup path has no parent.".to_string())?;
        fs::create_dir_all(parent).map_err(|error| {
            format!("Failed to create accessibility backup directory: {error}")
        })?;
        let temporary_path = path.with_extension("json.tmp");
        let payload = serde_json::to_vec(&AccessibilityBackup::from_snapshot(
            snapshot,
        ))
        .map_err(|error| {
            format!("Failed to serialize accessibility backup: {error}")
        })?;
        fs::write(&temporary_path, payload).map_err(|error| {
            format!("Failed to write accessibility backup: {error}")
        })?;
        fs::rename(&temporary_path, path).map_err(|error| {
            let _ = fs::remove_file(&temporary_path);
            format!("Failed to commit accessibility backup atomically: {error}")
        })
    }

    fn persist_backup(snapshot: AccessibilitySnapshot) -> Result<(), String> {
        persist_backup_at(&backup_path(), snapshot)
    }

    fn remove_backup_at(path: &Path) -> Result<(), String> {
        if !path.exists() {
            return Ok(());
        }
        fs::remove_file(path).map_err(|error| {
            format!(
                "Failed to remove accessibility backup {}: {error}",
                path.display()
            )
        })
    }

    fn remove_backup() -> Result<(), String> {
        remove_backup_at(&backup_path())
    }

    fn process_started_at_ticks(pid: u32) -> Option<u64> {
        let handle = unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
        };
        match handle {
            Ok(handle) => {
                let mut creation_time = FILETIME::default();
                let mut exit_time = FILETIME::default();
                let mut kernel_time = FILETIME::default();
                let mut user_time = FILETIME::default();
                let result = unsafe {
                    GetProcessTimes(
                        handle,
                        &mut creation_time,
                        &mut exit_time,
                        &mut kernel_time,
                        &mut user_time,
                    )
                };
                let _ = unsafe { CloseHandle(handle) };
                result.ok().map(|_| {
                    (u64::from(creation_time.dwHighDateTime) << 32)
                        | u64::from(creation_time.dwLowDateTime)
                })
            }
            Err(_) => None,
        }
    }

    fn same_process_identity(
        owner_pid: u32,
        owner_started_at_ticks: Option<u64>,
        candidate_pid: u32,
        candidate_started_at_ticks: Option<u64>,
    ) -> bool {
        if owner_pid != candidate_pid {
            return false;
        }
        match owner_started_at_ticks {
            Some(expected) => candidate_started_at_ticks == Some(expected),
            None => candidate_started_at_ticks.is_some(),
        }
    }

    fn query_setting<T>(
        action: SYSTEM_PARAMETERS_INFO_ACTION,
        mut setting: T,
    ) -> Result<T, String> {
        unsafe {
            SystemParametersInfoW(
                action,
                std::mem::size_of::<T>() as u32,
                Some((&mut setting as *mut T).cast::<c_void>()),
                Default::default(),
            )
        }
        .map_err(|error| format!("SystemParametersInfoW query failed: {error}"))?;
        Ok(setting)
    }

    fn update_setting<T>(
        action: SYSTEM_PARAMETERS_INFO_ACTION,
        setting: &mut T,
    ) -> Result<(), String> {
        unsafe {
            SystemParametersInfoW(
                action,
                std::mem::size_of::<T>() as u32,
                Some((setting as *mut T).cast::<c_void>()),
                SPIF_SENDCHANGE,
            )
        }
        .map_err(|error| format!("SystemParametersInfoW update failed: {error}"))
    }

    fn disable_accessibility_hotkeys(
        snapshot: AccessibilitySnapshot,
    ) -> AccessibilitySnapshot {
        let mut protected = snapshot;
        protected.sticky_keys.dwFlags = STICKYKEYS_FLAGS(
            protected.sticky_keys.dwFlags.0
                & !(SKF_HOTKEYACTIVE.0 | SKF_CONFIRMHOTKEY.0),
        );
        protected.filter_keys.dwFlags &=
            !(FKF_HOTKEYACTIVE | FKF_CONFIRMHOTKEY);
        protected.toggle_keys.dwFlags &=
            !(TKF_HOTKEYACTIVE | TKF_CONFIRMHOTKEY);
        protected
    }

    fn apply_snapshot(snapshot: AccessibilitySnapshot) -> Result<(), String> {
        let mut sticky_keys = snapshot.sticky_keys;
        let mut filter_keys = snapshot.filter_keys;
        let mut toggle_keys = snapshot.toggle_keys;

        update_setting(SPI_SETSTICKYKEYS, &mut sticky_keys)?;
        if let Err(error) = update_setting(SPI_SETFILTERKEYS, &mut filter_keys) {
            return Err(error);
        }
        update_setting(SPI_SETTOGGLEKEYS, &mut toggle_keys)
    }

    /// Accessibility tools that live outside the SystemParametersInfo hotkey
    /// surface — Magnifier, Narrator and the On-Screen Keyboard — and can each be
    /// used to read/inject content during an exam.
    fn is_blocked_accessibility_tool(name: &str) -> bool {
        matches!(
            name.trim().to_ascii_lowercase().as_str(),
            "magnify.exe" | "narrator.exe" | "osk.exe"
        )
    }

    /// Terminate any running Magnifier / Narrator / On-Screen Keyboard process.
    /// Returns how many were signalled. Best-effort: processes that cannot be
    /// killed (e.g. protected) are simply skipped.
    pub fn terminate_blocked_accessibility_tools() -> usize {
        use sysinfo::{ProcessRefreshKind, System};
        let mut system = System::new();
        system.refresh_processes_specifics(ProcessRefreshKind::new());
        system
            .processes()
            .values()
            .filter(|process| is_blocked_accessibility_tool(process.name()))
            .filter(|process| process.kill())
            .count()
    }

    pub fn activate_accessibility_guard() -> AccessibilityGuardMutationResult {
        let state = accessibility_guard_state();
        let mut guard = match state.lock() {
            Ok(value) => value,
            Err(_) => {
                return AccessibilityGuardMutationResult {
                    applied: false,
                    active: false,
                    detail: "Accessibility guard state lock is poisoned."
                        .to_string(),
                }
            }
        };

        if guard.is_some() {
            return AccessibilityGuardMutationResult {
                applied: true,
                active: true,
                detail: "Accessibility hotkey guard is already active.".to_string(),
            };
        }

        let snapshot = match (
            query_setting(
                SPI_GETSTICKYKEYS,
                STICKYKEYS {
                    cbSize: std::mem::size_of::<STICKYKEYS>() as u32,
                    ..Default::default()
                },
            ),
            query_setting(
                SPI_GETFILTERKEYS,
                FILTERKEYS {
                    cbSize: std::mem::size_of::<FILTERKEYS>() as u32,
                    ..Default::default()
                },
            ),
            query_setting(
                SPI_GETTOGGLEKEYS,
                TOGGLEKEYS {
                    cbSize: std::mem::size_of::<TOGGLEKEYS>() as u32,
                    ..Default::default()
                },
            ),
        ) {
            (Ok(sticky_keys), Ok(filter_keys), Ok(toggle_keys)) => {
                AccessibilitySnapshot {
                    sticky_keys,
                    filter_keys,
                    toggle_keys,
                }
            }
            (sticky, filter, toggle) => {
                return AccessibilityGuardMutationResult {
                    applied: false,
                    active: false,
                    detail: format!(
                        "Could not snapshot accessibility settings: sticky={sticky:?}, filter={filter:?}, toggle={toggle:?}."
                    ),
                }
            }
        };

        if let Err(error) = persist_backup(snapshot) {
            return AccessibilityGuardMutationResult {
                applied: false,
                active: false,
                detail: format!(
                    "Accessibility settings were not changed because crash recovery could not be prepared: {error}"
                ),
            };
        }

        let protected = disable_accessibility_hotkeys(snapshot);
        match apply_snapshot(protected) {
            Ok(()) => {
                *guard = Some(snapshot);
                let terminated = terminate_blocked_accessibility_tools();
                AccessibilityGuardMutationResult {
                    applied: true,
                    active: true,
                    detail: format!(
                        "Sticky/Filter/Toggle Keys activation hotkeys are disabled and {terminated} accessibility tool(s) (Magnifier/Narrator/OSK) were terminated for the protected session."
                    ),
                }
            }
            Err(error) => {
                let restore_result = apply_snapshot(snapshot);
                if restore_result.is_ok() {
                    let _ = remove_backup();
                }
                AccessibilityGuardMutationResult {
                    applied: false,
                    active: false,
                    detail: format!(
                        "Failed to disable accessibility hotkeys; original settings were restored: {error}"
                    ),
                }
            }
        }
    }

    pub fn deactivate_accessibility_guard() -> AccessibilityGuardMutationResult {
        let state = accessibility_guard_state();
        let mut guard = match state.lock() {
            Ok(value) => value,
            Err(_) => {
                return AccessibilityGuardMutationResult {
                    applied: false,
                    active: true,
                    detail: "Accessibility guard state lock is poisoned during restore."
                        .to_string(),
                }
            }
        };

        let Some(snapshot) = guard.as_ref().copied() else {
            return AccessibilityGuardMutationResult {
                applied: true,
                active: false,
                detail: "Accessibility hotkey guard was already inactive."
                    .to_string(),
            };
        };

        match apply_snapshot(snapshot) {
            Ok(()) => {
                guard.take();
                match remove_backup() {
                    Ok(()) => AccessibilityGuardMutationResult {
                        applied: true,
                        active: false,
                        detail: "Original accessibility hotkey settings were restored and the crash-recovery backup was removed.".to_string(),
                    },
                    Err(error) => AccessibilityGuardMutationResult {
                        applied: false,
                        active: false,
                        detail: format!(
                            "Accessibility settings were restored but backup cleanup failed: {error}"
                        ),
                    },
                }
            }
            Err(error) => AccessibilityGuardMutationResult {
                applied: false,
                active: true,
                detail: format!(
                    "Failed to restore original accessibility settings: {error}"
                ),
            },
        }
    }

    pub fn restore_accessibility_after_unclean_shutdown(
    ) -> AccessibilityGuardMutationResult {
        let path = backup_path();
        if !path.exists() {
            return AccessibilityGuardMutationResult {
                applied: true,
                active: false,
                detail: "No stale accessibility backup was found.".to_string(),
            };
        }

        let backup = match fs::read(&path)
            .map_err(|error| error.to_string())
            .and_then(|payload| {
                serde_json::from_slice::<AccessibilityBackup>(&payload)
                    .map_err(|error| error.to_string())
            }) {
            Ok(value) => value,
            Err(error) => {
                return AccessibilityGuardMutationResult {
                    applied: false,
                    active: false,
                    detail: format!(
                        "Could not read stale accessibility backup {}: {error}",
                        path.display()
                    ),
                }
            }
        };

        let owner_started_at_ticks = process_started_at_ticks(backup.owner_pid);
        if same_process_identity(
            backup.owner_pid,
            backup.owner_process_started_at_ticks,
            backup.owner_pid,
            owner_started_at_ticks,
        ) {
            return AccessibilityGuardMutationResult {
                applied: false,
                active: false,
                detail: format!(
                    "Accessibility backup belongs to active process {} and was not restored.",
                    backup.owner_pid
                ),
            };
        }

        let snapshot = match backup.to_snapshot() {
            Ok(value) => value,
            Err(error) => {
                return AccessibilityGuardMutationResult {
                    applied: false,
                    active: false,
                    detail: error,
                }
            }
        };

        match apply_snapshot(snapshot) {
            Ok(()) => match remove_backup() {
                Ok(()) => AccessibilityGuardMutationResult {
                    applied: true,
                    active: false,
                    detail: "Recovered accessibility settings from an unclean previous shutdown.".to_string(),
                },
                Err(error) => AccessibilityGuardMutationResult {
                    applied: false,
                    active: false,
                    detail: format!(
                        "Recovered accessibility settings but could not remove the stale backup: {error}"
                    ),
                },
            },
            Err(error) => AccessibilityGuardMutationResult {
                applied: false,
                active: false,
                detail: format!(
                    "Failed to recover accessibility settings after an unclean shutdown: {error}"
                ),
            },
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            disable_accessibility_hotkeys, is_blocked_accessibility_tool,
            AccessibilityBackup,
            persist_backup_at, remove_backup_at, same_process_identity,
            AccessibilitySnapshot,
            FKF_CONFIRMHOTKEY, FKF_HOTKEYACTIVE, FILTERKEYS,
            SKF_CONFIRMHOTKEY, SKF_HOTKEYACTIVE, STICKYKEYS,
            STICKYKEYS_FLAGS, TKF_CONFIRMHOTKEY, TKF_HOTKEYACTIVE, TOGGLEKEYS,
        };

        #[test]
        fn blocks_magnifier_narrator_and_osk_by_name() {
            assert!(is_blocked_accessibility_tool("magnify.exe"));
            assert!(is_blocked_accessibility_tool("Narrator.EXE"));
            assert!(is_blocked_accessibility_tool("osk.exe"));
            assert!(!is_blocked_accessibility_tool("chrome.exe"));
            assert!(!is_blocked_accessibility_tool("notepad.exe"));
        }

        #[test]
        fn disables_only_accessibility_activation_hotkeys() {
            let snapshot = AccessibilitySnapshot {
                sticky_keys: STICKYKEYS {
                    cbSize: std::mem::size_of::<STICKYKEYS>() as u32,
                    dwFlags: STICKYKEYS_FLAGS(
                        SKF_HOTKEYACTIVE.0 | SKF_CONFIRMHOTKEY.0 | 1,
                    ),
                },
                filter_keys: FILTERKEYS {
                    cbSize: std::mem::size_of::<FILTERKEYS>() as u32,
                    dwFlags: FKF_HOTKEYACTIVE | FKF_CONFIRMHOTKEY | 1,
                    ..Default::default()
                },
                toggle_keys: TOGGLEKEYS {
                    cbSize: std::mem::size_of::<TOGGLEKEYS>() as u32,
                    dwFlags: TKF_HOTKEYACTIVE | TKF_CONFIRMHOTKEY | 1,
                },
            };

            let protected = disable_accessibility_hotkeys(snapshot);

            assert_eq!(protected.sticky_keys.dwFlags.0, 1);
            assert_eq!(protected.filter_keys.dwFlags, 1);
            assert_eq!(protected.toggle_keys.dwFlags, 1);
        }

        #[test]
        fn backup_round_trip_preserves_accessibility_settings() {
            let snapshot = AccessibilitySnapshot {
                sticky_keys: STICKYKEYS {
                    cbSize: std::mem::size_of::<STICKYKEYS>() as u32,
                    dwFlags: STICKYKEYS_FLAGS(123),
                },
                filter_keys: FILTERKEYS {
                    cbSize: std::mem::size_of::<FILTERKEYS>() as u32,
                    dwFlags: 456,
                    iWaitMSec: 1,
                    iDelayMSec: 2,
                    iRepeatMSec: 3,
                    iBounceMSec: 4,
                },
                toggle_keys: TOGGLEKEYS {
                    cbSize: std::mem::size_of::<TOGGLEKEYS>() as u32,
                    dwFlags: 789,
                },
            };

            let restored = AccessibilityBackup::from_snapshot(snapshot)
                .to_snapshot()
                .expect("backup should be supported");

            assert_eq!(restored.sticky_keys.dwFlags.0, 123);
            assert_eq!(restored.filter_keys.dwFlags, 456);
            assert_eq!(restored.filter_keys.iBounceMSec, 4);
            assert_eq!(restored.toggle_keys.dwFlags, 789);
        }

        #[test]
        fn process_identity_rejects_pid_reuse_with_different_creation_time() {
            assert!(same_process_identity(42, Some(1_000), 42, Some(1_000)));
            assert!(!same_process_identity(42, Some(1_000), 42, Some(2_000)));
            assert!(!same_process_identity(42, Some(1_000), 43, Some(1_000)));
            assert!(same_process_identity(42, None, 42, Some(2_000)));
        }

        #[test]
        fn backup_is_written_and_removed_atomically() {
            let test_directory = std::env::temp_dir().join(format!(
                "edulearn-accessibility-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time should be valid")
                    .as_nanos()
            ));
            let path = test_directory.join("backup.json");
            let snapshot = AccessibilitySnapshot {
                sticky_keys: STICKYKEYS {
                    cbSize: std::mem::size_of::<STICKYKEYS>() as u32,
                    dwFlags: STICKYKEYS_FLAGS(123),
                },
                filter_keys: FILTERKEYS {
                    cbSize: std::mem::size_of::<FILTERKEYS>() as u32,
                    dwFlags: 456,
                    ..Default::default()
                },
                toggle_keys: TOGGLEKEYS {
                    cbSize: std::mem::size_of::<TOGGLEKEYS>() as u32,
                    dwFlags: 789,
                },
            };

            persist_backup_at(&path, snapshot)
                .expect("backup should be persisted");
            assert!(path.exists());
            assert!(!path.with_extension("json.tmp").exists());

            remove_backup_at(&path).expect("backup should be removed");
            assert!(!path.exists());
            let _ = std::fs::remove_dir_all(test_directory);
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod windows_impl {
    use super::AccessibilityGuardMutationResult;

    pub fn activate_accessibility_guard() -> AccessibilityGuardMutationResult {
        AccessibilityGuardMutationResult {
            applied: false,
            active: false,
            detail: "Accessibility guard is only supported on Windows.".to_string(),
        }
    }

    pub fn deactivate_accessibility_guard() -> AccessibilityGuardMutationResult {
        AccessibilityGuardMutationResult {
            applied: false,
            active: false,
            detail: "Accessibility guard restore is only supported on Windows."
                .to_string(),
        }
    }

    pub fn restore_accessibility_after_unclean_shutdown(
    ) -> AccessibilityGuardMutationResult {
        AccessibilityGuardMutationResult {
            applied: false,
            active: false,
            detail: "Accessibility crash recovery is only supported on Windows."
                .to_string(),
        }
    }

    pub fn terminate_blocked_accessibility_tools() -> usize {
        0
    }
}

pub use windows_impl::{
    activate_accessibility_guard, deactivate_accessibility_guard,
    restore_accessibility_after_unclean_shutdown, terminate_blocked_accessibility_tools,
};
