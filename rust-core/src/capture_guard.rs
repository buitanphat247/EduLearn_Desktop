#[cfg(target_os = "windows")]
mod windows_impl {
    use std::sync::{Mutex, OnceLock};

    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        IsWindow, SetWindowDisplayAffinity, WINDOW_DISPLAY_AFFINITY, WDA_EXCLUDEFROMCAPTURE,
        WDA_MONITOR, WDA_NONE,
    };

    #[derive(Debug, Clone)]
    pub struct CaptureGuardMutationResult {
        pub applied: bool,
        pub active: bool,
        pub status: String,
        pub detail: String,
    }

    static CAPTURE_GUARD_STATE: OnceLock<Mutex<Option<isize>>> = OnceLock::new();

    fn capture_guard_state() -> &'static Mutex<Option<isize>> {
        CAPTURE_GUARD_STATE.get_or_init(|| Mutex::new(None))
    }

    pub(super) fn parse_window_handle_hex(
        window_handle_hex: &str,
    ) -> Option<isize> {
        let normalized = window_handle_hex.trim().trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(normalized, 16).ok().map(|value| value as isize)
    }

    fn set_affinity(window_handle: isize, affinity: WINDOW_DISPLAY_AFFINITY) -> Result<(), String> {
        let window = HWND(window_handle as *mut core::ffi::c_void);
        unsafe { SetWindowDisplayAffinity(window, affinity) }
            .map_err(|error| format!("SetWindowDisplayAffinity failed: {error}"))
    }

    fn is_valid_window_handle(window_handle: isize) -> bool {
        if window_handle == 0 {
            return false;
        }
        let window = HWND(window_handle as *mut core::ffi::c_void);
        unsafe { IsWindow(window).as_bool() }
    }

    pub fn activate_capture_guard(window_handle_hex: Option<&str>) -> CaptureGuardMutationResult {
        let Some(window_handle_hex) = window_handle_hex else {
            return CaptureGuardMutationResult {
                applied: false,
                active: false,
                status: "missing-window-handle".to_string(),
                detail: "Capture guard was skipped because no exam window handle was provided.".to_string(),
            };
        };

        let Some(window_handle) = parse_window_handle_hex(window_handle_hex) else {
            return CaptureGuardMutationResult {
                applied: false,
                active: false,
                status: "invalid-window-handle".to_string(),
                detail: "Capture guard was skipped because the exam window handle could not be parsed.".to_string(),
            };
        };
        if !is_valid_window_handle(window_handle) {
            return CaptureGuardMutationResult {
                applied: false,
                active: false,
                status: "window-gone".to_string(),
                detail: "Capture guard was skipped because the exam window handle is no longer a valid HWND.".to_string(),
            };
        }

        let state = capture_guard_state();
        let mut guard = match state.lock() {
            Ok(value) => value,
            Err(_) => {
                return CaptureGuardMutationResult {
                    applied: false,
                    active: false,
                    status: "state-lock-poisoned".to_string(),
                    detail: "Capture guard state lock is poisoned.".to_string(),
                }
            }
        };

        let is_reapply = guard.as_ref() == Some(&window_handle);

        if !is_reapply {
            if let Some(previous_window_handle) = guard.take() {
                let _ = set_affinity(previous_window_handle, WDA_NONE);
            }
        }

        match set_affinity(window_handle, WDA_EXCLUDEFROMCAPTURE) {
            Ok(()) => {
                *guard = Some(window_handle);
                CaptureGuardMutationResult {
                    applied: true,
                    active: true,
                    status: "exclude-from-capture".to_string(),
                    detail: if is_reapply {
                        "Native capture guard self-healed WDA_EXCLUDEFROMCAPTURE on the exam window."
                            .to_string()
                    } else {
                        "Native capture guard is active with WDA_EXCLUDEFROMCAPTURE."
                            .to_string()
                    },
                }
            }
            Err(primary_error) => match set_affinity(window_handle, WDA_MONITOR) {
                Ok(()) => {
                    *guard = Some(window_handle);
                    CaptureGuardMutationResult {
                        applied: true,
                        active: true,
                        status: "monitor-only-fallback".to_string(),
                        detail: format!(
                            "WDA_EXCLUDEFROMCAPTURE failed ({primary_error}); WDA_MONITOR fallback is active."
                        ),
                    }
                }
                Err(fallback_error) => {
                    if guard.as_ref() == Some(&window_handle) {
                        guard.take();
                    }
                    CaptureGuardMutationResult {
                        applied: false,
                        active: false,
                        status: "failed".to_string(),
                        detail: format!(
                            "Native capture guard failed. Primary: {primary_error}. Fallback: {fallback_error}."
                        ),
                    }
                }
            },
        }
    }

    pub fn re_apply_capture_guard(
        window_handle_hex: Option<&str>,
    ) -> CaptureGuardMutationResult {
        activate_capture_guard(window_handle_hex)
    }

    pub fn deactivate_capture_guard() -> CaptureGuardMutationResult {
        let state = capture_guard_state();
        let mut guard = match state.lock() {
            Ok(value) => value,
            Err(_) => {
                return CaptureGuardMutationResult {
                    applied: false,
                    active: false,
                    status: "state-lock-poisoned".to_string(),
                    detail: "Capture guard state lock is poisoned during restore.".to_string(),
                }
            }
        };

        if let Some(window_handle) = guard.take() {
            return match set_affinity(window_handle, WDA_NONE) {
                Ok(()) => CaptureGuardMutationResult {
                    applied: true,
                    active: false,
                    status: "inactive".to_string(),
                    detail: "Native capture guard was removed from the exam window.".to_string(),
                },
                Err(error) => CaptureGuardMutationResult {
                    applied: false,
                    active: false,
                    status: "restore-failed".to_string(),
                    detail: format!("Native capture guard restore failed: {error}"),
                },
            };
        }

        CaptureGuardMutationResult {
            applied: true,
            active: false,
            status: "inactive".to_string(),
            detail: "Native capture guard was already inactive.".to_string(),
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod windows_impl {
    #[derive(Debug, Clone)]
    pub struct CaptureGuardMutationResult {
        pub applied: bool,
        pub active: bool,
        pub status: String,
        pub detail: String,
    }

    pub fn activate_capture_guard(_window_handle_hex: Option<&str>) -> CaptureGuardMutationResult {
        CaptureGuardMutationResult {
            applied: false,
            active: false,
            status: "unsupported-platform".to_string(),
            detail: "Native capture guard is only supported on Windows.".to_string(),
        }
    }

    pub fn deactivate_capture_guard() -> CaptureGuardMutationResult {
        CaptureGuardMutationResult {
            applied: false,
            active: false,
            status: "unsupported-platform".to_string(),
            detail: "Native capture guard restore is only supported on Windows.".to_string(),
        }
    }

    pub fn re_apply_capture_guard(
        _window_handle_hex: Option<&str>,
    ) -> CaptureGuardMutationResult {
        CaptureGuardMutationResult {
            applied: false,
            active: false,
            status: "unsupported-platform".to_string(),
            detail: "Native capture guard self-healing is only supported on Windows."
                .to_string(),
        }
    }
}

pub use windows_impl::{
    activate_capture_guard, deactivate_capture_guard, re_apply_capture_guard,
    CaptureGuardMutationResult,
};

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::windows_impl::parse_window_handle_hex;

    #[test]
    fn parses_prefixed_and_plain_window_handles() {
        assert_eq!(parse_window_handle_hex("0x2A"), Some(42));
        assert_eq!(parse_window_handle_hex("2a"), Some(42));
        assert_eq!(parse_window_handle_hex("invalid"), None);
    }
}
