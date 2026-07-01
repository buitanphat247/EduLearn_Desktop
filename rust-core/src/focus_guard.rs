#[cfg(target_os = "windows")]
mod windows_impl {
    use crate::guard_liveness::is_thread_guard_healthy;
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
    use std::sync::{mpsc, Arc, Mutex, OnceLock};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use windows::Win32::Foundation::{HMODULE, HWND, LPARAM, WPARAM};
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::Accessibility::{
        SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, GetForegroundWindow, GetMessageW, IsWindow, IsWindowVisible,
        PeekMessageW, PostThreadMessageW, SetForegroundWindow, ShowWindow, TranslateMessage,
        EVENT_SYSTEM_FOREGROUND, MSG, PM_NOREMOVE, SW_RESTORE, WINEVENT_OUTOFCONTEXT,
        WINEVENT_SKIPOWNPROCESS, WM_QUIT,
    };

    #[derive(Debug, Clone)]
    pub struct FocusGuardMutationResult {
        pub applied: bool,
        pub active: bool,
        pub detail: String,
    }

    struct FocusGuardHandle {
        stop_flag: Arc<AtomicBool>,
        thread_id: u32,
        thread: JoinHandle<()>,
        target_window_handle: isize,
    }

    static FOCUS_GUARD_STATE: OnceLock<Mutex<Option<FocusGuardHandle>>> = OnceLock::new();
    static FOCUS_GUARD_ACTIVE: AtomicBool = AtomicBool::new(false);
    static FOCUS_TARGET_WINDOW: AtomicIsize = AtomicIsize::new(0);

    fn focus_guard_state() -> &'static Mutex<Option<FocusGuardHandle>> {
        FOCUS_GUARD_STATE.get_or_init(|| Mutex::new(None))
    }

    fn parse_window_handle_hex(window_handle_hex: &str) -> Option<isize> {
        let normalized = window_handle_hex.trim().trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(normalized, 16).ok().map(|value| value as isize)
    }

    fn is_window_valid(window_handle: HWND) -> bool {
        unsafe { IsWindow(window_handle).as_bool() && IsWindowVisible(window_handle).as_bool() }
    }

    fn should_restore_focus(
        guard_active: bool,
        target_window_handle: isize,
        foreground_window_handle: isize,
        target_is_valid: bool,
    ) -> bool {
        guard_active
            && target_is_valid
            && target_window_handle != 0
            && foreground_window_handle != target_window_handle
    }

    fn restore_target_window_if_needed(foreground_window: HWND) {
        let target_window_handle = FOCUS_TARGET_WINDOW.load(Ordering::SeqCst);
        let target_window = HWND(target_window_handle as *mut core::ffi::c_void);
        let target_is_valid = target_window_handle != 0 && is_window_valid(target_window);

        if should_restore_focus(
            FOCUS_GUARD_ACTIVE.load(Ordering::SeqCst),
            target_window_handle,
            foreground_window.0 as isize,
            target_is_valid,
        ) {
            unsafe {
                let _ = ShowWindow(target_window, SW_RESTORE);
                let _ = SetForegroundWindow(target_window);
            }
        }
    }

    unsafe extern "system" fn foreground_event_callback(
        _hook: HWINEVENTHOOK,
        event: u32,
        window_handle: HWND,
        _object_id: i32,
        _child_id: i32,
        _event_thread_id: u32,
        _event_time_ms: u32,
    ) {
        if event == EVENT_SYSTEM_FOREGROUND {
            restore_target_window_if_needed(window_handle);
        }
    }

    fn spawn_focus_guard_thread(
        stop_flag: Arc<AtomicBool>,
        target_window_handle: isize,
        ready_tx: mpsc::Sender<Result<u32, String>>,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            let mut bootstrap_message = MSG::default();
            unsafe {
                let _ = PeekMessageW(&mut bootstrap_message, None, 0, 0, PM_NOREMOVE);
            }

            let hook = unsafe {
                SetWinEventHook(
                    EVENT_SYSTEM_FOREGROUND,
                    EVENT_SYSTEM_FOREGROUND,
                    HMODULE::default(),
                    Some(foreground_event_callback),
                    0,
                    0,
                    WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
                )
            };

            if hook.0.is_null() {
                let _ = ready_tx.send(Err(
                    "SetWinEventHook(EVENT_SYSTEM_FOREGROUND) returned a null handle.".to_string(),
                ));
                return;
            }

            let thread_id = unsafe { GetCurrentThreadId() };
            FOCUS_TARGET_WINDOW.store(target_window_handle, Ordering::SeqCst);
            FOCUS_GUARD_ACTIVE.store(true, Ordering::SeqCst);
            restore_target_window_if_needed(unsafe { GetForegroundWindow() });
            let _ = ready_tx.send(Ok(thread_id));

            let mut message = MSG::default();
            while !stop_flag.load(Ordering::SeqCst) {
                let result = unsafe { GetMessageW(&mut message, None, 0, 0) };
                if result.0 <= 0 || message.message == WM_QUIT {
                    break;
                }

                unsafe {
                    let _ = TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }

            FOCUS_GUARD_ACTIVE.store(false, Ordering::SeqCst);
            FOCUS_TARGET_WINDOW.store(0, Ordering::SeqCst);
            let _ = unsafe { UnhookWinEvent(hook) };
        })
    }

    fn stop_focus_guard(handle: FocusGuardHandle) {
        handle.stop_flag.store(true, Ordering::SeqCst);
        FOCUS_GUARD_ACTIVE.store(false, Ordering::SeqCst);
        FOCUS_TARGET_WINDOW.store(0, Ordering::SeqCst);
        unsafe {
            let _ = PostThreadMessageW(handle.thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
        }
        let _ = handle.thread.join();
    }

    pub fn activate_focus_guard(window_handle_hex: Option<&str>) -> FocusGuardMutationResult {
        let Some(window_handle_hex) = window_handle_hex else {
            return FocusGuardMutationResult {
                applied: false,
                active: false,
                detail: "Focus guard was skipped because no exam window handle was provided.".to_string(),
            };
        };

        let Some(target_window_handle) = parse_window_handle_hex(window_handle_hex) else {
            return FocusGuardMutationResult {
                applied: false,
                active: false,
                detail: "Focus guard was skipped because the exam window handle could not be parsed.".to_string(),
            };
        };

        let target_window = HWND(target_window_handle as *mut core::ffi::c_void);
        if !is_window_valid(target_window) {
            return FocusGuardMutationResult {
                applied: false,
                active: false,
                detail: "Focus guard was skipped because the exam window handle is not valid anymore.".to_string(),
            };
        }

        let state = focus_guard_state();
        let mut guard = match state.lock() {
            Ok(value) => value,
            Err(_) => {
                return FocusGuardMutationResult {
                    applied: false,
                    active: false,
                    detail: "Focus guard state lock is poisoned.".to_string(),
                }
            }
        };

        if let Some(existing_handle) = guard.as_ref() {
            if existing_handle.target_window_handle == target_window_handle
                && is_thread_guard_healthy(
                    true,
                    FOCUS_GUARD_ACTIVE.load(Ordering::SeqCst),
                    existing_handle.thread.is_finished(),
                )
            {
                return FocusGuardMutationResult {
                    applied: true,
                    active: true,
                    detail: "Native focus guard is already active for the current exam window.".to_string(),
                };
            }
        }

        if let Some(existing_handle) = guard.take() {
            stop_focus_guard(existing_handle);
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = mpsc::channel();
        let thread = spawn_focus_guard_thread(
            Arc::clone(&stop_flag),
            target_window_handle,
            ready_tx,
        );

        match ready_rx.recv_timeout(Duration::from_secs(3)) {
            Ok(Ok(thread_id)) => {
                *guard = Some(FocusGuardHandle {
                    stop_flag,
                    thread_id,
                    thread,
                    target_window_handle,
                });
                FocusGuardMutationResult {
                    applied: true,
                    active: true,
                    detail: "Event-based focus guard is active with EVENT_SYSTEM_FOREGROUND."
                        .to_string(),
                }
            }
            Ok(Err(error)) => {
                stop_flag.store(true, Ordering::SeqCst);
                let _ = thread.join();
                FocusGuardMutationResult {
                    applied: false,
                    active: false,
                    detail: error,
                }
            }
            Err(_) => {
                stop_flag.store(true, Ordering::SeqCst);
                let _ = thread.join();
                FocusGuardMutationResult {
                    applied: false,
                    active: false,
                    detail: "Timed out while waiting for the event-based focus guard to start."
                        .to_string(),
                }
            }
        }
    }

    pub fn deactivate_focus_guard() -> FocusGuardMutationResult {
        let state = focus_guard_state();
        let mut guard = match state.lock() {
            Ok(value) => value,
            Err(_) => {
                return FocusGuardMutationResult {
                    applied: false,
                    active: false,
                    detail: "Focus guard state lock is poisoned during restore.".to_string(),
                }
            }
        };

        if let Some(existing_handle) = guard.take() {
            stop_focus_guard(existing_handle);

            return FocusGuardMutationResult {
                applied: true,
                active: false,
                detail: "Native focus guard was removed.".to_string(),
            };
        }

        FocusGuardMutationResult {
            applied: true,
            active: false,
            detail: "Native focus guard was already inactive.".to_string(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{parse_window_handle_hex, should_restore_focus};

        #[test]
        fn parses_prefixed_window_handle() {
            assert_eq!(parse_window_handle_hex("0x2A"), Some(42));
        }

        #[test]
        fn restores_when_another_window_takes_foreground() {
            assert!(should_restore_focus(true, 42, 99, true));
        }

        #[test]
        fn ignores_target_focus_and_invalid_targets() {
            assert!(!should_restore_focus(true, 42, 42, true));
            assert!(!should_restore_focus(true, 42, 99, false));
            assert!(!should_restore_focus(false, 42, 99, true));
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod windows_impl {
    #[derive(Debug, Clone)]
    pub struct FocusGuardMutationResult {
        pub applied: bool,
        pub active: bool,
        pub detail: String,
    }

    pub fn activate_focus_guard(_window_handle_hex: Option<&str>) -> FocusGuardMutationResult {
        FocusGuardMutationResult {
            applied: false,
            active: false,
            detail: "Native focus guard is only supported on Windows.".to_string(),
        }
    }

    pub fn deactivate_focus_guard() -> FocusGuardMutationResult {
        FocusGuardMutationResult {
            applied: false,
            active: false,
            detail: "Native focus guard is only supported on Windows.".to_string(),
        }
    }
}

pub use windows_impl::{activate_focus_guard, deactivate_focus_guard, FocusGuardMutationResult};
