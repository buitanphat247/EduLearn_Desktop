#[derive(Debug, Clone)]
pub struct ClipboardGuardMutationResult {
    pub applied: bool,
    pub detail: String,
}

#[cfg(target_os = "windows")]
fn clear_clipboard_with<Open, Empty, Close>(
    mut open_clipboard: Open,
    mut empty_clipboard: Empty,
    mut close_clipboard: Close,
) -> ClipboardGuardMutationResult
where
    Open: FnMut() -> Result<(), String>,
    Empty: FnMut() -> Result<(), String>,
    Close: FnMut() -> Result<(), String>,
{
    if let Err(error) = open_clipboard() {
        return ClipboardGuardMutationResult {
            applied: false,
            detail: format!("OpenClipboard failed: {error}"),
        };
    }

    let empty_result = empty_clipboard();
    let close_result = close_clipboard();

    match (empty_result, close_result) {
        (Ok(()), Ok(())) => ClipboardGuardMutationResult {
            applied: true,
            detail: "Windows clipboard contents were cleared.".to_string(),
        },
        (Err(error), Ok(())) => ClipboardGuardMutationResult {
            applied: false,
            detail: format!("EmptyClipboard failed: {error}"),
        },
        (Ok(()), Err(error)) => ClipboardGuardMutationResult {
            applied: false,
            detail: format!("Clipboard was emptied but CloseClipboard failed: {error}"),
        },
        (Err(empty_error), Err(close_error)) => ClipboardGuardMutationResult {
            applied: false,
            detail: format!(
                "EmptyClipboard failed: {empty_error}; CloseClipboard also failed: {close_error}"
            ),
        },
    }
}

#[cfg(target_os = "windows")]
pub fn clear_clipboard() -> ClipboardGuardMutationResult {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard,
    };

    clear_clipboard_with(
        || unsafe { OpenClipboard(HWND::default()) }.map_err(|error| error.to_string()),
        || unsafe { EmptyClipboard() }.map_err(|error| error.to_string()),
        || unsafe { CloseClipboard() }.map_err(|error| error.to_string()),
    )
}

#[cfg(target_os = "windows")]
fn clear_clipboard_with_retry<Clear, Wait>(
    max_attempts: usize,
    mut clear: Clear,
    mut wait: Wait,
) -> ClipboardGuardMutationResult
where
    Clear: FnMut() -> ClipboardGuardMutationResult,
    Wait: FnMut(),
{
    let attempts = max_attempts.max(1);
    let mut last_result = clear();
    for _ in 1..attempts {
        if last_result.applied {
            break;
        }
        wait();
        last_result = clear();
    }
    last_result
}

#[cfg(target_os = "windows")]
fn clear_clipboard_retrying() -> ClipboardGuardMutationResult {
    clear_clipboard_with_retry(
        5,
        clear_clipboard,
        || std::thread::sleep(std::time::Duration::from_millis(10)),
    )
}

#[cfg(target_os = "windows")]
mod clipboard_monitor {
    use super::{clear_clipboard_retrying, ClipboardGuardMutationResult};
    use crate::guard_liveness::is_thread_guard_healthy;
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc, Mutex, OnceLock};
    use std::thread::{self, JoinHandle};
    use windows::core::w;
    use windows::Win32::Foundation::{
        HINSTANCE, HWND, LPARAM, LRESULT, WPARAM,
    };
    use windows::Win32::System::DataExchange::{
        AddClipboardFormatListener, CountClipboardFormats,
        RemoveClipboardFormatListener,
    };
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
        GetMessageW, HWND_MESSAGE, IsWindow, MSG, PostThreadMessageW, RegisterClassW,
        TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLIPBOARDUPDATE,
        WM_QUIT, WNDCLASSW,
    };

    struct ClipboardMonitorHandle {
        stop_flag: Arc<AtomicBool>,
        thread_id: u32,
        window_handle: isize,
        thread: JoinHandle<()>,
    }

    static CLIPBOARD_MONITOR_STATE: OnceLock<
        Mutex<Option<ClipboardMonitorHandle>>,
    > = OnceLock::new();
    static CLIPBOARD_CLEAR_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
    const CLASS_NAME: windows::core::PCWSTR =
        w!("EdulearnClipboardGuardWindow");

    fn clipboard_monitor_state(
    ) -> &'static Mutex<Option<ClipboardMonitorHandle>> {
        CLIPBOARD_MONITOR_STATE.get_or_init(|| Mutex::new(None))
    }

    unsafe extern "system" fn clipboard_window_proc(
        window_handle: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if message == WM_CLIPBOARDUPDATE
            && unsafe { CountClipboardFormats() } > 0
            && !CLIPBOARD_CLEAR_IN_PROGRESS.swap(true, Ordering::SeqCst)
        {
            let _ = clear_clipboard_retrying();
            CLIPBOARD_CLEAR_IN_PROGRESS.store(false, Ordering::SeqCst);
            return LRESULT(0);
        }

        unsafe { DefWindowProcW(window_handle, message, wparam, lparam) }
    }

    fn spawn_clipboard_monitor(
        stop_flag: Arc<AtomicBool>,
        ready_tx: mpsc::Sender<Result<(u32, isize), String>>,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            let module = match unsafe { GetModuleHandleW(None) } {
                Ok(value) => value,
                Err(error) => {
                    let _ = ready_tx.send(Err(format!(
                        "GetModuleHandleW failed for clipboard monitor: {error}"
                    )));
                    return;
                }
            };
            let instance = HINSTANCE(module.0);
            let window_class = WNDCLASSW {
                lpfnWndProc: Some(clipboard_window_proc),
                hInstance: instance,
                lpszClassName: CLASS_NAME,
                ..Default::default()
            };
            let _ = unsafe { RegisterClassW(&window_class) };

            let window = match unsafe {
                CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    CLASS_NAME,
                    w!("Edulearn Clipboard Guard"),
                    WINDOW_STYLE::default(),
                    0,
                    0,
                    0,
                    0,
                    HWND_MESSAGE,
                    None,
                    instance,
                    None,
                )
            } {
                Ok(value) => value,
                Err(error) => {
                    let _ = ready_tx.send(Err(format!(
                        "Failed to create clipboard listener window: {error}"
                    )));
                    return;
                }
            };

            if let Err(error) = unsafe { AddClipboardFormatListener(window) } {
                let _ = unsafe { DestroyWindow(window) };
                let _ = ready_tx.send(Err(format!(
                    "AddClipboardFormatListener failed: {error}"
                )));
                return;
            }

            let thread_id = unsafe { GetCurrentThreadId() };
            let _ = ready_tx.send(Ok((thread_id, window.0 as isize)));

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

            let _ = unsafe { RemoveClipboardFormatListener(window) };
            let _ = unsafe { DestroyWindow(window) };
        })
    }

    fn clipboard_monitor_is_healthy(handle: &ClipboardMonitorHandle) -> bool {
        let window = HWND(handle.window_handle as *mut c_void);
        is_thread_guard_healthy(
            true,
            unsafe { IsWindow(window) }.as_bool(),
            handle.thread.is_finished(),
        )
    }

    fn stop_clipboard_monitor(handle: ClipboardMonitorHandle) {
        handle.stop_flag.store(true, Ordering::SeqCst);
        unsafe {
            let _ = PostThreadMessageW(
                handle.thread_id,
                WM_QUIT,
                WPARAM(0),
                LPARAM(0),
            );
        }
        let _ = handle.thread.join();
    }

    pub fn activate_clipboard_guard() -> ClipboardGuardMutationResult {
        let state = clipboard_monitor_state();
        let mut guard = match state.lock() {
            Ok(value) => value,
            Err(_) => {
                return ClipboardGuardMutationResult {
                    applied: false,
                    detail: "Clipboard monitor state lock is poisoned.".to_string(),
                }
            }
        };

        if let Some(existing_handle) = guard.as_ref() {
            if clipboard_monitor_is_healthy(existing_handle) {
                return ClipboardGuardMutationResult {
                    applied: true,
                    detail: "Event-based clipboard guard is already active.".to_string(),
                };
            }
        }

        if let Some(stale_handle) = guard.take() {
            stop_clipboard_monitor(stale_handle);
        }

        let initial_clear = clear_clipboard_retrying();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = mpsc::channel();
        let thread =
            spawn_clipboard_monitor(Arc::clone(&stop_flag), ready_tx);
        match ready_rx.recv_timeout(std::time::Duration::from_secs(3)) {
            Ok(Ok((thread_id, window_handle))) => {
                *guard = Some(ClipboardMonitorHandle {
                    stop_flag,
                    thread_id,
                    window_handle,
                    thread,
                });
                ClipboardGuardMutationResult {
                    applied: true,
                    detail: format!(
                        "Event-based clipboard guard is active. {}",
                        initial_clear.detail
                    ),
                }
            }
            Ok(Err(error)) => {
                stop_flag.store(true, Ordering::SeqCst);
                let _ = thread.join();
                ClipboardGuardMutationResult {
                    applied: false,
                    detail: error,
                }
            }
            Err(_) => {
                stop_flag.store(true, Ordering::SeqCst);
                let _ = thread.join();
                ClipboardGuardMutationResult {
                    applied: false,
                    detail: "Timed out while starting the clipboard monitor."
                        .to_string(),
                }
            }
        }
    }

    pub fn deactivate_clipboard_guard() -> ClipboardGuardMutationResult {
        let state = clipboard_monitor_state();
        let mut guard = match state.lock() {
            Ok(value) => value,
            Err(_) => {
                return ClipboardGuardMutationResult {
                    applied: false,
                    detail: "Clipboard monitor state lock is poisoned during restore."
                        .to_string(),
                }
            }
        };

        if let Some(handle) = guard.take() {
            stop_clipboard_monitor(handle);
            return ClipboardGuardMutationResult {
                applied: true,
                detail: "Event-based clipboard guard was stopped.".to_string(),
            };
        }

        ClipboardGuardMutationResult {
            applied: true,
            detail: "Event-based clipboard guard was already inactive.".to_string(),
        }
    }

}

#[cfg(target_os = "windows")]
pub use clipboard_monitor::{
    activate_clipboard_guard, deactivate_clipboard_guard,
};

#[cfg(not(target_os = "windows"))]
pub fn activate_clipboard_guard() -> ClipboardGuardMutationResult {
    clear_clipboard()
}

#[cfg(not(target_os = "windows"))]
pub fn deactivate_clipboard_guard() -> ClipboardGuardMutationResult {
    ClipboardGuardMutationResult {
        applied: false,
        detail: "Clipboard monitor restore is only supported on Windows."
            .to_string(),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn clear_clipboard() -> ClipboardGuardMutationResult {
    ClipboardGuardMutationResult {
        applied: false,
        detail: "Native clipboard guard is only supported on Windows.".to_string(),
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::{clear_clipboard_with, clear_clipboard_with_retry};
    use std::cell::Cell;

    #[test]
    fn clears_and_closes_an_open_clipboard() {
        let close_called = Cell::new(false);
        let result = clear_clipboard_with(
            || Ok(()),
            || Ok(()),
            || {
                close_called.set(true);
                Ok(())
            },
        );

        assert!(result.applied);
        assert!(close_called.get());
    }

    #[test]
    fn does_not_empty_or_close_when_clipboard_cannot_be_opened() {
        let empty_called = Cell::new(false);
        let close_called = Cell::new(false);
        let result = clear_clipboard_with(
            || Err("clipboard busy".to_string()),
            || {
                empty_called.set(true);
                Ok(())
            },
            || {
                close_called.set(true);
                Ok(())
            },
        );

        assert!(!result.applied);
        assert!(!empty_called.get());
        assert!(!close_called.get());
    }

    #[test]
    fn always_closes_after_empty_failure() {
        let close_called = Cell::new(false);
        let result = clear_clipboard_with(
            || Ok(()),
            || Err("empty denied".to_string()),
            || {
                close_called.set(true);
                Ok(())
            },
        );

        assert!(!result.applied);
        assert!(close_called.get());
    }

    #[test]
    fn retries_transient_clipboard_contention_with_a_bound() {
        let attempts = Cell::new(0);
        let waits = Cell::new(0);
        let result = clear_clipboard_with_retry(
            5,
            || {
                let current = attempts.get() + 1;
                attempts.set(current);
                if current < 3 {
                    super::ClipboardGuardMutationResult {
                        applied: false,
                        detail: "clipboard busy".to_string(),
                    }
                } else {
                    super::ClipboardGuardMutationResult {
                        applied: true,
                        detail: "cleared".to_string(),
                    }
                }
            },
            || waits.set(waits.get() + 1),
        );

        assert!(result.applied);
        assert_eq!(attempts.get(), 3);
        assert_eq!(waits.get(), 2);
    }
}
