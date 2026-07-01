use crate::models::DisplayInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MouseClipBounds {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

fn primary_clip_bounds(display_info: &DisplayInfo) -> Option<MouseClipBounds> {
    display_info
        .monitors
        .iter()
        .find(|monitor| monitor.is_primary)
        .map(|monitor| MouseClipBounds {
            left: monitor.offset_x,
            top: monitor.offset_y,
            right: monitor.offset_x.saturating_add(monitor.width),
            bottom: monitor.offset_y.saturating_add(monitor.height),
        })
}

fn clamp_point_to_bounds(
    x: i32,
    y: i32,
    bounds: MouseClipBounds,
) -> Option<(i32, i32)> {
    if bounds.right <= bounds.left || bounds.bottom <= bounds.top {
        return None;
    }

    let clamped_x = x.clamp(bounds.left, bounds.right - 1);
    let clamped_y = y.clamp(bounds.top, bounds.bottom - 1);
    if clamped_x == x && clamped_y == y {
        None
    } else {
        Some((clamped_x, clamped_y))
    }
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::{
        clamp_point_to_bounds, primary_clip_bounds, DisplayInfo, MouseClipBounds,
    };
    use crate::guard_liveness::is_thread_guard_healthy;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::sync::{mpsc, Arc, Mutex, OnceLock};
    use std::thread::{self, JoinHandle};
    use windows::Win32::Foundation::{
        HINSTANCE, LPARAM, LRESULT, RECT, WPARAM,
    };
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, ClipCursor, DispatchMessageW, GetMessageW,
        MSLLHOOKSTRUCT, PeekMessageW, PostThreadMessageW, SetCursorPos,
        SetWindowsHookExW, TranslateMessage, UnhookWindowsHookEx, HC_ACTION,
        HHOOK, MSG, PM_NOREMOVE, WH_MOUSE_LL, WM_QUIT,
    };

    #[derive(Debug, Clone)]
    pub struct MouseGuardMutationResult {
        pub applied: bool,
        pub active: bool,
        pub detail: String,
    }

    struct MouseGuardHandle {
        stop_flag: Arc<AtomicBool>,
        thread_id: u32,
        thread: JoinHandle<()>,
    }

    static MOUSE_GUARD_STATE: OnceLock<Mutex<Option<MouseGuardHandle>>> =
        OnceLock::new();
    static MOUSE_GUARD_ACTIVE: AtomicBool = AtomicBool::new(false);
    static BOUNDS_LEFT: AtomicI32 = AtomicI32::new(0);
    static BOUNDS_TOP: AtomicI32 = AtomicI32::new(0);
    static BOUNDS_RIGHT: AtomicI32 = AtomicI32::new(0);
    static BOUNDS_BOTTOM: AtomicI32 = AtomicI32::new(0);

    fn mouse_guard_state() -> &'static Mutex<Option<MouseGuardHandle>> {
        MOUSE_GUARD_STATE.get_or_init(|| Mutex::new(None))
    }

    fn store_bounds(bounds: MouseClipBounds) {
        BOUNDS_LEFT.store(bounds.left, Ordering::SeqCst);
        BOUNDS_TOP.store(bounds.top, Ordering::SeqCst);
        BOUNDS_RIGHT.store(bounds.right, Ordering::SeqCst);
        BOUNDS_BOTTOM.store(bounds.bottom, Ordering::SeqCst);
    }

    fn current_bounds() -> MouseClipBounds {
        MouseClipBounds {
            left: BOUNDS_LEFT.load(Ordering::SeqCst),
            top: BOUNDS_TOP.load(Ordering::SeqCst),
            right: BOUNDS_RIGHT.load(Ordering::SeqCst),
            bottom: BOUNDS_BOTTOM.load(Ordering::SeqCst),
        }
    }

    unsafe extern "system" fn mouse_hook_proc(
        code: i32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if code == HC_ACTION as i32
            && MOUSE_GUARD_ACTIVE.load(Ordering::SeqCst)
        {
            let mouse_info =
                unsafe { &*(lparam.0 as *const MSLLHOOKSTRUCT) };
            if let Some((x, y)) = clamp_point_to_bounds(
                mouse_info.pt.x,
                mouse_info.pt.y,
                current_bounds(),
            ) {
                let _ = unsafe { SetCursorPos(x, y) };
                return LRESULT(1);
            }
        }

        unsafe { CallNextHookEx(HHOOK::default(), code, wparam, lparam) }
    }

    fn spawn_mouse_guard_thread(
        stop_flag: Arc<AtomicBool>,
        ready_tx: mpsc::Sender<Result<u32, String>>,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            let module = match unsafe { GetModuleHandleW(None) } {
                Ok(value) => value,
                Err(error) => {
                    let _ = ready_tx.send(Err(format!(
                        "GetModuleHandleW failed for mouse hook: {error}"
                    )));
                    return;
                }
            };
            let hook = match unsafe {
                SetWindowsHookExW(
                    WH_MOUSE_LL,
                    Some(mouse_hook_proc),
                    HINSTANCE(module.0),
                    0,
                )
            } {
                Ok(value) => value,
                Err(error) => {
                    let _ = ready_tx.send(Err(format!(
                        "SetWindowsHookExW(WH_MOUSE_LL) failed: {error}"
                    )));
                    return;
                }
            };

            let mut bootstrap_message = MSG::default();
            unsafe {
                let _ = PeekMessageW(
                    &mut bootstrap_message,
                    None,
                    0,
                    0,
                    PM_NOREMOVE,
                );
            }
            let thread_id = unsafe { GetCurrentThreadId() };
            MOUSE_GUARD_ACTIVE.store(true, Ordering::SeqCst);
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

            let _ = unsafe { UnhookWindowsHookEx(hook) };
            MOUSE_GUARD_ACTIVE.store(false, Ordering::SeqCst);
        })
    }

    fn stop_mouse_guard(handle: MouseGuardHandle) {
        handle.stop_flag.store(true, Ordering::SeqCst);
        MOUSE_GUARD_ACTIVE.store(false, Ordering::SeqCst);
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

    pub fn activate_mouse_guard(display_info: &DisplayInfo) -> MouseGuardMutationResult {
        let Some(bounds) = primary_clip_bounds(display_info) else {
            let restore = deactivate_mouse_guard();
            return MouseGuardMutationResult {
                applied: restore.applied,
                active: false,
                detail: format!(
                    "Mouse guard was stopped because no primary monitor was detected. {}",
                    restore.detail
                ),
            };
        };

        let clip_rect = RECT {
            left: bounds.left,
            top: bounds.top,
            right: bounds.right,
            bottom: bounds.bottom,
        };

        store_bounds(bounds);
        let clip_result = unsafe { ClipCursor(Some(&clip_rect)) };
        let state = mouse_guard_state();
        let mut guard = match state.lock() {
            Ok(value) => value,
            Err(_) => {
                let _ = unsafe { ClipCursor(None) };
                return MouseGuardMutationResult {
                    applied: false,
                    active: false,
                    detail: "Mouse guard state lock is poisoned; ClipCursor was released."
                        .to_string(),
                }
            }
        };

        if let Some(existing_handle) = guard.as_ref() {
            if is_thread_guard_healthy(
                true,
                MOUSE_GUARD_ACTIVE.load(Ordering::SeqCst),
                existing_handle.thread.is_finished(),
            ) {
                return MouseGuardMutationResult {
                    applied: clip_result.is_ok(),
                    active: true,
                    detail: format!(
                        "Mouse hook is active and ClipCursor was re-applied to {},{} {}x{}.",
                        bounds.left,
                        bounds.top,
                        bounds.right - bounds.left,
                        bounds.bottom - bounds.top
                    ),
                };
            }
        }

        if let Some(stale_handle) = guard.take() {
            stop_mouse_guard(stale_handle);
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = mpsc::channel();
        let thread =
            spawn_mouse_guard_thread(Arc::clone(&stop_flag), ready_tx);
        match ready_rx.recv_timeout(std::time::Duration::from_secs(3)) {
            Ok(Ok(thread_id)) => {
                *guard = Some(MouseGuardHandle {
                    stop_flag,
                    thread_id,
                    thread,
                });
                MouseGuardMutationResult {
                    applied: true,
                    active: true,
                    detail: format!(
                        "WH_MOUSE_LL guard and ClipCursor are active on {},{} {}x{}.",
                        bounds.left,
                        bounds.top,
                        bounds.right - bounds.left,
                        bounds.bottom - bounds.top
                    ),
                }
            }
            Ok(Err(error)) => {
                stop_flag.store(true, Ordering::SeqCst);
                let _ = thread.join();
                MouseGuardMutationResult {
                    applied: clip_result.is_ok(),
                    active: clip_result.is_ok(),
                    detail: format!(
                        "Mouse hook failed; ClipCursor fallback status={}: {error}",
                        clip_result.is_ok()
                    ),
                }
            }
            Err(_) => {
                stop_flag.store(true, Ordering::SeqCst);
                let _ = thread.join();
                MouseGuardMutationResult {
                    applied: clip_result.is_ok(),
                    active: clip_result.is_ok(),
                    detail: "Timed out while starting WH_MOUSE_LL; ClipCursor fallback remains."
                        .to_string(),
                }
            }
        }
    }

    pub fn deactivate_mouse_guard() -> MouseGuardMutationResult {
        MOUSE_GUARD_ACTIVE.store(false, Ordering::SeqCst);
        let state = mouse_guard_state();
        let mut guard = match state.lock() {
            Ok(value) => value,
            Err(_) => {
                return MouseGuardMutationResult {
                    applied: false,
                    active: true,
                    detail: "Mouse guard state lock is poisoned during restore."
                        .to_string(),
                }
            }
        };
        if let Some(handle) = guard.take() {
            stop_mouse_guard(handle);
        }

        match unsafe { ClipCursor(None) } {
            Ok(()) => MouseGuardMutationResult {
                applied: true,
                active: false,
                detail: "WH_MOUSE_LL guard and ClipCursor were removed."
                    .to_string(),
            },
            Err(error) => MouseGuardMutationResult {
                applied: false,
                active: false,
                detail: format!(
                    "Mouse hook stopped but ClipCursor restore failed: {error}"
                ),
            },
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod windows_impl {
    use super::DisplayInfo;

    #[derive(Debug, Clone)]
    pub struct MouseGuardMutationResult {
        pub applied: bool,
        pub active: bool,
        pub detail: String,
    }

    pub fn activate_mouse_guard(_display_info: &DisplayInfo) -> MouseGuardMutationResult {
        MouseGuardMutationResult {
            applied: false,
            active: false,
            detail: "Mouse guard is only supported on Windows.".to_string(),
        }
    }

    pub fn deactivate_mouse_guard() -> MouseGuardMutationResult {
        MouseGuardMutationResult {
            applied: false,
            active: false,
            detail: "Mouse guard restore is only supported on Windows.".to_string(),
        }
    }
}

pub use windows_impl::{activate_mouse_guard, deactivate_mouse_guard, MouseGuardMutationResult};

#[cfg(test)]
mod tests {
    use super::{
        clamp_point_to_bounds, primary_clip_bounds, MouseClipBounds,
    };
    use crate::models::{DisplayInfo, MonitorInfo};

    fn display_info() -> DisplayInfo {
        DisplayInfo {
            monitor_count: 2,
            monitors: vec![
                MonitorInfo {
                    device_name: "PRIMARY".to_string(),
                    width: 1920,
                    height: 1080,
                    offset_x: 0,
                    offset_y: 0,
                    is_primary: true,
                },
                MonitorInfo {
                    device_name: "SECONDARY".to_string(),
                    width: 1920,
                    height: 1080,
                    offset_x: 1920,
                    offset_y: 0,
                    is_primary: false,
                },
            ],
        }
    }

    #[test]
    fn builds_clip_bounds_from_primary_monitor_only() {
        assert_eq!(
            primary_clip_bounds(&display_info()),
            Some(MouseClipBounds {
                left: 0,
                top: 0,
                right: 1920,
                bottom: 1080,
            })
        );
    }

    #[test]
    fn returns_none_when_primary_monitor_is_missing() {
        let mut display_info = display_info();
        for monitor in &mut display_info.monitors {
            monitor.is_primary = false;
        }

        assert_eq!(primary_clip_bounds(&display_info), None);
    }

    #[test]
    fn clamps_points_to_the_nearest_primary_monitor_edge() {
        let bounds = MouseClipBounds {
            left: 0,
            top: 0,
            right: 1920,
            bottom: 1080,
        };

        assert_eq!(
            clamp_point_to_bounds(2200, -10, bounds),
            Some((1919, 0))
        );
        assert_eq!(clamp_point_to_bounds(500, 500, bounds), None);
    }
}
