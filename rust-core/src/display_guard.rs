use crate::models::{DesktopStateSnapshot, DisplayInfo, MonitorInfo};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct DisplayProtectionPlan {
    pub active_monitor_count: usize,
    pub black_overlay_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverlayMutationResult {
    pub applied: bool,
    pub active: bool,
    pub overlay_count: usize,
    pub detail: String,
}

pub fn build_display_protection_plan(desktop_state: &DesktopStateSnapshot) -> DisplayProtectionPlan {
    DisplayProtectionPlan {
        active_monitor_count: desktop_state.monitor_count,
        black_overlay_count: desktop_state.monitor_count.saturating_sub(1),
    }
}

pub fn build_display_protection_plan_from_display_info(display_info: &DisplayInfo) -> DisplayProtectionPlan {
    DisplayProtectionPlan {
        active_monitor_count: display_info.monitor_count,
        black_overlay_count: display_info.monitors.iter().filter(|monitor| !monitor.is_primary).count(),
    }
}

fn collect_secondary_monitors(display_info: &DisplayInfo) -> Vec<MonitorInfo> {
    display_info
        .monitors
        .iter()
        .filter(|monitor| !monitor.is_primary)
        .cloned()
        .collect()
}

#[cfg(target_os = "windows")]
mod native_overlay {
    use super::{collect_secondary_monitors, DisplayInfo, MonitorInfo, OverlayMutationResult};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc, Mutex, OnceLock};
    use std::thread::{self, JoinHandle};

    use windows::core::w;
    use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
    use windows::Win32::Graphics::Gdi::{GetStockObject, BLACK_BRUSH, HBRUSH};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, PeekMessageW,
        GetWindowRect, IsWindow, PostThreadMessageW, RegisterClassW, SetWindowDisplayAffinity,
        SetWindowPos, ShowWindow, TranslateMessage, CS_HREDRAW, CS_VREDRAW, HWND_TOPMOST, MSG,
        PM_NOREMOVE, SC_CLOSE, SC_MINIMIZE, SW_SHOW, SWP_NOACTIVATE, SWP_NOMOVE,
        SWP_NOSIZE, SWP_SHOWWINDOW, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR, WINDOW_EX_STYLE,
        WINDOW_STYLE, WM_CLOSE, WM_QUIT, WM_SYSCOMMAND, WNDCLASSW, WS_EX_NOACTIVATE,
        WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP, WS_VISIBLE,
    };

    const OVERLAY_CLASS_NAME: windows::core::PCWSTR = w!("EdulearnSafeExamOverlayWindow");
    const OVERLAY_WINDOW_TITLE: windows::core::PCWSTR = w!("Edulearn Safe Exam Overlay");

    struct NativeOverlayHandle {
        thread_id: u32,
        window_handles: Vec<isize>,
        signature: String,
        stop_flag: Arc<AtomicBool>,
        thread: JoinHandle<()>,
    }

    static NATIVE_OVERLAY_STATE: OnceLock<Mutex<Option<NativeOverlayHandle>>> = OnceLock::new();

    fn native_overlay_state() -> &'static Mutex<Option<NativeOverlayHandle>> {
        NATIVE_OVERLAY_STATE.get_or_init(|| Mutex::new(None))
    }

    fn build_signature(display_info: &DisplayInfo) -> String {
        collect_secondary_monitors(display_info)
            .iter()
            .map(|monitor| {
                format!(
                    "{}:{}:{}:{}:{}",
                    monitor.device_name, monitor.offset_x, monitor.offset_y, monitor.width, monitor.height
                )
            })
            .collect::<Vec<_>>()
            .join("|")
    }

    unsafe extern "system" fn overlay_window_proc(
        window_handle: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if message == WM_CLOSE {
            return LRESULT(0);
        }

        if message == WM_SYSCOMMAND {
            let command = (wparam.0 & 0xfff0) as u32;
            if command == SC_CLOSE || command == SC_MINIMIZE {
                return LRESULT(0);
            }
        }

        if message == WM_QUIT {
            return LRESULT(0);
        }

        unsafe { DefWindowProcW(window_handle, message, wparam, lparam) }
    }

    fn register_overlay_window_class(instance_handle: HINSTANCE) {
        let window_class = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(overlay_window_proc),
            hInstance: instance_handle,
            hbrBackground: HBRUSH(unsafe { GetStockObject(BLACK_BRUSH) }.0),
            lpszClassName: OVERLAY_CLASS_NAME,
            ..Default::default()
        };

        let _ = unsafe { RegisterClassW(&window_class) };
    }

    fn create_overlay_window(instance_handle: HINSTANCE, monitor: &crate::models::MonitorInfo) -> Result<HWND, String> {
        let width = monitor.width.max(1);
        let height = monitor.height.max(1);

        let window_handle = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(WS_EX_TOPMOST.0 | WS_EX_TOOLWINDOW.0 | WS_EX_NOACTIVATE.0),
                OVERLAY_CLASS_NAME,
                OVERLAY_WINDOW_TITLE,
                WINDOW_STYLE(WS_POPUP.0 | WS_VISIBLE.0),
                monitor.offset_x,
                monitor.offset_y,
                width,
                height,
                HWND::default(),
                None,
                instance_handle,
                None,
            )
        }
        .map_err(|error| {
            format!(
                "Failed to create a native overlay window for {}: {error}",
                monitor.device_name
            )
        })?;

        unsafe {
            if SetWindowDisplayAffinity(window_handle, WDA_EXCLUDEFROMCAPTURE).is_err() {
                let _ = SetWindowDisplayAffinity(window_handle, WDA_MONITOR);
            }
            let _ = ShowWindow(window_handle, SW_SHOW);
            let _ = SetWindowPos(
                window_handle,
                HWND_TOPMOST,
                monitor.offset_x,
                monitor.offset_y,
                width,
                height,
                SWP_SHOWWINDOW | SWP_NOACTIVATE,
            );
        }

        Ok(window_handle)
    }

    fn monitor_bounds(monitor: &MonitorInfo) -> RECT {
        RECT {
            left: monitor.offset_x,
            top: monitor.offset_y,
            right: monitor.offset_x.saturating_add(monitor.width.max(1)),
            bottom: monitor.offset_y.saturating_add(monitor.height.max(1)),
        }
    }

    fn rect_matches_monitor(rect: RECT, monitor: &MonitorInfo) -> bool {
        let expected = monitor_bounds(monitor);
        rect.left == expected.left
            && rect.top == expected.top
            && rect.right == expected.right
            && rect.bottom == expected.bottom
    }

    fn heal_overlay_windows(
        window_handles: &[isize],
        secondary_monitors: &[MonitorInfo],
    ) -> Result<usize, String> {
        let mut healed_count = 0;
        if window_handles.len() != secondary_monitors.len() {
            return Err(format!(
                "Overlay count {} no longer matches secondary monitor count {}.",
                window_handles.len(),
                secondary_monitors.len()
            ));
        }

        for (raw_handle, monitor) in window_handles.iter().zip(secondary_monitors) {
            let window_handle = HWND(*raw_handle as *mut core::ffi::c_void);
            if !unsafe { IsWindow(window_handle) }.as_bool() {
                return Err(format!("Overlay window handle 0x{raw_handle:x} is no longer valid."));
            }
            let mut actual = RECT::default();
            unsafe { GetWindowRect(window_handle, &mut actual) }.map_err(|error| {
                format!("Failed to query bounds for overlay 0x{raw_handle:x}: {error}")
            })?;
            if !rect_matches_monitor(actual, monitor) {
                return Err(format!(
                    "Overlay 0x{raw_handle:x} bounds mismatch; expected {},{} {}x{} but got {},{} {}x{}.",
                    monitor.offset_x,
                    monitor.offset_y,
                    monitor.width,
                    monitor.height,
                    actual.left,
                    actual.top,
                    actual.right.saturating_sub(actual.left),
                    actual.bottom.saturating_sub(actual.top)
                ));
            }

            unsafe {
                if SetWindowDisplayAffinity(window_handle, WDA_EXCLUDEFROMCAPTURE).is_err() {
                    SetWindowDisplayAffinity(window_handle, WDA_MONITOR).map_err(|error| {
                        format!(
                            "Failed to restore capture affinity for overlay 0x{raw_handle:x}: {error}"
                        )
                    })?;
                }
                let _ = ShowWindow(window_handle, SW_SHOW);
                SetWindowPos(
                    window_handle,
                    HWND_TOPMOST,
                    0,
                    0,
                    0,
                    0,
                    SWP_SHOWWINDOW | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE,
                )
                .map_err(|error| {
                    format!("Failed to restore TOPMOST for overlay 0x{raw_handle:x}: {error}")
                })?;
            }

            healed_count += 1;
        }

        Ok(healed_count)
    }

    fn spawn_overlay_thread(
        display_info: DisplayInfo,
        stop_flag: Arc<AtomicBool>,
        ready_tx: mpsc::Sender<Result<(u32, Vec<isize>), String>>,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            let instance_handle = match unsafe { GetModuleHandleW(None) } {
                Ok(handle) => HINSTANCE(handle.0),
                Err(error) => {
                    let _ = ready_tx.send(Err(format!("GetModuleHandleW failed: {error}")));
                    return;
                }
            };

            register_overlay_window_class(instance_handle);

            let mut bootstrap_message = MSG::default();
            unsafe {
                let _ = PeekMessageW(&mut bootstrap_message, HWND::default(), 0, 0, PM_NOREMOVE);
            }

            let secondary_monitors = collect_secondary_monitors(&display_info);
            let thread_id = unsafe { GetCurrentThreadId() };
            let mut window_handles = Vec::<HWND>::new();

            for monitor in &secondary_monitors {
                match create_overlay_window(instance_handle, monitor) {
                    Ok(window_handle) => window_handles.push(window_handle),
                    Err(error) => {
                        for existing_window in &window_handles {
                            unsafe {
                                let _ = DestroyWindow(*existing_window);
                            }
                        }
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                }
            }

            let raw_window_handles = window_handles
                .iter()
                .map(|window_handle| window_handle.0 as isize)
                .collect::<Vec<_>>();
            let _ = ready_tx.send(Ok((thread_id, raw_window_handles)));

            let mut message = MSG::default();
            loop {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }

                let result = unsafe { GetMessageW(&mut message, HWND::default(), 0, 0) };
                if result.0 <= 0 || message.message == WM_QUIT {
                    break;
                }

                unsafe {
                    let _ = TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }

            for window_handle in window_handles {
                unsafe {
                    let _ = DestroyWindow(window_handle);
                }
            }
        })
    }

    fn stop_existing_overlay(handle: NativeOverlayHandle) -> OverlayMutationResult {
        handle.stop_flag.store(true, Ordering::SeqCst);
        unsafe {
            let _ = PostThreadMessageW(handle.thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
        }
        let _ = handle.thread.join();

        OverlayMutationResult {
            applied: true,
            active: false,
            overlay_count: 0,
            detail: "Native secondary-display overlays were removed.".to_string(),
        }
    }

    pub fn activate_native_overlays(display_info: &DisplayInfo) -> OverlayMutationResult {
        let secondary_monitors = collect_secondary_monitors(display_info);
        let secondary_monitor_count = secondary_monitors.len();
        let signature = build_signature(display_info);
        let state = native_overlay_state();
        let mut guard = match state.lock() {
            Ok(value) => value,
            Err(_) => {
                return OverlayMutationResult {
                    applied: false,
                    active: false,
                    overlay_count: 0,
                    detail: "Native overlay state lock is poisoned.".to_string(),
                }
            }
        };

        if secondary_monitor_count == 0 {
            if let Some(existing_handle) = guard.take() {
                let _ = stop_existing_overlay(existing_handle);
                return OverlayMutationResult {
                    applied: true,
                    active: false,
                    overlay_count: 0,
                    detail: "No secondary monitors remain; stale native overlay windows were destroyed.".to_string(),
                };
            }

            return OverlayMutationResult {
                applied: true,
                active: false,
                overlay_count: 0,
                detail: "No secondary monitors were detected. Native overlay windows were not required.".to_string(),
            };
        }

        if let Some(existing_handle) = guard.as_ref() {
            if existing_handle.signature == signature {
                if let Ok(healed_count) =
                    heal_overlay_windows(&existing_handle.window_handles, &secondary_monitors)
                {
                    return OverlayMutationResult {
                        applied: true,
                        active: healed_count > 0,
                        overlay_count: healed_count,
                        detail: format!(
                            "Self-healed {} native overlay window(s): TOPMOST and capture affinity were re-applied.",
                            healed_count
                        ),
                    };
                }
            }
        }

        if let Some(existing_handle) = guard.take() {
            let _ = stop_existing_overlay(existing_handle);
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = mpsc::channel();
        let thread = spawn_overlay_thread(display_info.clone(), Arc::clone(&stop_flag), ready_tx);

        match ready_rx.recv_timeout(std::time::Duration::from_secs(3)) {
            Ok(Ok((thread_id, window_handles))) => {
                let overlay_count = window_handles.len();
                *guard = Some(NativeOverlayHandle {
                    thread_id,
                    window_handles,
                    signature,
                    stop_flag,
                    thread,
                });

                OverlayMutationResult {
                    applied: true,
                    active: overlay_count > 0,
                    overlay_count,
                    detail: format!(
                        "Native overlay windows are active on {} secondary monitor(s).",
                        overlay_count
                    ),
                }
            }
            Ok(Err(error)) => {
                stop_flag.store(true, Ordering::SeqCst);
                let _ = thread.join();
                OverlayMutationResult {
                    applied: false,
                    active: false,
                    overlay_count: 0,
                    detail: error,
                }
            }
            Err(_) => {
                stop_flag.store(true, Ordering::SeqCst);
                let _ = thread.join();
                OverlayMutationResult {
                    applied: false,
                    active: false,
                    overlay_count: 0,
                    detail: "Timed out while waiting for native overlay windows to activate.".to_string(),
                }
            }
        }
    }

    pub fn sync_native_overlays(display_info: &DisplayInfo) -> OverlayMutationResult {
        activate_native_overlays(display_info)
    }

    pub fn deactivate_native_overlays() -> OverlayMutationResult {
        let state = native_overlay_state();
        let mut guard = match state.lock() {
            Ok(value) => value,
            Err(_) => {
                return OverlayMutationResult {
                    applied: false,
                    active: false,
                    overlay_count: 0,
                    detail: "Native overlay state lock is poisoned during restore.".to_string(),
                }
            }
        };

        if let Some(existing_handle) = guard.take() {
            return stop_existing_overlay(existing_handle);
        }

        OverlayMutationResult {
            applied: true,
            active: false,
            overlay_count: 0,
            detail: "Native overlay windows were already inactive.".to_string(),
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod native_overlay {
    use super::{collect_secondary_monitors, DisplayInfo, OverlayMutationResult};

    pub fn activate_native_overlays(display_info: &DisplayInfo) -> OverlayMutationResult {
        let overlay_count = collect_secondary_monitors(display_info).len();

        OverlayMutationResult {
            applied: false,
            active: false,
            overlay_count,
            detail: "Native overlay windows are only supported on Windows.".to_string(),
        }
    }

    pub fn sync_native_overlays(display_info: &DisplayInfo) -> OverlayMutationResult {
        activate_native_overlays(display_info)
    }

    pub fn deactivate_native_overlays() -> OverlayMutationResult {
        OverlayMutationResult {
            applied: false,
            active: false,
            overlay_count: 0,
            detail: "Native overlay windows are only supported on Windows.".to_string(),
        }
    }
}

pub use native_overlay::{activate_native_overlays, deactivate_native_overlays, sync_native_overlays};

#[cfg(test)]
mod tests {
    use super::{build_display_protection_plan, build_display_protection_plan_from_display_info};
    use crate::models::{DesktopStateSnapshot, DisplayInfo, MonitorInfo};

    fn desktop_state(monitor_count: usize) -> DesktopStateSnapshot {
        DesktopStateSnapshot {
            captured_at: 1,
            monitor_count,
            taskbar_visible: true,
            start_menu_visible: false,
            foreground_window_title: Some("English Reading".to_string()),
        }
    }

    fn display_info(monitor_count: usize) -> DisplayInfo {
        let monitors = (0..monitor_count)
            .map(|index| MonitorInfo {
                device_name: format!("MONITOR-{index}"),
                width: 1920,
                height: 1080,
                offset_x: (index as i32) * 1920,
                offset_y: 0,
                is_primary: index == 0,
            })
            .collect::<Vec<_>>();

        DisplayInfo {
            monitor_count,
            monitors,
        }
    }

    #[test]
    fn keeps_single_monitor_without_auxiliary_overlays() {
        let plan = build_display_protection_plan(&desktop_state(1));

        assert_eq!(plan.active_monitor_count, 1);
        assert_eq!(plan.black_overlay_count, 0);
    }

    #[test]
    fn adds_black_overlays_for_each_secondary_monitor() {
        let plan = build_display_protection_plan(&desktop_state(3));

        assert_eq!(plan.active_monitor_count, 3);
        assert_eq!(plan.black_overlay_count, 2);
    }

    #[test]
    fn display_info_plan_tracks_secondary_monitor_count() {
        let plan = build_display_protection_plan_from_display_info(&display_info(4));

        assert_eq!(plan.active_monitor_count, 4);
        assert_eq!(plan.black_overlay_count, 3);
    }
}
