use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeWidgetState {
    pub visible: bool,
    pub widget_id: Option<String>,
    pub correlation_id: Option<String>,
    pub require_hold_ms: u64,
    pub desktop_isolation_active: bool,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeWidgetEventKind {
    HoldStarted,
    HoldCancelled,
    HoldCompleted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeWidgetEvent {
    pub kind: NativeWidgetEventKind,
    pub state: NativeWidgetState,
    pub occurred_at_ms: u64,
}

#[derive(Default)]
struct SharedWidgetState {
    desired: NativeWidgetState,
    events: VecDeque<NativeWidgetEvent>,
    shutdown: bool,
}

pub struct EmergencyWidgetManager {
    shared: Arc<Mutex<SharedWidgetState>>,
    thread: Option<JoinHandle<()>>,
}

impl EmergencyWidgetManager {
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Mutex::new(SharedWidgetState::default())),
            thread: None,
        }
    }

    pub fn update_state(&mut self, state: NativeWidgetState) {
        {
            let mut shared = self.shared.lock().expect("widget shared lock poisoned");
            shared.desired = state;
        }
        if self.thread.is_none() {
            let shared = Arc::clone(&self.shared);
            self.thread = Some(thread::spawn(move || {
                run_widget_thread(shared);
            }));
        }
    }

    pub fn drain_events(&self) -> Vec<NativeWidgetEvent> {
        let mut shared = self.shared.lock().expect("widget shared lock poisoned");
        shared.events.drain(..).collect()
    }

    pub fn shutdown(&mut self) {
        {
            let mut shared = self.shared.lock().expect("widget shared lock poisoned");
            shared.shutdown = true;
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for EmergencyWidgetManager {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn push_event(shared: &Arc<Mutex<SharedWidgetState>>, kind: NativeWidgetEventKind, state: NativeWidgetState) {
    let mut guard = shared.lock().expect("widget shared lock poisoned");
    guard.events.push_back(NativeWidgetEvent {
        kind,
        occurred_at_ms: now_ms(),
        state,
    });
}

fn desired_state(shared: &Arc<Mutex<SharedWidgetState>>) -> NativeWidgetState {
    shared
        .lock()
        .expect("widget shared lock poisoned")
        .desired
        .clone()
}

fn is_shutdown(shared: &Arc<Mutex<SharedWidgetState>>) -> bool {
    shared.lock().expect("widget shared lock poisoned").shutdown
}

#[cfg(target_os = "windows")]
fn run_widget_thread(shared: Arc<Mutex<SharedWidgetState>>) {
    use std::mem::size_of;
    use std::ptr::null_mut;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
    use windows::Win32::Graphics::Gdi::{
        BeginPaint, CreateSolidBrush, DeleteObject, DrawTextW, EndPaint, FillRect,
        GetMonitorInfoW, GetStockObject, InvalidateRect, MonitorFromPoint, MONITORINFO,
        SetBkMode, SetTextColor, UpdateWindow, DEFAULT_GUI_FONT, DT_CENTER, DT_SINGLELINE,
        DT_VCENTER, HGDIOBJ, HMONITOR, MONITOR_DEFAULTTOPRIMARY, PAINTSTRUCT, TRANSPARENT,
    };
    use windows::Win32::UI::HiDpi::{
        GetDpiForWindow, SetThreadDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
    };
    use windows::Win32::UI::Input::KeyboardAndMouse::{ReleaseCapture, SetCapture};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetCursorPos,
        GetMessageW, GetWindowLongPtrW, LoadCursorW, PostQuitMessage, RegisterClassW, SetTimer,
        SetWindowLongPtrW, SetWindowPos, ShowWindow, TranslateMessage, CS_HREDRAW, CS_VREDRAW,
        CW_USEDEFAULT, GWLP_USERDATA, HCURSOR, HMENU, HWND_TOPMOST, IDC_HAND, MSG, SW_HIDE,
        SW_SHOWNOACTIVATE, SWP_NOACTIVATE, SWP_SHOWWINDOW, WM_CANCELMODE, WM_CAPTURECHANGED,
        WM_DESTROY, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_PAINT, WM_POINTERDOWN, WM_POINTERUP,
        WM_TIMER, WNDCLASSW, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP,
    };

    const TIMER_ID: usize = 7;
    const TIMER_INTERVAL_MS: u32 = 50;

    #[derive(Clone)]
    struct WindowState {
        shared: Arc<Mutex<SharedWidgetState>>,
        holding: bool,
        hold_started_at_ms: u64,
        completed_sent: bool,
        visible: bool,
    }

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let state_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut WindowState;
        if message == WM_DESTROY {
            if !state_ptr.is_null() {
                let _ = Box::from_raw(state_ptr);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
            PostQuitMessage(0);
            return LRESULT(0);
        }

        if state_ptr.is_null() {
            return DefWindowProcW(hwnd, message, wparam, lparam);
        }
        let state = &mut *state_ptr;

        match message {
            WM_TIMER => {
                if is_shutdown(&state.shared) {
                    DestroyWindow(hwnd).ok();
                    return LRESULT(0);
                }

                let desired = desired_state(&state.shared);
                let should_show = desired.visible && desired.widget_id.is_some();
                if should_show != state.visible {
                    apply_window_position(hwnd);
                    let _ = ShowWindow(hwnd, if should_show { SW_SHOWNOACTIVATE } else { SW_HIDE });
                    state.visible = should_show;
                } else if should_show {
                    apply_window_position(hwnd);
                }

                if state.holding && !state.completed_sent {
                    let elapsed = now_ms().saturating_sub(state.hold_started_at_ms);
                    if elapsed >= desired.require_hold_ms.max(500) {
                        state.holding = false;
                        state.completed_sent = true;
                        let _ = ReleaseCapture();
                        push_event(&state.shared, NativeWidgetEventKind::HoldCompleted, desired);
                    }
                    let _ = InvalidateRect(hwnd, None, true).ok();
                } else if should_show {
                    let _ = InvalidateRect(hwnd, None, true).ok();
                }
                LRESULT(0)
            }
            WM_LBUTTONDOWN | WM_POINTERDOWN => {
                let desired = desired_state(&state.shared);
                if !desired.visible || desired.widget_id.is_none() {
                    return LRESULT(0);
                }
                state.holding = true;
                state.completed_sent = false;
                state.hold_started_at_ms = now_ms();
                let _ = SetCapture(hwnd);
                push_event(&state.shared, NativeWidgetEventKind::HoldStarted, desired);
                let _ = InvalidateRect(hwnd, None, true).ok();
                LRESULT(0)
            }
            WM_LBUTTONUP | WM_POINTERUP | WM_CANCELMODE | WM_CAPTURECHANGED => {
                if state.holding && !state.completed_sent {
                    state.holding = false;
                    state.completed_sent = false;
                    let desired = desired_state(&state.shared);
                    push_event(&state.shared, NativeWidgetEventKind::HoldCancelled, desired);
                    let _ = ReleaseCapture();
                    let _ = InvalidateRect(hwnd, None, true).ok();
                }
                LRESULT(0)
            }
            WM_PAINT => {
                let desired = desired_state(&state.shared);
                let mut paint = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut paint);
                let mut rect = RECT::default();
                let _ = windows::Win32::UI::WindowsAndMessaging::GetClientRect(hwnd, &mut rect);
                let background = CreateSolidBrush(COLORREF(0x202020));
                let progress = CreateSolidBrush(COLORREF(0xD95F2A));
                let _ = FillRect(hdc, &rect, background);
                let elapsed = if state.holding {
                    now_ms().saturating_sub(state.hold_started_at_ms)
                } else if state.completed_sent {
                    desired.require_hold_ms
                } else {
                    0
                };
                let progress_width = if desired.require_hold_ms == 0 {
                    0
                } else {
                    (((rect.right - rect.left) as u64)
                        .saturating_mul(elapsed.min(desired.require_hold_ms)))
                        / desired.require_hold_ms
                } as i32;
                if progress_width > 0 {
                    let progress_rect = RECT {
                        left: rect.left,
                        top: rect.bottom - scale_for_window(hwnd, 8),
                        right: rect.left + progress_width,
                        bottom: rect.bottom,
                    };
                    let _ = FillRect(hdc, &progress_rect, progress);
                }
                let _ = windows::Win32::Graphics::Gdi::SelectObject(
                    hdc,
                    HGDIOBJ(GetStockObject(DEFAULT_GUI_FONT).0),
                );
                let _ = SetBkMode(hdc, TRANSPARENT);
                let _ = SetTextColor(hdc, COLORREF(0xF4F4F4));
                let label = if state.holding { "HOLD" } else { "RESTORE" };
                let mut label_wide = to_wide(label);
                let _ = DrawTextW(hdc, &mut label_wide, &mut rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                let _ = DeleteObject(background);
                let _ = DeleteObject(progress);
                let _ = EndPaint(hwnd, &paint);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, message, wparam, lparam),
        }
    }

    let _ = unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    let class_name = to_wide("EduLearnEmergencyRestoreWidget");
    let instance = unsafe { windows::Win32::System::LibraryLoader::GetModuleHandleW(None) }.unwrap_or_default();
    let cursor: HCURSOR = unsafe { LoadCursorW(None, IDC_HAND) }.unwrap_or_default();
    let class = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(window_proc),
        hInstance: instance.into(),
        hCursor: cursor,
        lpszClassName: PCWSTR(class_name.as_ptr()),
        ..Default::default()
    };
    let _ = unsafe { RegisterClassW(&class) };

    let title = to_wide("Emergency Restore");
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            PCWSTR(class_name.as_ptr()),
            PCWSTR(title.as_ptr()),
            WS_POPUP,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            scale_px(148, 96),
            scale_px(56, 96),
            HWND(null_mut()),
            HMENU(null_mut()),
            instance,
            None,
        )
    };
    let Ok(hwnd) = hwnd else { return; };

    let state = Box::new(WindowState {
        shared,
        holding: false,
        hold_started_at_ms: 0,
        completed_sent: false,
        visible: false,
    });
    unsafe {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(state) as isize);
        SetTimer(hwnd, TIMER_ID, TIMER_INTERVAL_MS, None);
        let _ = ShowWindow(hwnd, SW_HIDE);
        let _ = UpdateWindow(hwnd).ok();
    }

    let mut message = MSG::default();
    while unsafe { GetMessageW(&mut message, HWND(null_mut()), 0, 0) }.into() {
        unsafe {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    fn apply_window_position(hwnd: HWND) {
        let mut cursor = POINT::default();
        let _ = unsafe { GetCursorPos(&mut cursor) };
        let monitor: HMONITOR = unsafe { MonitorFromPoint(cursor, MONITOR_DEFAULTTOPRIMARY) };
        let mut monitor_info = MONITORINFO {
            cbSize: size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        let _ = unsafe { GetMonitorInfoW(monitor, &mut monitor_info) };
        let dpi = unsafe { GetDpiForWindow(hwnd) }.max(96);
        let width = scale_px(148, dpi);
        let height = scale_px(56, dpi);
        let margin = scale_px(20, dpi);
        let right = monitor_info.rcWork.right;
        let bottom = monitor_info.rcWork.bottom;
        let x = right - width - margin;
        let y = bottom - height - margin;
        let _ = unsafe {
            SetWindowPos(
                hwnd,
                HWND_TOPMOST,
                x,
                y,
                width,
                height,
                SWP_NOACTIVATE | SWP_SHOWWINDOW,
            )
        };
    }

    fn scale_for_window(hwnd: HWND, value: i32) -> i32 {
        scale_px(value, unsafe { GetDpiForWindow(hwnd) }.max(96))
    }
}

#[cfg(not(target_os = "windows"))]
fn run_widget_thread(shared: Arc<Mutex<SharedWidgetState>>) {
    loop {
        if is_shutdown(&shared) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn scale_px(value: i32, dpi: u32) -> i32 {
    ((value as i64) * (dpi as i64) / 96_i64) as i32
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{NativeWidgetEventKind, NativeWidgetState};

    #[test]
    fn widget_state_defaults_to_hidden() {
        let state = NativeWidgetState::default();
        assert!(!state.visible);
        assert_eq!(state.require_hold_ms, 0);
    }

    #[test]
    fn event_kinds_are_distinct() {
        assert_ne!(NativeWidgetEventKind::HoldStarted, NativeWidgetEventKind::HoldCompleted);
        assert_ne!(NativeWidgetEventKind::HoldCancelled, NativeWidgetEventKind::HoldCompleted);
    }
}
