#[cfg(target_os = "windows")]
mod windows_impl {
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        FindWindowW, IsWindowVisible, ShowWindow, SW_HIDE, SW_SHOW,
    };

    #[derive(Debug, Clone)]
    pub struct TaskbarMutationResult {
        pub applied: bool,
        pub detail: String,
    }

    fn find_taskbar_window() -> Option<HWND> {
        match unsafe { FindWindowW(w!("Shell_TrayWnd"), PCWSTR::null()) } {
            Ok(handle) if !handle.0.is_null() => Some(handle),
            _ => None,
        }
    }

    pub fn is_taskbar_visible() -> bool {
        if let Some(handle) = find_taskbar_window() {
            unsafe { IsWindowVisible(handle).as_bool() }
        } else {
            true
        }
    }

    pub fn hide_taskbar() -> TaskbarMutationResult {
        match find_taskbar_window() {
            Some(handle) => {
                let applied = unsafe { ShowWindow(handle, SW_HIDE).as_bool() || !IsWindowVisible(handle).as_bool() };
                TaskbarMutationResult {
                    applied,
                    detail: if applied {
                        "Taskbar hide request completed.".to_string()
                    } else {
                        "Taskbar hide request did not change the shell visibility.".to_string()
                    },
                }
            }
            None => TaskbarMutationResult {
                applied: false,
                detail: "Shell_TrayWnd was not found. Taskbar hide was skipped.".to_string(),
            },
        }
    }

    pub fn show_taskbar(previously_visible: bool) -> TaskbarMutationResult {
        match find_taskbar_window() {
            Some(handle) => {
                let should_show = previously_visible;
                let applied = if should_show {
                    unsafe { ShowWindow(handle, SW_SHOW).as_bool() || IsWindowVisible(handle).as_bool() }
                } else {
                    true
                };

                TaskbarMutationResult {
                    applied,
                    detail: if should_show {
                        "Taskbar restore request completed.".to_string()
                    } else {
                        "Taskbar was hidden before the session and was left unchanged.".to_string()
                    },
                }
            }
            None => TaskbarMutationResult {
                applied: false,
                detail: "Shell_TrayWnd was not found. Taskbar restore was skipped.".to_string(),
            },
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod windows_impl {
    #[derive(Debug, Clone)]
    pub struct TaskbarMutationResult {
        pub applied: bool,
        pub detail: String,
    }

    pub fn is_taskbar_visible() -> bool {
        true
    }

    pub fn hide_taskbar() -> TaskbarMutationResult {
        TaskbarMutationResult {
            applied: false,
            detail: "Taskbar hide is only supported on Windows.".to_string(),
        }
    }

    pub fn show_taskbar(previously_visible: bool) -> TaskbarMutationResult {
        TaskbarMutationResult {
            applied: false,
            detail: "Taskbar restore is only supported on Windows.".to_string(),
        }
    }
}

pub use windows_impl::{hide_taskbar, is_taskbar_visible, show_taskbar, TaskbarMutationResult};
