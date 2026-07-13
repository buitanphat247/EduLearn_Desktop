#[cfg(target_os = "windows")]
mod windows_impl {
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        FindWindowExW, FindWindowW, IsWindowVisible, ShowWindow, SW_HIDE, SW_SHOW,
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

    /// Every secondary-monitor taskbar (`Shell_SecondaryTrayWnd`). There is one
    /// per additional display, so we enumerate all of them rather than just the
    /// first — otherwise a second monitor keeps its taskbar during the exam.
    fn find_secondary_taskbars() -> Vec<HWND> {
        let mut handles = Vec::new();
        let mut previous = HWND::default();
        loop {
            match unsafe {
                FindWindowExW(None, previous, w!("Shell_SecondaryTrayWnd"), PCWSTR::null())
            } {
                Ok(handle) if !handle.0.is_null() => {
                    handles.push(handle);
                    previous = handle;
                }
                _ => break,
            }
        }
        handles
    }

    /// All taskbar windows (primary + every secondary monitor).
    fn all_taskbar_windows() -> Vec<HWND> {
        let mut handles = Vec::new();
        if let Some(primary) = find_taskbar_window() {
            handles.push(primary);
        }
        handles.extend(find_secondary_taskbars());
        handles
    }

    pub fn is_taskbar_visible() -> bool {
        // Visible if ANY taskbar (primary or secondary) is currently shown.
        let windows = all_taskbar_windows();
        if windows.is_empty() {
            return true;
        }
        windows
            .iter()
            .any(|handle| unsafe { IsWindowVisible(*handle).as_bool() })
    }

    pub fn hide_taskbar() -> TaskbarMutationResult {
        let windows = all_taskbar_windows();
        if windows.is_empty() {
            return TaskbarMutationResult {
                applied: false,
                detail: "No taskbar window was found. Taskbar hide was skipped.".to_string(),
            };
        }

        let total = windows.len();
        let mut hidden = 0usize;
        for handle in &windows {
            let applied = unsafe {
                ShowWindow(*handle, SW_HIDE).as_bool() || !IsWindowVisible(*handle).as_bool()
            };
            if applied {
                hidden += 1;
            }
        }

        TaskbarMutationResult {
            applied: hidden == total,
            detail: format!(
                "Taskbar hide: {hidden}/{total} taskbar window(s) hidden ({} secondary monitor).",
                total.saturating_sub(1)
            ),
        }
    }

    /// Re-hide any taskbar that has become visible again (self-heal). Intended to
    /// be called periodically by the runtime monitor, like the overlay/capture
    /// heal loops.
    pub fn reassert_taskbar_hidden() -> TaskbarMutationResult {
        hide_taskbar()
    }

    pub fn show_taskbar(previously_visible: bool) -> TaskbarMutationResult {
        if !previously_visible {
            return TaskbarMutationResult {
                applied: true,
                detail: "Taskbar was hidden before the session and was left unchanged.".to_string(),
            };
        }

        let windows = all_taskbar_windows();
        if windows.is_empty() {
            return TaskbarMutationResult {
                applied: false,
                detail: "No taskbar window was found. Taskbar restore was skipped.".to_string(),
            };
        }

        let total = windows.len();
        let mut shown = 0usize;
        for handle in &windows {
            let applied = unsafe {
                ShowWindow(*handle, SW_SHOW).as_bool() || IsWindowVisible(*handle).as_bool()
            };
            if applied {
                shown += 1;
            }
        }

        TaskbarMutationResult {
            applied: shown == total,
            detail: format!("Taskbar restore: {shown}/{total} taskbar window(s) restored."),
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

    pub fn reassert_taskbar_hidden() -> TaskbarMutationResult {
        hide_taskbar()
    }

    pub fn show_taskbar(previously_visible: bool) -> TaskbarMutationResult {
        let _ = previously_visible;
        TaskbarMutationResult {
            applied: false,
            detail: "Taskbar restore is only supported on Windows.".to_string(),
        }
    }
}

pub use windows_impl::{
    hide_taskbar, is_taskbar_visible, reassert_taskbar_hidden, show_taskbar, TaskbarMutationResult,
};
