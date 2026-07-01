#[derive(Debug, Clone)]
pub struct DpiAwarenessResult {
    pub applied: bool,
    pub detail: String,
}

#[cfg(target_os = "windows")]
pub fn activate_per_monitor_v2_awareness() -> DpiAwarenessResult {
    use windows::Win32::UI::HiDpi::{
        SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
    };

    match unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) } {
        Ok(()) => DpiAwarenessResult {
            applied: true,
            detail: "Rust core process DPI awareness is Per-Monitor V2.".to_string(),
        },
        Err(error) => DpiAwarenessResult {
            applied: false,
            detail: format!(
                "Per-Monitor V2 DPI awareness could not be set, likely because the process DPI context was already fixed: {error}"
            ),
        },
    }
}

#[cfg(not(target_os = "windows"))]
pub fn activate_per_monitor_v2_awareness() -> DpiAwarenessResult {
    DpiAwarenessResult {
        applied: false,
        detail: "Per-Monitor V2 DPI awareness is only supported on Windows.".to_string(),
    }
}
