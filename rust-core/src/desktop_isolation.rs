#[derive(Debug, Clone)]
pub struct DesktopRestoreResult {
    pub applied: bool,
    pub detail: String,
}

#[cfg(target_os = "windows")]
pub fn restore_default_input_desktop() -> DesktopRestoreResult {
    use windows::core::w;
    use windows::Win32::System::StationsAndDesktops::{
        CloseDesktop, OpenDesktopW, SwitchDesktop, DESKTOP_CONTROL_FLAGS,
        DESKTOP_SWITCHDESKTOP,
    };

    let desktop = match unsafe {
        OpenDesktopW(
            w!("Default"),
            DESKTOP_CONTROL_FLAGS(0),
            false,
            DESKTOP_SWITCHDESKTOP.0,
        )
    } {
        Ok(desktop) => desktop,
        Err(error) => {
            return DesktopRestoreResult {
                applied: false,
                detail: format!("OpenDesktopW(Default) failed: {error}"),
            }
        }
    };
    let result = unsafe { SwitchDesktop(desktop) };
    let _ = unsafe { CloseDesktop(desktop) };
    match result {
        Ok(()) => DesktopRestoreResult {
            applied: true,
            detail: "Default Windows input desktop was restored.".to_string(),
        },
        Err(error) => DesktopRestoreResult {
            applied: false,
            detail: format!("SwitchDesktop(Default) failed: {error}"),
        },
    }
}

#[cfg(not(target_os = "windows"))]
pub fn restore_default_input_desktop() -> DesktopRestoreResult {
    DesktopRestoreResult {
        applied: false,
        detail: "Desktop isolation recovery is only supported on Windows.".to_string(),
    }
}
