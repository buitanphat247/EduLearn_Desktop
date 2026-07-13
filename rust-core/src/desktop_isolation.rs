use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct DesktopRestoreResult {
    pub applied: bool,
    pub detail: String,
}

/// Launch spec for the isolated exam-shell process. `executable` + `args` are
/// the Electron command line; `env` overrides are merged over the current
/// process environment for the spawned child.
#[derive(Debug, Clone)]
pub struct ExamDesktopLaunchSpec {
    pub desktop_name: String,
    pub executable: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub switch_to_exam: bool,
}

#[derive(Debug, Clone)]
pub struct ExamDesktopLaunchResult {
    pub desktop_path: String,
    pub desktop_name: String,
    pub shell_pid: u32,
    pub switched: bool,
    pub created: bool,
}

/// Switch the visible/input desktop back to the interactive "Default" desktop.
/// Used both by the exam-shell on a password-verified exit and by the lobby as
/// a recovery path if the exam-shell dies while the exam desktop is in front.
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

/// Create a dedicated Windows desktop, launch the exam-shell process ON that
/// desktop (a window is bound to the desktop it is created on, so the shell
/// must be spawned there), then switch input to it.
///
/// The freshly created desktop handle is intentionally closed right after the
/// child is spawned: the exam-shell's own threads keep the desktop object alive
/// for the duration of the exam, and it is auto-destroyed by the OS once the
/// shell exits — so the core never has to hold a handle across IPC calls.
#[cfg(target_os = "windows")]
pub fn launch_isolated_exam_desktop(
    spec: &ExamDesktopLaunchSpec,
) -> Result<ExamDesktopLaunchResult, String> {
    use std::ffi::c_void;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::StationsAndDesktops::{
        CloseDesktop, CreateDesktopW, SwitchDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_CREATEWINDOW,
        DESKTOP_ENUMERATE, DESKTOP_HOOKCONTROL, DESKTOP_JOURNALPLAYBACK, DESKTOP_JOURNALRECORD,
        DESKTOP_READOBJECTS, DESKTOP_SWITCHDESKTOP, DESKTOP_WRITEOBJECTS,
    };
    use windows::Win32::System::Threading::{
        CreateProcessW, TerminateProcess, CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT,
        PROCESS_INFORMATION, STARTUPINFOW,
    };

    let desktop_name = spec.desktop_name.trim();
    if desktop_name.is_empty() {
        return Err("desktopName is required for isolated exam desktop.".to_string());
    }
    validate_desktop_name(desktop_name)?;
    if spec.executable.trim().is_empty() {
        return Err("executable is required for isolated exam desktop.".to_string());
    }

    let name_wide = desktop_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let access = DESKTOP_CREATEWINDOW.0
        | DESKTOP_ENUMERATE.0
        | DESKTOP_HOOKCONTROL.0
        | DESKTOP_JOURNALPLAYBACK.0
        | DESKTOP_JOURNALRECORD.0
        | DESKTOP_READOBJECTS.0
        | DESKTOP_WRITEOBJECTS.0
        | DESKTOP_SWITCHDESKTOP.0;

    let exam = unsafe {
        CreateDesktopW(
            PCWSTR(name_wide.as_ptr()),
            PCWSTR::null(),
            None,
            DESKTOP_CONTROL_FLAGS(0),
            access,
            None,
        )
    }
    .map_err(|error| format!("CreateDesktopW({desktop_name}) failed: {error}"))?;

    let desktop_path = format!("WinSta0\\{desktop_name}");
    let mut desktop_path_wide = desktop_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();

    let mut application_wide = spec
        .executable
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut command_line_wide = build_command_line(&spec.executable, &spec.args)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut environment = build_environment_block(&spec.env);

    let mut startup = STARTUPINFOW::default();
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    startup.lpDesktop = PWSTR(desktop_path_wide.as_mut_ptr());

    let mut process = PROCESS_INFORMATION::default();
    let create_result = unsafe {
        CreateProcessW(
            PCWSTR(application_wide.as_mut_ptr()),
            PWSTR(command_line_wide.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
            Some(environment.as_mut_ptr() as *const c_void),
            PCWSTR::null(),
            &startup,
            &mut process,
        )
    };

    if let Err(error) = create_result {
        let _ = unsafe { CloseDesktop(exam) };
        return Err(format!("CreateProcessW on exam desktop failed: {error}"));
    }

    // The child's own threads keep the exam desktop alive, so we don't hold the
    // desktop handle. Close the thread handle now but keep the process handle
    // until after the switch decision, so we can terminate the child if the
    // switch fails (otherwise it would be orphaned on a hidden desktop).
    let _ = unsafe { CloseHandle(process.hThread) };

    let mut switched = false;
    if spec.switch_to_exam {
        if let Err(error) = unsafe { SwitchDesktop(exam) } {
            let _ = unsafe { TerminateProcess(process.hProcess, 1) };
            let _ = unsafe { CloseHandle(process.hProcess) };
            let _ = unsafe { CloseDesktop(exam) };
            return Err(format!("SwitchDesktop(exam) failed: {error}"));
        }
        switched = true;
    }

    // Close our handles: the child keeps the desktop alive; the lobby watches
    // the returned PID for recovery.
    let _ = unsafe { CloseHandle(process.hProcess) };
    let _ = unsafe { CloseDesktop(exam) };

    Ok(ExamDesktopLaunchResult {
        desktop_path,
        desktop_name: desktop_name.to_string(),
        shell_pid: process.dwProcessId,
        switched,
        created: true,
    })
}

#[cfg(not(target_os = "windows"))]
pub fn launch_isolated_exam_desktop(
    _spec: &ExamDesktopLaunchSpec,
) -> Result<ExamDesktopLaunchResult, String> {
    Err("Desktop isolation is only supported on Windows.".to_string())
}

/// Windows desktop names may not contain backslash and must be non-empty and
/// reasonably short; reject anything that could escape the WinSta0 station.
fn validate_desktop_name(name: &str) -> Result<(), String> {
    if name.len() > 96 {
        return Err("desktopName is too long.".to_string());
    }
    if name
        .chars()
        .any(|c| c == '\\' || c == '/' || c.is_control())
    {
        return Err("desktopName contains invalid characters.".to_string());
    }
    Ok(())
}

/// Build a Windows command line from an executable + args, quoting entries that
/// contain whitespace or quotes (CreateProcessW consumes a single string).
fn build_command_line(executable: &str, args: &[String]) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(quote_argument(executable));
    for arg in args {
        parts.push(quote_argument(arg));
    }
    parts.join(" ")
}

fn quote_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument.chars().any(|c| c == ' ' || c == '\t' || c == '"')
    {
        return argument.to_string();
    }

    let mut quoted = String::with_capacity(argument.len() + 2);
    quoted.push('"');
    let mut backslashes = 0usize;
    for c in argument.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                quoted.extend(std::iter::repeat('\\').take(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.extend(std::iter::repeat('\\').take(backslashes));
                quoted.push(c);
                backslashes = 0;
            }
        }
    }
    quoted.extend(std::iter::repeat('\\').take(backslashes * 2));
    quoted.push('"');
    quoted
}

/// Merge env overrides over the current process environment and encode the
/// result as a UTF-16 double-null-terminated block for CREATE_UNICODE_ENVIRONMENT.
#[cfg(target_os = "windows")]
fn build_environment_block(overrides: &HashMap<String, String>) -> Vec<u16> {
    use std::collections::BTreeMap;

    let mut entries = std::env::vars().collect::<BTreeMap<_, _>>();
    for (key, value) in overrides {
        entries.insert(key.clone(), value.clone());
    }

    let mut block = Vec::new();
    for (key, value) in entries {
        block.extend(format!("{key}={value}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}
