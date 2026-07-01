use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Clone, PartialEq, Eq)]
struct IsolationConfig {
    desktop_name: String,
    application: PathBuf,
    application_args: Vec<String>,
    switch_desktop: bool,
}

impl IsolationConfig {
    fn parse<I>(arguments: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut arguments = arguments.into_iter();
        let _executable = arguments.next();
        let mut desktop_name = "EduLearnExamDesktop".to_string();
        let mut application = None;
        let mut application_args = Vec::new();
        let mut switch_desktop = false;

        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--desktop-name" => {
                    desktop_name = arguments
                        .next()
                        .ok_or_else(|| "--desktop-name requires a value.".to_string())?;
                }
                "--application" => {
                    application = Some(PathBuf::from(
                        arguments
                            .next()
                            .ok_or_else(|| "--application requires a path.".to_string())?,
                    ));
                }
                "--switch" => switch_desktop = true,
                "--" => {
                    application_args.extend(arguments);
                    break;
                }
                unknown => return Err(format!("Unknown argument {unknown}.")),
            }
        }

        validate_desktop_name(&desktop_name)?;
        Ok(Self {
            desktop_name,
            application: application
                .ok_or_else(|| "--application is required.".to_string())?,
            application_args,
            switch_desktop,
        })
    }
}

fn validate_desktop_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
    {
        return Err(
            "Desktop name must contain 1-64 ASCII letters, digits, '-' or '_'.".to_string(),
        );
    }
    Ok(())
}

fn quote_windows_argument(value: &str) -> String {
    if !value.is_empty()
        && !value
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return value.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for character in value.chars() {
        if character == '\\' {
            backslashes += 1;
        } else if character == '"' {
            quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
            quoted.push('"');
            backslashes = 0;
        } else {
            quoted.push_str(&"\\".repeat(backslashes));
            backslashes = 0;
            quoted.push(character);
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

fn build_command_line(application: &str, arguments: &[String]) -> String {
    std::iter::once(application)
        .chain(arguments.iter().map(String::as_str))
        .map(quote_windows_argument)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(target_os = "windows")]
fn run(config: &IsolationConfig) -> Result<u32, String> {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::StationsAndDesktops::{
        CloseDesktop, CreateDesktopW, OpenInputDesktop, SwitchDesktop, DESKTOP_CONTROL_FLAGS,
        DESKTOP_CREATEWINDOW, DESKTOP_READOBJECTS, DESKTOP_SWITCHDESKTOP, DESKTOP_WRITEOBJECTS,
        HDESK,
    };
    use windows::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
        CREATE_NEW_PROCESS_GROUP, INFINITE, PROCESS_INFORMATION, STARTUPINFOW,
    };

    struct DesktopGuard {
        original: HDESK,
        exam: HDESK,
        switched: bool,
    }

    impl Drop for DesktopGuard {
        fn drop(&mut self) {
            if self.switched {
                let _ = unsafe { SwitchDesktop(self.original) };
            }
            let _ = unsafe { CloseDesktop(self.exam) };
            let _ = unsafe { CloseDesktop(self.original) };
        }
    }

    struct ChildProcessGuard {
        handle: HANDLE,
        terminate_on_drop: bool,
    }

    impl ChildProcessGuard {
        fn new(handle: HANDLE) -> Self {
            Self {
                handle,
                terminate_on_drop: true,
            }
        }

        fn disarm(&mut self) {
            self.terminate_on_drop = false;
        }
    }

    impl Drop for ChildProcessGuard {
        fn drop(&mut self) {
            if self.terminate_on_drop {
                let _ = unsafe { TerminateProcess(self.handle, 222) };
            }
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }

    let mut name_wide = config
        .desktop_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let original = unsafe {
        OpenInputDesktop(
            DESKTOP_CONTROL_FLAGS(0),
            false,
            DESKTOP_SWITCHDESKTOP,
        )
    }
    .map_err(|error| format!("OpenInputDesktop failed: {error}"))?;
    let access = DESKTOP_CREATEWINDOW.0
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
    .map_err(|error| {
        let _ = unsafe { CloseDesktop(original) };
        format!("CreateDesktopW failed: {error}")
    })?;
    let mut guard = DesktopGuard {
        original,
        exam,
        switched: false,
    };

    let desktop_path = format!("WinSta0\\{}", config.desktop_name);
    let mut desktop_path_wide = desktop_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let application = config.application.to_string_lossy().to_string();
    let mut application_wide = application
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut command_line_wide = build_command_line(&application, &config.application_args)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut startup = STARTUPINFOW::default();
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    startup.lpDesktop = PWSTR(desktop_path_wide.as_mut_ptr());
    let mut process = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            PCWSTR(application_wide.as_mut_ptr()),
            PWSTR(command_line_wide.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_NEW_PROCESS_GROUP,
            None,
            PCWSTR::null(),
            &startup,
            &mut process,
        )
    }
    .map_err(|error| format!("CreateProcessW on exam desktop failed: {error}"))?;
    let _ = unsafe { CloseHandle(process.hThread) };
    let mut child_guard = ChildProcessGuard::new(process.hProcess);

    if config.switch_desktop {
        unsafe { SwitchDesktop(exam) }
            .map_err(|error| format!("SwitchDesktop(exam) failed: {error}"))?;
        guard.switched = true;
    }

    let wait_result = unsafe { WaitForSingleObject(child_guard.handle, INFINITE) };
    if wait_result != WAIT_OBJECT_0 {
        return Err(format!("WaitForSingleObject returned {wait_result:?}."));
    }
    let mut exit_code = 1_u32;
    unsafe { GetExitCodeProcess(child_guard.handle, &mut exit_code) }
        .map_err(|error| format!("GetExitCodeProcess failed: {error}"))?;
    child_guard.disarm();

    if guard.switched {
        unsafe { SwitchDesktop(original) }
            .map_err(|error| format!("SwitchDesktop(original) failed: {error}"))?;
        guard.switched = false;
    }
    drop(guard);
    name_wide.fill(0);
    application_wide.fill(0);
    Ok(exit_code)
}

#[cfg(not(target_os = "windows"))]
fn run(_config: &IsolationConfig) -> Result<u32, String> {
    Err("Desktop isolation is only supported on Windows.".to_string())
}

fn main() -> ExitCode {
    let config = match IsolationConfig::parse(std::env::args()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("desktop-isolation-prototype: {error}");
            return ExitCode::from(2);
        }
    };
    match run(&config) {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(error) => {
            eprintln!("desktop-isolation-prototype: {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_command_line, quote_windows_argument, validate_desktop_name, IsolationConfig,
    };

    #[test]
    fn validates_desktop_names() {
        assert!(validate_desktop_name("EduLearnExam_2026-01").is_ok());
        assert!(validate_desktop_name("WinSta0\\Default").is_err());
        assert!(validate_desktop_name("").is_err());
    }

    #[test]
    fn quotes_windows_arguments_with_spaces_quotes_and_trailing_slashes() {
        assert_eq!(quote_windows_argument("plain"), "plain");
        assert_eq!(quote_windows_argument("two words"), "\"two words\"");
        assert_eq!(quote_windows_argument(""), "\"\"");
        assert_eq!(
            build_command_line(
                "C:\\Program Files\\app.exe",
                &["value\"quoted".to_string(), "C:\\tail\\".to_string()],
            ),
            "\"C:\\Program Files\\app.exe\" \"value\\\"quoted\" C:\\tail\\"
        );
    }

    #[test]
    fn parses_opt_in_switch_and_application_arguments() {
        let config = IsolationConfig::parse(
            [
                "prototype.exe",
                "--desktop-name",
                "ExamDesktop",
                "--application",
                "notepad.exe",
                "--switch",
                "--",
                "file.txt",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap();
        assert!(config.switch_desktop);
        assert_eq!(config.application_args, vec!["file.txt"]);
    }
}
