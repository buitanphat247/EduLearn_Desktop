#[cfg(target_os = "windows")]
mod windows_impl {
    use std::fs::File;
    use std::os::windows::io::FromRawHandle;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{GetLastError, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE};
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    pub fn accept_authenticated_pipe(
        pipe_name: &str,
        expected_client_pid: u32,
    ) -> Result<File, String> {
        validate_pipe_name(pipe_name)?;
        let full_name = format!(r"\\.\pipe\{pipe_name}");
        let wide_name = full_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide_name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                65_536,
                65_536,
                0,
                None,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(format!(
                "CreateNamedPipeW failed with Windows error {:?}.",
                unsafe { GetLastError() }
            ));
        }

        if let Err(error) = unsafe { ConnectNamedPipe(handle, None) } {
            if error.code() != ERROR_PIPE_CONNECTED.to_hresult() {
                let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
                return Err(format!("ConnectNamedPipe failed: {error}"));
            }
        }

        let mut client_pid = 0_u32;
        if let Err(error) = unsafe { GetNamedPipeClientProcessId(handle, &mut client_pid) } {
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
            return Err(format!("GetNamedPipeClientProcessId failed: {error}"));
        }
        if client_pid != expected_client_pid {
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
            return Err(format!(
                "Named-pipe client PID {client_pid} does not match expected Electron PID {expected_client_pid}."
            ));
        }

        let raw_handle = handle.0;
        Ok(unsafe { File::from_raw_handle(raw_handle) })
    }

    fn validate_pipe_name(name: &str) -> Result<(), String> {
        if name.len() < 16
            || name.len() > 120
            || !name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
        {
            return Err("Named-pipe name is invalid.".to_string());
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::accept_authenticated_pipe;
