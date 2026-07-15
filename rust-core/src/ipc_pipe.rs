#[cfg(target_os = "windows")]
mod windows_impl {
    use std::fs::File;
    use std::os::windows::io::FromRawHandle;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        FALSE, GetLastError, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE,
    };
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    // VS-10: explicit security descriptor for the command pipe, replacing the NULL
    // (default) DACL. SDDL:
    //   D:P                    -> DACL, Protected (no inherited ACEs)
    //   (A;;GA;;;OW)           -> GENERIC_ALL to the object OWNER (the creating user)
    //   (A;;GA;;;SY)           -> GENERIC_ALL to LOCAL SYSTEM
    //   S:(ML;;NW;;;ME)        -> mandatory MEDIUM integrity label, No-Write-Up, so a
    //                             LOWER-integrity process (e.g. a sandboxed browser
    //                             or untrusted child) cannot write to the pipe.
    // Net effect: only the owning user (and SYSTEM) at >= medium integrity can open
    // the pipe — other users and low-integrity processes are denied by the OS BEFORE
    // any bytes flow, hardening the compensating HMAC + PID checks.
    const PIPE_SDDL: &str = "D:P(A;;GA;;;OW)(A;;GA;;;SY)S:(ML;;NW;;;ME)";

    /// Build a `SECURITY_ATTRIBUTES` carrying the owner-only DACL + integrity label.
    /// The allocated security descriptor is intentionally leaked: this runs exactly
    /// once per process (the pipe is created at sidecar startup) and the OS reclaims
    /// it at exit — so we avoid the `LocalFree` dance for a one-shot allocation.
    fn build_pipe_security_attributes() -> Result<SECURITY_ATTRIBUTES, String> {
        let wide: Vec<u16> = PIPE_SDDL
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut psd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut psd,
                None,
            )
        }
        .map_err(|error| {
            format!("ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {error}")
        })?;
        Ok(SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd.0,
            bInheritHandle: FALSE,
        })
    }

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
        let security_attributes = build_pipe_security_attributes()?;
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide_name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                65_536,
                65_536,
                0,
                Some(&security_attributes as *const SECURITY_ATTRIBUTES),
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn vs10_builds_owner_only_security_descriptor() {
            // The SDDL must parse (ConvertString... returns Err on a malformed
            // descriptor) and yield a non-null, correctly-sized SECURITY_ATTRIBUTES
            // with inheritance disabled — proving the pipe no longer relies on the
            // NULL default DACL.
            let sa = build_pipe_security_attributes()
                .expect("owner-only SDDL should be valid and build a security descriptor");
            assert!(
                !sa.lpSecurityDescriptor.is_null(),
                "a real security descriptor must be allocated (not NULL/default DACL)"
            );
            assert_eq!(
                sa.nLength as usize,
                std::mem::size_of::<SECURITY_ATTRIBUTES>()
            );
            assert_eq!(sa.bInheritHandle, FALSE, "pipe handle must not be inheritable");
        }

        #[test]
        fn vs10_sddl_has_owner_system_and_integrity_label() {
            // Guard the intent of the descriptor string so a future edit can't
            // silently widen access (e.g. add Everyone) without failing a test.
            assert!(PIPE_SDDL.contains("D:P"), "DACL must be protected");
            assert!(PIPE_SDDL.contains("(A;;GA;;;OW)"), "owner full control");
            assert!(PIPE_SDDL.contains("(A;;GA;;;SY)"), "SYSTEM full control");
            assert!(PIPE_SDDL.contains("S:(ML;;NW;;;ME)"), "medium integrity, no-write-up");
            assert!(!PIPE_SDDL.contains(";;;WD)"), "must not grant Everyone (WD)");
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::accept_authenticated_pipe;
