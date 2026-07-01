use crate::exam_key::ElevatedTerminationRequest;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceResponse {
    ok: bool,
    code: String,
    message: String,
    target_pid: Option<u32>,
}

#[cfg(target_os = "windows")]
pub fn request_elevated_termination(
    request: &ElevatedTerminationRequest,
) -> Result<String, String> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::IO::CancelSynchronousIo;

    let request = request.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::Builder::new()
        .name("edulearn-service-request".to_string())
        .spawn(move || {
            let _ = tx.send(request_elevated_termination_blocking(&request));
        })
        .map_err(|error| format!("Unable to start Exam Guard service request: {error}"))?;

    match rx.recv_timeout(std::time::Duration::from_millis(
        service_client_response_timeout_ms(),
    )) {
        Ok(result) => {
            let _ = worker.join();
            result
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let cancellation =
                unsafe { CancelSynchronousIo(HANDLE(worker.as_raw_handle())) };
            if cancellation.is_ok() {
                let _ = rx.recv_timeout(std::time::Duration::from_secs(1));
                let _ = worker.join();
            }
            Err(format!(
                "Exam Guard service did not respond within {}ms; synchronous pipe I/O cancellation status={}.",
                service_client_response_timeout_ms(),
                cancellation.is_ok()
            ))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            let _ = worker.join();
            Err("Exam Guard service request worker stopped unexpectedly.".to_string())
        }
    }
}

#[cfg(target_os = "windows")]
fn service_client_response_timeout_ms() -> u64 {
    std::env::var("EDULEARN_EXAM_SERVICE_CLIENT_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (500..=60_000).contains(value))
        .unwrap_or(5_000)
}

#[cfg(target_os = "windows")]
fn request_elevated_termination_blocking(
    request: &ElevatedTerminationRequest,
) -> Result<String, String> {
    use std::fs::File;
    use std::io::{BufRead, BufReader, BufWriter, Write};
    use std::os::windows::io::FromRawHandle;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, OPEN_EXISTING,
    };

    let pipe_name = r"\\.\pipe\EduLearnExamGuardService";
    let wide = pipe_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            (GENERIC_READ | GENERIC_WRITE).0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|error| format!("Exam Guard service is unavailable: {error}"))?;
    if handle == INVALID_HANDLE_VALUE {
        let _ = unsafe { CloseHandle(handle) };
        return Err("Exam Guard service returned an invalid pipe handle.".to_string());
    }
    let file = unsafe { File::from_raw_handle(handle.0) };
    let reader_file = file
        .try_clone()
        .map_err(|error| format!("Unable to clone service pipe: {error}"))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, request)
        .map_err(|error| format!("Unable to encode service request: {error}"))?;
    writer
        .write_all(b"\n")
        .and_then(|_| writer.flush())
        .map_err(|error| format!("Unable to write service request: {error}"))?;
    let mut reader = BufReader::new(reader_file);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|error| format!("Unable to read service response: {error}"))?;
    let response: ServiceResponse = serde_json::from_str(&line)
        .map_err(|error| format!("Service response is invalid: {error}"))?;
    if !response.ok || response.target_pid != Some(request.target_pid) {
        return Err(format!("{}: {}", response.code, response.message));
    }
    Ok(response.message)
}

#[cfg(not(target_os = "windows"))]
pub fn request_elevated_termination(
    _request: &ElevatedTerminationRequest,
) -> Result<String, String> {
    Err("Exam Guard service is only supported on Windows.".to_string())
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::service_client_response_timeout_ms;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn service_client_timeout_uses_safe_default() {
        let _guard = env_lock().lock().unwrap();
        std::env::remove_var("EDULEARN_EXAM_SERVICE_CLIENT_TIMEOUT_MS");
        assert_eq!(service_client_response_timeout_ms(), 5_000);
    }

    #[test]
    fn service_client_timeout_rejects_extreme_values() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("EDULEARN_EXAM_SERVICE_CLIENT_TIMEOUT_MS", "1");
        assert_eq!(service_client_response_timeout_ms(), 5_000);

        std::env::set_var("EDULEARN_EXAM_SERVICE_CLIENT_TIMEOUT_MS", "1000");
        assert_eq!(service_client_response_timeout_ms(), 1_000);
        std::env::remove_var("EDULEARN_EXAM_SERVICE_CLIENT_TIMEOUT_MS");
    }
}
