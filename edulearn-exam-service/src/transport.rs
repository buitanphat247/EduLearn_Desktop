use crate::authorization::{ElevatedTerminationRequest, ServiceAuthorizer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, HANDLE, HLOCAL, ERROR_PIPE_CONNECTED,
    INVALID_HANDLE_VALUE,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PeekNamedPipe,
    PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::IO::CancelSynchronousIo;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};

const PIPE_PATH: &str = r"\\.\pipe\EduLearnExamGuardService";
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const PIPE_READ_IDLE_TIMEOUT_MS: u64 = 5_000;
const PIPE_POLL_INTERVAL_MS: u64 = 25;
const PIPE_ACCEPT_STOP_POLL_MS: u64 = 250;
const PIPE_STOP_NUDGE_TIMEOUT_MS: u64 = 1_000;
const MAX_ACTIVE_CLIENTS: usize = 32;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceConfig {
    pub trusted_server_keys: std::collections::BTreeMap<String, String>,
    pub allowed_client_path: String,
    pub allowed_client_sha256: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceResponse {
    ok: bool,
    code: String,
    message: String,
    target_pid: Option<u32>,
}

pub fn load_service_config() -> Result<ServiceConfig, String> {
    let path = std::env::var_os("EDULEARN_EXAM_SERVICE_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let base = std::env::var_os("PROGRAMDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
            base.join("Edulearn")
                .join("ExamGuard")
                .join("service-config.json")
        });
    let bytes =
        fs::read(&path).map_err(|error| format!("Unable to read {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("Service configuration is too large.".to_string());
    }
    let config: ServiceConfig = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Service configuration is invalid: {error}"))?;
    if config.allowed_client_sha256.len() != 64
        || !config
            .allowed_client_sha256
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        || config.allowed_client_path.trim().is_empty()
    {
        return Err("Service client identity configuration is invalid.".to_string());
    }
    Ok(config)
}

pub fn run_transport(
    config: ServiceConfig,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let authorizer = Arc::new(Mutex::new(ServiceAuthorizer::from_base64_keys(
        config.trusted_server_keys.clone(),
    )?));
    let active_clients = Arc::new(AtomicUsize::new(0));
    let mut client_workers = Vec::new();
    while !stop.load(Ordering::Acquire) {
        reap_finished_workers(&mut client_workers);
        match accept_loop_decision(
            stop.load(Ordering::Acquire),
            active_clients.load(Ordering::Acquire),
        ) {
            AcceptLoopDecision::Stop => break,
            AcceptLoopDecision::Backoff => {
                std::thread::sleep(std::time::Duration::from_millis(PIPE_ACCEPT_STOP_POLL_MS));
                continue;
            }
            AcceptLoopDecision::Accept => {}
        }
        let Some(pipe) = create_and_connect_pipe(&stop)? else {
            break;
        };
        let config = config.clone();
        let authorizer = Arc::clone(&authorizer);
        let active_clients_for_thread = Arc::clone(&active_clients);
        active_clients.fetch_add(1, Ordering::AcqRel);
        let worker = std::thread::Builder::new()
            .name("edulearn-service-client".to_string())
            .spawn(move || {
                let _active_client = ActiveClientGuard::new(active_clients_for_thread);
                if let Err(error) = handle_client(pipe, &config, &authorizer) {
                    eprintln!("EduLearn service rejected request: {error}");
                }
            });
        match worker {
            Ok(worker) => client_workers.push(worker),
            Err(error) => {
                active_clients.fetch_sub(1, Ordering::AcqRel);
                return Err(format!("Unable to start service client worker: {error}"));
            }
        }
    }
    for worker in client_workers {
        let _ = worker.join();
    }
    Ok(())
}

struct ActiveClientGuard {
    active_clients: Arc<AtomicUsize>,
}

impl ActiveClientGuard {
    fn new(active_clients: Arc<AtomicUsize>) -> Self {
        Self { active_clients }
    }
}

impl Drop for ActiveClientGuard {
    fn drop(&mut self) {
        self.active_clients.fetch_sub(1, Ordering::AcqRel);
    }
}

fn reap_finished_workers(workers: &mut Vec<std::thread::JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            let _ = worker.join();
        } else {
            index += 1;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptLoopDecision {
    Accept,
    Backoff,
    Stop,
}

fn accept_loop_decision(stop_requested: bool, active_clients: usize) -> AcceptLoopDecision {
    if stop_requested {
        return AcceptLoopDecision::Stop;
    }
    if active_clients >= MAX_ACTIVE_CLIENTS {
        return AcceptLoopDecision::Backoff;
    }
    AcceptLoopDecision::Accept
}

fn create_pipe_instance() -> Result<File, String> {
    struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                let _ = unsafe { LocalFree(HLOCAL(self.0.0 as *mut core::ffi::c_void)) };
            }
        }
    }

    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            // SYSTEM and Administrators get full control; authenticated users
            // can connect, but every request is still path/hash/signature
            // authorized before any elevated action runs.
            w!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|error| format!("Pipe security descriptor is invalid: {error}"))?;
    let _descriptor_guard = SecurityDescriptor(descriptor);
    let mut security_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.cast(),
        bInheritHandle: false.into(),
    };
    let wide = PIPE_PATH
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(wide.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65_536,
            65_536,
            PIPE_READ_IDLE_TIMEOUT_MS as u32,
            Some(&mut security_attributes),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "CreateNamedPipeW failed: {:?}",
            unsafe { GetLastError() }
        ));
    }
    Ok(unsafe { File::from_raw_handle(handle.0) })
}

fn connect_pipe(pipe: File) -> Result<File, String> {
    if let Err(error) = unsafe {
        ConnectNamedPipe(
            windows::Win32::Foundation::HANDLE(pipe.as_raw_handle()),
            None,
        )
    } {
        if error.code() != ERROR_PIPE_CONNECTED.to_hresult() {
            return Err(format!("ConnectNamedPipe failed: {error}"));
        }
    }
    Ok(pipe)
}

fn nudge_pipe_accept() {
    let _ = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(PIPE_PATH);
}

fn create_and_connect_pipe(stop: &Arc<AtomicBool>) -> Result<Option<File>, String> {
    let pipe = create_pipe_instance()?;
    let (tx, rx) = mpsc::channel();
    let mut worker = Some(
        std::thread::Builder::new()
            .name("edulearn-service-pipe-accept".to_string())
            .spawn(move || {
                let _ = tx.send(connect_pipe(pipe));
            })
            .map_err(|error| format!("Unable to start pipe accept worker: {error}"))?,
    );

    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(PIPE_ACCEPT_STOP_POLL_MS)) {
            Ok(result) => {
                if let Some(worker) = worker.take() {
                    let _ = worker.join();
                }
                return result.map(Some);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if let Some(worker) = worker.take() {
                    let _ = worker.join();
                }
                return Err("Pipe accept worker disconnected.".to_string());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if stop.load(Ordering::Acquire) {
                    let cancel_result = worker
                        .as_ref()
                        .ok_or_else(|| "Pipe accept worker is unavailable.".to_string())
                        .and_then(|worker| {
                            unsafe { CancelSynchronousIo(HANDLE(worker.as_raw_handle())) }
                                .map_err(|error| {
                                    format!(
                                        "CancelSynchronousIo for pipe accept failed: {error}"
                                    )
                                })
                        });
                    if cancel_result.is_err() {
                        nudge_pipe_accept();
                    }
                    match rx.recv_timeout(std::time::Duration::from_millis(
                        PIPE_STOP_NUDGE_TIMEOUT_MS,
                    )) {
                        Ok(_) => {
                            if let Some(worker) = worker.take() {
                                let _ = worker.join();
                            }
                            return Ok(None);
                        }
                        Err(_) => {
                            return Err(
                                "Timed out while cancelling pending named-pipe accept."
                                    .to_string(),
                            )
                        }
                    }
                }
            }
        }
    }
}

fn handle_client(
    pipe: File,
    config: &ServiceConfig,
    authorizer: &Arc<Mutex<ServiceAuthorizer>>,
) -> Result<(), String> {
    let mut client_pid = 0_u32;
    unsafe { GetNamedPipeClientProcessId(windows::Win32::Foundation::HANDLE(pipe.as_raw_handle()), &mut client_pid) }
        .map_err(|error| format!("GetNamedPipeClientProcessId failed: {error}"))?;
    verify_client_identity(client_pid, config)?;

    let reader_pipe = pipe
        .try_clone()
        .map_err(|error| format!("Unable to clone service pipe: {error}"))?;
    let mut writer = BufWriter::new(pipe);
    let line = read_request_line_with_timeout(reader_pipe, PIPE_READ_IDLE_TIMEOUT_MS)?;
    let request: ElevatedTerminationRequest = serde_json::from_str(&line)
        .map_err(|error| format!("Service request JSON is invalid: {error}"))?;
    let target = open_target(request.target_pid)?;
    let process_name = target
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "Target process executable name is unavailable.".to_string())?;
    authorizer
        .lock()
        .map_err(|_| "Service authorizer lock is poisoned.".to_string())?
        .authorize_termination(
            &request,
            process_name,
            now_ms(),
            std::process::id(),
        )?;
    unsafe { TerminateProcess(target.handle, 1) }
        .map_err(|error| format!("Elevated TerminateProcess failed: {error}"))?;
    let response = ServiceResponse {
        ok: true,
        code: "PROCESS_TERMINATED".to_string(),
        message: format!("{process_name} was terminated by signed exam policy."),
        target_pid: Some(request.target_pid),
    };
    serde_json::to_writer(&mut writer, &response)
        .map_err(|error| format!("Unable to serialize service response: {error}"))?;
    writer
        .write_all(b"\n")
        .and_then(|_| writer.flush())
        .map_err(|error| format!("Unable to write service response: {error}"))
}

use std::os::windows::io::AsRawHandle;

fn read_request_line_with_timeout(mut pipe: File, timeout_ms: u64) -> Result<String, String> {
    let started_at = std::time::Instant::now();
    let mut buffer = Vec::<u8>::new();

    loop {
        if buffer.len() as u64 > MAX_REQUEST_BYTES {
            return Err("Service request exceeded 1 MiB.".to_string());
        }
        if started_at.elapsed().as_millis() as u64 > timeout_ms {
            return Err("Timed out waiting for a complete service request.".to_string());
        }

        let mut available = 0_u32;
        unsafe {
            PeekNamedPipe(
                windows::Win32::Foundation::HANDLE(pipe.as_raw_handle()),
                None,
                0,
                None,
                Some(&mut available),
                None,
            )
        }
        .map_err(|error| format!("PeekNamedPipe failed: {error}"))?;

        if available == 0 {
            std::thread::sleep(std::time::Duration::from_millis(PIPE_POLL_INTERVAL_MS));
            continue;
        }

        let mut chunk = vec![0_u8; available.min(8192) as usize];
        let bytes_read = pipe
            .read(&mut chunk)
            .map_err(|error| format!("Unable to read service request: {error}"))?;
        if bytes_read == 0 {
            return Err("Service client disconnected before sending a request.".to_string());
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);
        if let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
            buffer.truncate(newline);
            return String::from_utf8(buffer)
                .map_err(|error| format!("Service request is not valid UTF-8: {error}"));
        }
    }
}

struct TargetProcess {
    handle: windows::Win32::Foundation::HANDLE,
    path: PathBuf,
}

impl Drop for TargetProcess {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

fn open_target(pid: u32) -> Result<TargetProcess, String> {
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            false,
            pid,
        )
    }
    .map_err(|error| format!("OpenProcess failed for pid {pid}: {error}"))?;
    let path = query_process_path(handle)?;
    Ok(TargetProcess { handle, path })
}

fn query_process_path(
    handle: windows::Win32::Foundation::HANDLE,
) -> Result<PathBuf, String> {
    let mut buffer = vec![0_u16; 32_768];
    let mut length = buffer.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    }
    .map_err(|error| format!("QueryFullProcessImageNameW failed: {error}"))?;
    buffer.truncate(length as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
}

fn verify_client_identity(pid: u32, config: &ServiceConfig) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(|error| format!("Unable to open service client pid {pid}: {error}"))?;
    let path = query_process_path(handle);
    let _ = unsafe { CloseHandle(handle) };
    let path = path?;
    let expected = fs::canonicalize(&config.allowed_client_path)
        .map_err(|error| format!("Configured client path is invalid: {error}"))?;
    let actual = fs::canonicalize(&path)
        .map_err(|error| format!("Service client path is invalid: {error}"))?;
    if !paths_equal(&expected, &actual) {
        return Err("Named-pipe client executable path is not authorized.".to_string());
    }
    let bytes = fs::read(&actual)
        .map_err(|error| format!("Unable to hash service client: {error}"))?;
    let hash = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if !hash.eq_ignore_ascii_case(&config.allowed_client_sha256) {
        return Err("Named-pipe client executable hash is not authorized.".to_string());
    }
    Ok(())
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        accept_loop_decision, ActiveClientGuard, AcceptLoopDecision, MAX_ACTIVE_CLIENTS,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn accept_loop_stops_immediately_when_stop_is_requested() {
        assert_eq!(accept_loop_decision(true, 0), AcceptLoopDecision::Stop);
    }

    #[test]
    fn accept_loop_backs_off_when_client_limit_is_reached() {
        assert_eq!(
            accept_loop_decision(false, MAX_ACTIVE_CLIENTS),
            AcceptLoopDecision::Backoff,
        );
    }

    #[test]
    fn accept_loop_accepts_when_running_under_limit() {
        assert_eq!(
            accept_loop_decision(false, MAX_ACTIVE_CLIENTS - 1),
            AcceptLoopDecision::Accept,
        );
    }

    #[test]
    fn active_client_slot_is_released_by_raii() {
        let active_clients = Arc::new(AtomicUsize::new(1));
        {
            let _guard = ActiveClientGuard::new(Arc::clone(&active_clients));
        }
        assert_eq!(active_clients.load(Ordering::Acquire), 0);
    }
}
