mod authorization;
mod transport;

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult,
};
use windows_service::service_dispatcher;

const SERVICE_NAME: &str = "EduLearnExamGuard";

// Early boot logging — a service has no console, and a hang before
// set_service_status(Running) is otherwise invisible (StartPending forever). We
// append synchronously to a file SYSTEM can always write so we can see exactly
// how far startup got. Never panics.
fn boot_log(stage: &str) {
    use std::io::Write;
    let base = std::env::var_os("PROGRAMDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData"));
    let dir = base.join("Edulearn").join("ExamGuard");
    let _ = std::fs::create_dir_all(&dir);
    let primary = dir.join("service-boot.log");
    let fallback = std::path::PathBuf::from(r"C:\Windows\Temp\edulearn-exam-service-boot.log");
    let line = format!(
        "{} pid={} {}\n",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
        std::process::id(),
        stage,
    );
    for path in [primary, fallback] {
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = file.write_all(line.as_bytes());
            break;
        }
    }
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    boot_log("service_main entered");
    if let Err(error) = run_service() {
        boot_log(&format!("run_service returned Err: {error}"));
        eprintln!("EduLearn Exam Guard service failed: {error}");
    } else {
        boot_log("run_service returned Ok");
    }
}

fn run_service() -> windows_service::Result<()> {
    boot_log("run_service: loading config");
    let config = transport::load_service_config().map_err(|error| {
        boot_log(&format!("load_service_config FAILED: {error}"));
        windows_service::Error::Winapi(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error,
        ))
    })?;
    boot_log("run_service: config loaded, registering control handler");
    let (stop_sender, stop_receiver) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let handler_stop = Arc::clone(&stop);
    let status_handle = service_control_handler::register(
        SERVICE_NAME,
        move |control| match control {
            ServiceControl::Stop => {
                handler_stop.store(true, Ordering::Release);
                let _ = stop_sender.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        },
    )?;
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    boot_log("run_service: set state RUNNING; starting transport");

    let transport_stop = Arc::clone(&stop);
    let transport_thread = std::thread::Builder::new()
        .name("edulearn-service-transport".to_string())
        .spawn(move || transport::run_transport(config, transport_stop))
        .map_err(windows_service::Error::Winapi)?;

    loop {
        match stop_receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if transport_thread.is_finished() {
                    stop.store(true, Ordering::Release);
                    break;
                }
            }
        }
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    })?;
    match transport_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("EduLearn service transport stopped: {error}"),
        Err(_) => eprintln!("EduLearn service transport thread panicked during shutdown."),
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    Ok(())
}

fn main() -> windows_service::Result<()> {
    boot_log("main: calling service_dispatcher::start");
    let result = service_dispatcher::start(SERVICE_NAME, ffi_service_main);
    if let Err(ref error) = result {
        boot_log(&format!("service_dispatcher::start FAILED: {error}"));
    }
    result
}
