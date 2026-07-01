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

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        eprintln!("EduLearn Exam Guard service failed: {error}");
    }
}

fn run_service() -> windows_service::Result<()> {
    let config = transport::load_service_config().map_err(|error| {
        windows_service::Error::Winapi(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error,
        ))
    })?;
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
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}
