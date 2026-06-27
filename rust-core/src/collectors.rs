use crate::models::{
    DetectionSignal, DisplayInfo, MonitorInfo, PrecheckSnapshot, PrecheckSummary, ProcessCategories,
    ProcessInfo, SystemInfo,
};
use std::env;
use sysinfo::System;
use windows::Win32::Foundation::{BOOL, LPARAM, RECT};
use windows::Win32::Graphics::Gdi::{
    EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFOEXW,
};
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;

const BROWSER_PATTERNS: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "opera.exe",
    "brave.exe",
    "safari.exe",
];
const COMMUNICATION_PATTERNS: &[&str] = &[
    "discord.exe",
    "slack.exe",
    "telegram.exe",
    "wechat.exe",
    "zalo.exe",
    "line.exe",
    "teams.exe",
    "zoom.exe",
];
const REMOTE_DESKTOP_PATTERNS: &[&str] = &[
    "mstsc.exe",
    "rdpclip.exe",
    "anydesk.exe",
    "teamviewer.exe",
    "teamviewer_service.exe",
    "rustdesk.exe",
    "vncviewer.exe",
    "vncserver.exe",
    "radmin.exe",
    "parsecd.exe",
];
const SCREEN_CAPTURE_PATTERNS: &[&str] = &[
    "obs64.exe",
    "obs32.exe",
    "bdcam.exe",
    "bandicam.exe",
    "camtasiastudio.exe",
    "snagit32.exe",
    "snagit64.exe",
    "sharex.exe",
    "streamlabs.exe",
    "xsplit.core.exe",
    "screenrec.exe",
];
const VIRTUAL_MACHINE_PATTERNS: &[&str] = &[
    "vmtoolsd.exe",
    "vmwaretray.exe",
    "vmwareuser.exe",
    "vboxservice.exe",
    "vboxtray.exe",
    "prl_tools.exe",
    "qemu-ga.exe",
];
const DEBUG_TOOLS_PATTERNS: &[&str] = &[
    "processhacker.exe",
    "procmon.exe",
    "procexp.exe",
    "windbg.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "ollydbg.exe",
    "ida64.exe",
    "ida.exe",
];
const MONITOR_PRIMARY_FLAG: u32 = 0x0000_0001;

pub fn collect_precheck_snapshot(collected_at: u64) -> PrecheckSnapshot {
    // Phase 3 only collects native information. No blocking, killing, or policy enforcement
    // should happen here, so the output stays safe to inspect from the UI.
    let system_info = collect_system_info();
    let display_info = collect_display_info();
    let process_list = collect_process_list();
    let process_categories = collect_process_categories_from_processes(&process_list);
    let vm_signals = collect_vm_signals(&system_info, &process_categories);
    let remote_signals = collect_remote_signals(&process_categories);
    let screen_capture_signals = collect_screen_capture_signals(&process_categories);
    let summary = build_precheck_summary(
        process_list.len(),
        &display_info,
        &process_categories,
        vm_signals.len(),
    );

    PrecheckSnapshot {
        collected_at,
        summary,
        system_info,
        display_info,
        process_list,
        process_categories,
        vm_signals,
        remote_signals,
        screen_capture_signals,
    }
}

pub fn collect_system_info() -> SystemInfo {
    let mut system = System::new_all();
    system.refresh_all();

    SystemInfo {
        os_name: System::name().unwrap_or_else(|| "Windows".to_string()),
        os_version: System::os_version().unwrap_or_else(|| "unknown".to_string()),
        kernel_version: System::kernel_version().unwrap_or_else(|| "unknown".to_string()),
        host_name: System::host_name().unwrap_or_else(|| "unknown".to_string()),
        architecture: env::consts::ARCH.to_string(),
        cpu_count: system.cpus().len(),
        total_memory_mb: bytes_to_mb(system.total_memory()),
        available_memory_mb: bytes_to_mb(system.available_memory()),
        uptime_seconds: System::uptime(),
        user_name: env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string()),
        system_manufacturer: read_registry_string(
            "HARDWARE\\DESCRIPTION\\System\\BIOS",
            "SystemManufacturer",
        ),
        system_product_name: read_registry_string(
            "HARDWARE\\DESCRIPTION\\System\\BIOS",
            "SystemProductName",
        ),
    }
}

pub fn collect_display_info() -> DisplayInfo {
    let mut monitors = Vec::<MonitorInfo>::new();

    unsafe extern "system" fn enum_monitor_callback(
        hmonitor: HMONITOR,
        _hdc: HDC,
        _clip_rect: *mut RECT,
        data: LPARAM,
    ) -> BOOL {
        let monitors = &mut *(data.0 as *mut Vec<MonitorInfo>);
        let mut info = MONITORINFOEXW::default();
        info.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;

        if GetMonitorInfoW(hmonitor, &mut info as *mut _ as *mut _).as_bool() {
            let device_name = utf16_to_string(&info.szDevice);
            let rect = info.monitorInfo.rcMonitor;

            monitors.push(MonitorInfo {
                device_name: if device_name.is_empty() {
                    "Unknown monitor".to_string()
                } else {
                    device_name
                },
                width: rect.right - rect.left,
                height: rect.bottom - rect.top,
                offset_x: rect.left,
                offset_y: rect.top,
                is_primary: (info.monitorInfo.dwFlags & MONITOR_PRIMARY_FLAG) != 0,
            });
        }

        true.into()
    }

    unsafe {
        let data = LPARAM((&mut monitors as *mut Vec<MonitorInfo>) as isize);
        let _ = EnumDisplayMonitors(HDC(std::ptr::null_mut()), None, Some(enum_monitor_callback), data);
    }

    DisplayInfo {
        monitor_count: monitors.len(),
        monitors,
    }
}

pub fn collect_process_list() -> Vec<ProcessInfo> {
    let mut system = System::new_all();
    system.refresh_all();

    let mut processes = system
        .processes()
        .values()
        .map(|process| {
            let name = process.name().to_string();
            ProcessInfo {
                pid: process.pid().as_u32(),
                name: name.clone(),
                executable_path: process.exe().map(|path| path.display().to_string()),
                memory_mb: bytes_to_mb(process.memory()),
                categories: categorize_process(&name),
            }
        })
        .collect::<Vec<_>>();

    processes.sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));
    processes
}

pub fn collect_process_categories_from_processes(processes: &[ProcessInfo]) -> ProcessCategories {
    ProcessCategories {
        browser: filter_process_category(processes, "browser"),
        communication: filter_process_category(processes, "communication"),
        remote_desktop: filter_process_category(processes, "remoteDesktop"),
        screen_capture: filter_process_category(processes, "screenCapture"),
        virtual_machine: filter_process_category(processes, "virtualMachine"),
        debug_tools: filter_process_category(processes, "debugTools"),
    }
}

pub fn collect_vm_signals(
    system_info: &SystemInfo,
    process_categories: &ProcessCategories,
) -> Vec<DetectionSignal> {
    let mut signals = Vec::new();

    if let Some(manufacturer) = system_info.system_manufacturer.as_ref() {
        let normalized = manufacturer.to_lowercase();
        if contains_vm_vendor(&normalized) {
            signals.push(DetectionSignal {
                id: "vm-manufacturer".to_string(),
                label: "Virtual machine manufacturer".to_string(),
                detail: manufacturer.clone(),
                severity: "warn".to_string(),
                source: "registry".to_string(),
            });
        }
    }

    if let Some(product_name) = system_info.system_product_name.as_ref() {
        let normalized = product_name.to_lowercase();
        if contains_vm_vendor(&normalized) {
            signals.push(DetectionSignal {
                id: "vm-product".to_string(),
                label: "Virtual machine product".to_string(),
                detail: product_name.clone(),
                severity: "warn".to_string(),
                source: "registry".to_string(),
            });
        }
    }

    for process in &process_categories.virtual_machine {
        signals.push(DetectionSignal {
            id: format!("vm-process-{}", process.pid),
            label: "Virtualization process".to_string(),
            detail: format!("{} (pid {})", process.name, process.pid),
            severity: "warn".to_string(),
            source: "process".to_string(),
        });
    }

    signals
}

pub fn collect_remote_signals(process_categories: &ProcessCategories) -> Vec<DetectionSignal> {
    let mut signals = process_categories
        .remote_desktop
        .iter()
        .map(|process| DetectionSignal {
            id: format!("remote-process-{}", process.pid),
            label: "Remote access process".to_string(),
            detail: format!("{} (pid {})", process.name, process.pid),
            severity: "warn".to_string(),
            source: "process".to_string(),
        })
        .collect::<Vec<_>>();

    if let Ok(session_name) = env::var("SESSIONNAME") {
        if session_name.to_ascii_uppercase().starts_with("RDP-") {
            signals.push(DetectionSignal {
                id: "remote-session-name".to_string(),
                label: "Remote desktop session".to_string(),
                detail: session_name,
                severity: "warn".to_string(),
                source: "environment".to_string(),
            });
        }
    }

    signals
}

pub fn collect_screen_capture_signals(
    process_categories: &ProcessCategories,
) -> Vec<DetectionSignal> {
    process_categories
        .screen_capture
        .iter()
        .map(|process| DetectionSignal {
            id: format!("capture-process-{}", process.pid),
            label: "Screen capture process".to_string(),
            detail: format!("{} (pid {})", process.name, process.pid),
            severity: "info".to_string(),
            source: "process".to_string(),
        })
        .collect()
}

fn build_precheck_summary(
    total_process_count: usize,
    display_info: &DisplayInfo,
    process_categories: &ProcessCategories,
    vm_signal_count: usize,
) -> PrecheckSummary {
    PrecheckSummary {
        total_process_count,
        monitor_count: display_info.monitor_count,
        browser_app_count: process_categories.browser.len(),
        remote_app_count: process_categories.remote_desktop.len(),
        screen_capture_app_count: process_categories.screen_capture.len(),
        vm_signal_count,
    }
}

fn filter_process_category(processes: &[ProcessInfo], category: &str) -> Vec<ProcessInfo> {
    processes
        .iter()
        .filter(|process| process.categories.iter().any(|entry| entry == category))
        .cloned()
        .collect()
}

fn categorize_process(name: &str) -> Vec<String> {
    let normalized = name.to_lowercase();
    let mut categories = Vec::new();

    if matches_any_pattern(&normalized, BROWSER_PATTERNS) {
        categories.push("browser".to_string());
    }
    if matches_any_pattern(&normalized, COMMUNICATION_PATTERNS) {
        categories.push("communication".to_string());
    }
    if matches_any_pattern(&normalized, REMOTE_DESKTOP_PATTERNS) {
        categories.push("remoteDesktop".to_string());
    }
    if matches_any_pattern(&normalized, SCREEN_CAPTURE_PATTERNS) {
        categories.push("screenCapture".to_string());
    }
    if matches_any_pattern(&normalized, VIRTUAL_MACHINE_PATTERNS) {
        categories.push("virtualMachine".to_string());
    }
    if matches_any_pattern(&normalized, DEBUG_TOOLS_PATTERNS) {
        categories.push("debugTools".to_string());
    }

    categories
}

fn matches_any_pattern(name: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| name.contains(pattern))
}

fn contains_vm_vendor(value: &str) -> bool {
    value.contains("vmware")
        || value.contains("virtualbox")
        || value.contains("virtual box")
        || value.contains("hyper-v")
        || value.contains("kvm")
        || value.contains("qemu")
        || value.contains("parallels")
}

fn read_registry_string(path: &str, value_name: &str) -> Option<String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey(path).ok()?;
    let value: String = key.get_value(value_name).ok()?;

    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn utf16_to_string(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|value| *value == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

fn bytes_to_mb(bytes: u64) -> u64 {
    bytes / (1024 * 1024)
}
