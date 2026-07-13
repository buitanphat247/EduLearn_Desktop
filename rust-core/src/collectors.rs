use crate::models::{
    DetectionSignal, DisplayInfo, ExecutableIdentity, MonitorInfo, PrecheckSnapshot,
    PrecheckSummary, ProcessCategories, ProcessInfo, SystemInfo,
};
use crate::process_policy::{
    categorize_process_with_identity, contains_vm_vendor, CATEGORY_BROWSER,
    CATEGORY_COMMUNICATION, CATEGORY_DEBUG_TOOLS, CATEGORY_POLICY_BLOCKED,
    CATEGORY_REMOTE_DESKTOP, CATEGORY_SCREEN_CAPTURE, CATEGORY_VIRTUAL_MACHINE,
};
use crate::policy_model::ExamPolicy;
use std::env;
use std::ffi::c_void;
use sysinfo::{ProcessRefreshKind, System, UpdateKind};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{BOOL, LPARAM, RECT};
use windows::Win32::Graphics::Gdi::{
    EnumDisplayDevicesW, EnumDisplayMonitors, GetMonitorInfoW, DISPLAY_DEVICEW,
    DISPLAY_DEVICE_MIRRORING_DRIVER, HDC, HMONITOR, MONITORINFOEXW,
};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GetExtendedTcpTable, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH, MIB_TCPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_REMOTESESSION};
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;

const MONITOR_PRIMARY_FLAG: u32 = 0x0000_0001;

#[derive(Debug)]
pub struct ProcessCollector {
    system: System,
}

impl ProcessCollector {
    pub fn new() -> Self {
        Self {
            system: System::new(),
        }
    }

    pub fn collect_with_policy(&mut self, policy: &ExamPolicy) -> Vec<ProcessInfo> {
        self.system.refresh_processes_specifics(
            ProcessRefreshKind::new()
                .with_memory()
                .with_exe(UpdateKind::OnlyIfNotSet),
        );

        build_process_list(&self.system, policy)
    }
}

pub fn collect_precheck_snapshot_with_policy(
    collected_at: u64,
    policy: &ExamPolicy,
) -> PrecheckSnapshot {
    // Phase 3 only collects native information. No blocking, killing, or policy enforcement
    // should happen here, so the output stays safe to inspect from the UI.
    let system_info = collect_system_info();
    let display_info = collect_display_info();
    let process_list = ProcessCollector::new().collect_with_policy(policy);
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

fn build_process_list(system: &System, policy: &ExamPolicy) -> Vec<ProcessInfo> {
    let mut processes = system
        .processes()
        .values()
        .map(|process| {
            let name = process.name().to_string();
            let executable_path = process.exe().map(|path| path.display().to_string());
            let identity = executable_path
                .as_deref()
                .and_then(read_executable_identity);
            let categories = categorize_process_with_identity(&name, identity.as_ref(), policy);
            ProcessInfo {
                pid: process.pid().as_u32(),
                name,
                executable_path,
                creation_time_ms: Some(process.start_time().saturating_mul(1_000)),
                memory_mb: bytes_to_mb(process.memory()),
                categories,
                identity,
            }
        })
        .collect::<Vec<_>>();

    processes.sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));
    processes
}

/// Read the `OriginalFilename` and `CompanyName` from an executable's Win32
/// version-info resource. Best-effort: any failure (missing resource, unreadable
/// file, no string table) yields `None` so callers fall back to name-only checks.
pub(crate) fn read_executable_identity(path: &str) -> Option<ExecutableIdentity> {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let filename = PCWSTR(wide.as_ptr());

    unsafe {
        let size = GetFileVersionInfoSizeW(filename, None);
        if size == 0 {
            return None;
        }

        let mut buffer = aligned_byte_buffer(size as usize);
        GetFileVersionInfoW(filename, 0, size, buffer.as_mut_ptr() as *mut c_void).ok()?;

        let sub_block = version_translation(&buffer);
        let original_filename = version_query_string(&buffer, &sub_block, "OriginalFilename");
        let company_name = version_query_string(&buffer, &sub_block, "CompanyName");
        if original_filename.is_none() && company_name.is_none() {
            return None;
        }

        Some(ExecutableIdentity {
            original_filename,
            company_name,
        })
    }
}

/// Resolve the first `language/codepage` translation into the hex sub-block used
/// by `\StringFileInfo\<lang><codepage>\...` queries. Falls back to US-English
/// Unicode (`040904b0`) when no translation table is present.
unsafe fn version_translation(buffer: &[u64]) -> String {
    const FALLBACK: &str = "040904b0";
    let query: Vec<u16> = "\\VarFileInfo\\Translation"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut value_ptr: *mut c_void = std::ptr::null_mut();
    let mut value_len: u32 = 0;

    let ok = VerQueryValueW(
        buffer.as_ptr() as *const c_void,
        PCWSTR(query.as_ptr()),
        &mut value_ptr,
        &mut value_len,
    );
    if !ok.as_bool() || value_ptr.is_null() || value_len < 4 {
        return FALLBACK.to_string();
    }

    let language = *(value_ptr as *const u16);
    let codepage = *((value_ptr as *const u16).add(1));
    format!("{language:04x}{codepage:04x}")
}

unsafe fn version_query_string(buffer: &[u64], sub_block: &str, field: &str) -> Option<String> {
    let query = format!("\\StringFileInfo\\{sub_block}\\{field}");
    let wide: Vec<u16> = query.encode_utf16().chain(std::iter::once(0)).collect();
    let mut value_ptr: *mut c_void = std::ptr::null_mut();
    let mut value_len: u32 = 0;

    let ok = VerQueryValueW(
        buffer.as_ptr() as *const c_void,
        PCWSTR(wide.as_ptr()),
        &mut value_ptr,
        &mut value_len,
    );
    if !ok.as_bool() || value_ptr.is_null() || value_len == 0 {
        return None;
    }

    let chars = std::slice::from_raw_parts(value_ptr as *const u16, value_len as usize);
    let text = String::from_utf16_lossy(chars);
    let trimmed = text.trim_end_matches('\0').trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub fn collect_process_categories_from_processes(processes: &[ProcessInfo]) -> ProcessCategories {
    ProcessCategories {
        browser: filter_process_category(processes, CATEGORY_BROWSER),
        communication: filter_process_category(processes, CATEGORY_COMMUNICATION),
        policy_blocked: filter_process_category(processes, CATEGORY_POLICY_BLOCKED),
        remote_desktop: filter_process_category(processes, CATEGORY_REMOTE_DESKTOP),
        screen_capture: filter_process_category(processes, CATEGORY_SCREEN_CAPTURE),
        virtual_machine: filter_process_category(processes, CATEGORY_VIRTUAL_MACHINE),
        debug_tools: filter_process_category(processes, CATEGORY_DEBUG_TOOLS),
    }
}

pub fn collect_vm_signals(
    system_info: &SystemInfo,
    process_categories: &ProcessCategories,
) -> Vec<DetectionSignal> {
    let mut signals = Vec::new();

    signals.extend(collect_hypervisor_signals());
    signals.extend(collect_mac_vm_signals());

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

/// Full remote-access signal set (session + environment). Used by the one-shot
/// precheck snapshot. The runtime tick uses the cheap `collect_remote_session_signals`
/// every tick and the expensive `collect_remote_environment_signals` only on the
/// slow (cached) environment scan — see the runtime monitor.
pub fn collect_remote_signals(process_categories: &ProcessCategories) -> Vec<DetectionSignal> {
    let mut signals = collect_remote_session_signals(process_categories);
    signals.extend(collect_remote_environment_signals());
    signals
}

/// Cheap remote-access signals safe to compute on every runtime tick: prohibited
/// remote-desktop processes plus native RDP session detection (`SESSIONNAME`,
/// `SM_REMOTESESSION`).
pub fn collect_remote_session_signals(
    process_categories: &ProcessCategories,
) -> Vec<DetectionSignal> {
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

    if unsafe { GetSystemMetrics(SM_REMOTESESSION) } != 0 {
        signals.push(DetectionSignal {
            id: "remote-session-win32".to_string(),
            label: "Remote desktop session".to_string(),
            detail: "Win32 SM_REMOTESESSION indicates the current session is remote.".to_string(),
            severity: "warn".to_string(),
            source: "win32".to_string(),
        });
    }

    signals
}

/// Expensive remote-access signals that enumerate OS state (TCP port table +
/// mirror display drivers). Catches TeamViewer/AnyDesk/RustDesk/Parsec that
/// native RDP checks miss. Cached between slow environment scans by the caller.
pub fn collect_remote_environment_signals() -> Vec<DetectionSignal> {
    let mut signals = collect_remote_port_signals();
    signals.extend(collect_mirror_driver_signals());
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

// ---------------------------------------------------------------------------
// VM / remote-tool detection (Sprint 1.2 / 1.3)
//
// The pure classifier functions below are unit-tested; the `collect_*` wrappers
// pull the raw signals from Windows and are best-effort (any failure yields no
// signal rather than a hard error).
// ---------------------------------------------------------------------------

/// Map a CPUID hypervisor-vendor string (leaf 0x40000000) to a product name.
///
/// `Microsoft Hv` is intentionally NOT matched: Windows 11 VBS/HVCI sets the
/// hypervisor-present bit on physical machines too, so trusting it would
/// false-positive on hardened bare-metal exam machines.
fn hypervisor_vendor_label(vendor: &str) -> Option<&'static str> {
    let vendor = vendor.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    if vendor.contains("VMware") {
        Some("VMware")
    } else if vendor.contains("VBox") {
        Some("VirtualBox")
    } else if vendor.contains("KVM") {
        Some("KVM")
    } else if vendor.contains("XenVMM") {
        Some("Xen")
    } else if vendor.contains("prl") {
        Some("Parallels")
    } else if vendor.contains("TCG") {
        Some("QEMU")
    } else {
        None
    }
}

/// Map the OUI (first three bytes) of a MAC address to a virtualization vendor.
fn mac_oui_vendor(mac: &[u8]) -> Option<&'static str> {
    if mac.len() < 3 {
        return None;
    }
    match [mac[0], mac[1], mac[2]] {
        [0x00, 0x05, 0x69] | [0x00, 0x0C, 0x29] | [0x00, 0x50, 0x56] | [0x00, 0x1C, 0x14] => {
            Some("VMware")
        }
        [0x08, 0x00, 0x27] | [0x0A, 0x00, 0x27] => Some("VirtualBox"),
        [0x00, 0x16, 0x3E] => Some("Xen"),
        [0x00, 0x1C, 0x42] => Some("Parallels"),
        // NOTE: Hyper-V's 00:15:5D and QEMU/KVM's 52:54:00 OUIs are deliberately
        // NOT matched: the Hyper-V virtual-switch adapter is present on any
        // physical Windows box running WSL2/Docker/VBS, and 52:54:00 appears on
        // legitimate hardware — flagging them would false-positive on real exam
        // machines (consistent with excluding "Microsoft Hv" from the CPUID path).
        _ => None,
    }
}

/// Map a listening/active TCP port to the remote-control product that owns it.
fn remote_port_label(port: u16) -> Option<&'static str> {
    match port {
        7070 => Some("AnyDesk"),
        5938 => Some("TeamViewer"),
        21115..=21119 => Some("RustDesk"),
        _ => None,
    }
}

#[cfg(target_arch = "x86_64")]
fn read_hypervisor_vendor() -> Option<String> {
    use core::arch::x86_64::__cpuid;
    // Leaf 1, ECX bit 31 = "hypervisor present".
    if (__cpuid(1).ecx & (1 << 31)) == 0 {
        return None;
    }
    let leaf = __cpuid(0x4000_0000);
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(&leaf.ebx.to_le_bytes());
    bytes.extend_from_slice(&leaf.ecx.to_le_bytes());
    bytes.extend_from_slice(&leaf.edx.to_le_bytes());
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(not(target_arch = "x86_64"))]
fn read_hypervisor_vendor() -> Option<String> {
    None
}

fn collect_hypervisor_signals() -> Vec<DetectionSignal> {
    match read_hypervisor_vendor().as_deref().and_then(hypervisor_vendor_label) {
        Some(label) => vec![DetectionSignal {
            id: "vm-cpuid-hypervisor".to_string(),
            label: "Hypervisor detected (CPUID)".to_string(),
            detail: format!("CPUID hypervisor vendor reports {label}."),
            severity: "warn".to_string(),
            source: "cpuid".to_string(),
        }],
        None => Vec::new(),
    }
}

fn collect_mac_vm_signals() -> Vec<DetectionSignal> {
    let mut signals = Vec::new();
    unsafe {
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size = 0u32;
        // First call sizes the buffer (returns ERROR_BUFFER_OVERFLOW).
        let _ = GetAdaptersAddresses(0, flags, None, None, &mut size);
        if size == 0 {
            return signals;
        }
        let mut buffer = aligned_byte_buffer(size as usize);
        let ret = GetAdaptersAddresses(
            0,
            flags,
            None,
            Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut size,
        );
        if ret != 0 {
            return signals;
        }
        let mut current = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !current.is_null() {
            let adapter = &*current;
            let len = (adapter.PhysicalAddressLength as usize).min(adapter.PhysicalAddress.len());
            if len >= 3 {
                let mac = &adapter.PhysicalAddress[..len];
                if let Some(vendor) = mac_oui_vendor(mac) {
                    signals.push(DetectionSignal {
                        id: "vm-mac-oui".to_string(),
                        label: "Virtual network adapter".to_string(),
                        detail: format!(
                            "{vendor} MAC prefix {:02X}:{:02X}:{:02X} detected.",
                            mac[0], mac[1], mac[2]
                        ),
                        severity: "warn".to_string(),
                        source: "network".to_string(),
                    });
                    break;
                }
            }
            current = adapter.Next;
        }
    }
    signals
}

fn collect_remote_port_signals() -> Vec<DetectionSignal> {
    let mut signals = Vec::new();
    unsafe {
        let af = 2u32; // AF_INET
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(None, &mut size, BOOL(0), af, TCP_TABLE_OWNER_PID_ALL, 0);
        if size == 0 {
            return signals;
        }
        let mut buffer = aligned_byte_buffer(size as usize);
        let ret = GetExtendedTcpTable(
            Some(buffer.as_mut_ptr() as *mut c_void),
            &mut size,
            BOOL(0),
            af,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if ret != 0 {
            return signals;
        }
        let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), count);
        let mut seen = std::collections::BTreeSet::new();
        for row in rows {
            // dwLocalPort holds the port in network byte order in its low word.
            let port = u16::from_be(row.dwLocalPort as u16);
            if let Some(vendor) = remote_port_label(port) {
                if seen.insert(port) {
                    signals.push(DetectionSignal {
                        id: format!("remote-port-{port}"),
                        label: "Remote-control network port".to_string(),
                        detail: format!(
                            "{vendor} network port {port} is open (owning pid {}).",
                            row.dwOwningPid
                        ),
                        severity: "warn".to_string(),
                        source: "network".to_string(),
                    });
                }
            }
        }
    }
    signals
}

fn collect_mirror_driver_signals() -> Vec<DetectionSignal> {
    let mut signals = Vec::new();
    unsafe {
        let mut index = 0u32;
        loop {
            let mut device = DISPLAY_DEVICEW {
                cb: std::mem::size_of::<DISPLAY_DEVICEW>() as u32,
                ..Default::default()
            };
            if !EnumDisplayDevicesW(PCWSTR::null(), index, &mut device, 0).as_bool() {
                break;
            }
            if (device.StateFlags & DISPLAY_DEVICE_MIRRORING_DRIVER) != 0 {
                let name = utf16_to_string(&device.DeviceString);
                signals.push(DetectionSignal {
                    id: format!("remote-mirror-{index}"),
                    label: "Mirror display driver".to_string(),
                    detail: format!("Mirror display driver active: {name}"),
                    severity: "warn".to_string(),
                    source: "driver".to_string(),
                });
            }
            index += 1;
        }
    }
    signals
}

/// Allocate a zeroed byte buffer that is guaranteed 8-byte aligned, for use when
/// the raw bytes are later reinterpreted as a Win32 struct (e.g.
/// `IP_ADAPTER_ADDRESSES_LH`, `MIB_TCPTABLE_OWNER_PID`, `VS_VERSIONINFO`). A plain
/// `vec![0u8; n]` only guarantees 1-byte alignment, so casting its pointer to an
/// aligned struct is technically UB. Backing the storage with `u64` fixes that.
fn aligned_byte_buffer(len: usize) -> Vec<u64> {
    vec![0u64; len.div_ceil(8).max(1)]
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

#[cfg(test)]
mod tests {
    use super::{hypervisor_vendor_label, mac_oui_vendor, remote_port_label};

    #[test]
    fn maps_known_hypervisor_vendors() {
        assert_eq!(hypervisor_vendor_label("VMwareVMware"), Some("VMware"));
        assert_eq!(hypervisor_vendor_label("VBoxVBoxVBox"), Some("VirtualBox"));
        assert_eq!(hypervisor_vendor_label("KVMKVMKVM\0\0\0"), Some("KVM"));
        assert_eq!(hypervisor_vendor_label("XenVMMXenVMM"), Some("Xen"));
        assert_eq!(hypervisor_vendor_label("prl hyperv  "), Some("Parallels"));
        assert_eq!(hypervisor_vendor_label("TCGTCGTCGTCG"), Some("QEMU"));
        // Microsoft Hyper-V is deliberately NOT flagged (Win11 VBS false-positive guard).
        assert_eq!(hypervisor_vendor_label("Microsoft Hv"), None);
        assert_eq!(hypervisor_vendor_label(""), None);
    }

    #[test]
    fn maps_known_virtual_mac_ouis() {
        assert_eq!(mac_oui_vendor(&[0x00, 0x0C, 0x29, 0x11, 0x22, 0x33]), Some("VMware"));
        assert_eq!(mac_oui_vendor(&[0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc]), Some("VirtualBox"));
        assert_eq!(mac_oui_vendor(&[0x00, 0x1C, 0x42, 0x00, 0x00, 0x01]), Some("Parallels"));
        // Hyper-V (00:15:5D) and QEMU/KVM (52:54:00) are intentionally NOT flagged
        // to avoid false positives on physical WSL2/Docker/VBS machines.
        assert_eq!(mac_oui_vendor(&[0x00, 0x15, 0x5D, 0x00, 0x00, 0x01]), None);
        assert_eq!(mac_oui_vendor(&[0x52, 0x54, 0x00, 0x01, 0x02, 0x03]), None);
        assert_eq!(mac_oui_vendor(&[0x3c, 0x22, 0xfb, 0x00, 0x00, 0x00]), None); // real vendor OUI
        assert_eq!(mac_oui_vendor(&[0x00, 0x0C]), None); // too short
    }

    #[test]
    fn maps_remote_control_ports() {
        assert_eq!(remote_port_label(7070), Some("AnyDesk"));
        assert_eq!(remote_port_label(5938), Some("TeamViewer"));
        assert_eq!(remote_port_label(21115), Some("RustDesk"));
        assert_eq!(remote_port_label(21119), Some("RustDesk"));
        assert_eq!(remote_port_label(443), None);
    }
}
