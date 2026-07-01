use crate::process_watcher::ProcessCreationEvent;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::mem::size_of;
use std::path::Path;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_CANCELLED, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS,
};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    TdhGetEventInformation, TdhGetProperty, TdhGetPropertySize, CONTROLTRACE_HANDLE,
    ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2, ETW_BUFFER_CONTEXT,
    EVENT_CONTROL_CODE_CAPTURE_STATE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_HEADER,
    EVENT_PROPERTY_INFO, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
    PROPERTY_DATA_DESCRIPTOR, TDH_INTYPE_ANSISTRING, TDH_INTYPE_UNICODESTRING,
    TRACE_EVENT_INFO, TRACE_LEVEL_VERBOSE, WNODE_FLAG_TRACED_GUID,
};

const ETW_SESSION_NAME: &str = "EduLearn Exam Guard Process Runtime";
const ETW_PROCESS_KEYWORD: u64 = 0x10;
const RAW_QUEUE_CAPACITY: usize = 8_192;
const OUTPUT_QUEUE_CAPACITY: usize = 8_192;
const FILETIME_UNIX_EPOCH_OFFSET: u64 = 116_444_736_000_000_000;
const ETW_SESSION_GUID: GUID =
    GUID::from_u128(0x8e8ac2b3_988a_4e45_a75f_b8cddfa96c81);
pub const KERNEL_PROCESS_PROVIDER_GUID: GUID =
    GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);

const EVENT_ID_PROCESS_START: u16 = 1;
const EVENT_ID_PROCESS_STOP: u16 = 2;
const EVENT_ID_PROCESS_RUNDOWN: u16 = 15;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwProducerHealth {
    pub health: String,
    pub heartbeat_at_ms: Option<u64>,
    pub last_event_time_ms: Option<u64>,
    pub events_lost: usize,
    pub buffers_lost: usize,
    pub realtime_buffers_lost: usize,
    pub raw_queue_depth: usize,
    pub dropped_events: usize,
    pub callback_latency_micros: u64,
    pub producer_restart_count: u64,
    pub parse_error_count: usize,
    pub last_failure: Option<String>,
}

#[derive(Clone)]
struct RawEtwEvent {
    event_header: EVENT_HEADER,
    buffer_context: ETW_BUFFER_CONTEXT,
    user_data: Vec<u8>,
    received_at_ms: u64,
}

struct EtwCallbackState {
    raw_queue: Mutex<VecDeque<RawEtwEvent>>,
    raw_queue_signal: Condvar,
    raw_dropped_events: AtomicUsize,
    callback_latency_micros: AtomicU64,
    heartbeat_at_ms: AtomicU64,
    last_event_time_ms: AtomicU64,
    events_lost: AtomicUsize,
    buffers_lost: AtomicUsize,
    realtime_buffers_lost: AtomicUsize,
    parse_error_count: AtomicUsize,
    last_failure: Mutex<Option<String>>,
}

impl EtwCallbackState {
    fn new() -> Self {
        Self {
            raw_queue: Mutex::new(VecDeque::new()),
            raw_queue_signal: Condvar::new(),
            raw_dropped_events: AtomicUsize::new(0),
            callback_latency_micros: AtomicU64::new(0),
            heartbeat_at_ms: AtomicU64::new(0),
            last_event_time_ms: AtomicU64::new(0),
            events_lost: AtomicUsize::new(0),
            buffers_lost: AtomicUsize::new(0),
            realtime_buffers_lost: AtomicUsize::new(0),
            parse_error_count: AtomicUsize::new(0),
            last_failure: Mutex::new(None),
        }
    }

    fn record_failure(&self, failure: impl Into<String>) {
        if let Ok(mut last_failure) = self.last_failure.lock() {
            *last_failure = Some(failure.into());
        }
    }

    fn enqueue_raw(&self, event: RawEtwEvent) {
        if let Ok(mut queue) = self.raw_queue.lock() {
            if queue.len() >= RAW_QUEUE_CAPACITY {
                queue.pop_front();
                self.raw_dropped_events.fetch_add(1, Ordering::Relaxed);
            }
            queue.push_back(event);
            self.raw_queue_signal.notify_one();
        } else {
            self.raw_dropped_events.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug)]
struct TracePropertiesBuffer {
    storage: Vec<u64>,
}

impl TracePropertiesBuffer {
    fn new(session_name: &[u16]) -> Self {
        let name_bytes = session_name.len().saturating_mul(size_of::<u16>());
        let total_bytes = size_of::<EVENT_TRACE_PROPERTIES>().saturating_add(name_bytes);
        let word_count = total_bytes.div_ceil(size_of::<u64>());
        let mut result = Self {
            storage: vec![0; word_count],
        };
        unsafe {
            let properties = &mut *result.as_mut_ptr();
            properties.Wnode.BufferSize = total_bytes as u32;
            properties.Wnode.Guid = ETW_SESSION_GUID;
            properties.Wnode.ClientContext = 1;
            properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            properties.BufferSize = 64;
            properties.MinimumBuffers = 4;
            properties.MaximumBuffers = 16;
            properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            properties.FlushTimer = 1;
            properties.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;

            let target = result
                .as_mut_bytes()
                .as_mut_ptr()
                .add(properties.LoggerNameOffset as usize) as *mut u16;
            ptr::copy_nonoverlapping(session_name.as_ptr(), target, session_name.len());
        }
        result
    }

    fn as_mut_ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.storage.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
    }

    fn as_mut_bytes(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(
                self.storage.as_mut_ptr() as *mut u8,
                self.storage.len().saturating_mul(size_of::<u64>()),
            )
        }
    }
}

pub struct EtwProcessProducer {
    control_handle: CONTROLTRACE_HANDLE,
    process_handle: PROCESSTRACE_HANDLE,
    session_name: Vec<u16>,
    properties: TracePropertiesBuffer,
    callback_state: Arc<EtwCallbackState>,
    running: Arc<AtomicBool>,
    output_queue: Arc<Mutex<VecDeque<ProcessCreationEvent>>>,
    output_dropped_events: Arc<Mutex<usize>>,
    consumer_thread: Option<JoinHandle<()>>,
    parser_thread: Option<JoinHandle<()>>,
    producer_restart_count: u64,
    rundown_requested: bool,
}

impl EtwProcessProducer {
    pub fn start(
        output_queue: Arc<Mutex<VecDeque<ProcessCreationEvent>>>,
        output_dropped_events: Arc<Mutex<usize>>,
        producer_restart_count: u64,
    ) -> Result<Self, String> {
        let session_name = wide_null(ETW_SESSION_NAME);
        let mut properties = TracePropertiesBuffer::new(&session_name);
        let mut control_handle = CONTROLTRACE_HANDLE::default();

        let mut start_status = unsafe {
            StartTraceW(
                &mut control_handle,
                PCWSTR(session_name.as_ptr()),
                properties.as_mut_ptr(),
            )
        };
        if start_status == ERROR_ALREADY_EXISTS {
            let mut orphan_properties = TracePropertiesBuffer::new(&session_name);
            unsafe {
                let _ = ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    PCWSTR(session_name.as_ptr()),
                    orphan_properties.as_mut_ptr(),
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            properties = TracePropertiesBuffer::new(&session_name);
            start_status = unsafe {
                StartTraceW(
                    &mut control_handle,
                    PCWSTR(session_name.as_ptr()),
                    properties.as_mut_ptr(),
                )
            };
        }
        ensure_success("StartTraceW", start_status)?;

        let mut enable_parameters = ENABLE_TRACE_PARAMETERS {
            Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
            ..Default::default()
        };
        let enable_status = unsafe {
            EnableTraceEx2(
                control_handle,
                &KERNEL_PROCESS_PROVIDER_GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_VERBOSE as u8,
                ETW_PROCESS_KEYWORD,
                0,
                0,
                Some(&mut enable_parameters),
            )
        };
        if enable_status != ERROR_SUCCESS {
            stop_trace_session(control_handle, &session_name, &mut properties);
            return Err(win32_error("EnableTraceEx2", enable_status.0));
        }

        let rundown_status = unsafe {
            EnableTraceEx2(
                control_handle,
                &KERNEL_PROCESS_PROVIDER_GUID,
                EVENT_CONTROL_CODE_CAPTURE_STATE.0,
                TRACE_LEVEL_VERBOSE as u8,
                ETW_PROCESS_KEYWORD,
                0,
                0,
                Some(&mut enable_parameters),
            )
        };
        let rundown_requested = rundown_status == ERROR_SUCCESS;

        let callback_state = Arc::new(EtwCallbackState::new());
        if !rundown_requested {
            callback_state.record_failure(win32_error(
                "EnableTraceEx2(CAPTURE_STATE)",
                rundown_status.0,
            ));
        }

        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(session_name.as_ptr() as *mut u16),
            BufferCallback: Some(etw_buffer_callback),
            Context: Arc::as_ptr(&callback_state) as *mut c_void,
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(etw_event_record_callback);

        let process_handle = unsafe { OpenTraceW(&mut logfile) };
        if process_handle.Value == u64::MAX {
            stop_trace_session(control_handle, &session_name, &mut properties);
            return Err("OpenTraceW returned INVALID_PROCESSTRACE_HANDLE.".to_string());
        }

        let running = Arc::new(AtomicBool::new(true));
        let parser_thread = Some(spawn_parser_worker(
            Arc::clone(&callback_state),
            Arc::clone(&running),
            Arc::clone(&output_queue),
            Arc::clone(&output_dropped_events),
            control_handle,
            session_name.clone(),
        ));
        let consumer_thread = Some(spawn_trace_consumer(
            Arc::clone(&callback_state),
            Arc::clone(&running),
            process_handle,
        ));

        Ok(Self {
            control_handle,
            process_handle,
            session_name,
            properties,
            callback_state,
            running,
            output_queue,
            output_dropped_events,
            consumer_thread,
            parser_thread,
            producer_restart_count,
            rundown_requested,
        })
    }

    pub fn health(&self) -> EtwProducerHealth {
        let raw_queue_depth = self
            .callback_state
            .raw_queue
            .lock()
            .map(|queue| queue.len())
            .unwrap_or(RAW_QUEUE_CAPACITY);
        let raw_dropped = self
            .callback_state
            .raw_dropped_events
            .load(Ordering::Relaxed);
        let output_dropped = self
            .output_dropped_events
            .lock()
            .map(|count| *count)
            .unwrap_or(0);
        let events_lost = self.callback_state.events_lost.load(Ordering::Relaxed);
        let buffers_lost = self.callback_state.buffers_lost.load(Ordering::Relaxed);
        let realtime_buffers_lost = self
            .callback_state
            .realtime_buffers_lost
            .load(Ordering::Relaxed);
        let parse_error_count = self
            .callback_state
            .parse_error_count
            .load(Ordering::Relaxed);
        let last_failure = self
            .callback_state
            .last_failure
            .lock()
            .ok()
            .and_then(|failure| failure.clone());
        let running = self.running.load(Ordering::SeqCst);
        let degraded = raw_dropped > 0
            || output_dropped > 0
            || events_lost > 0
            || buffers_lost > 0
            || realtime_buffers_lost > 0
            || parse_error_count > 0
            || !self.rundown_requested;
        let health = if !running || last_failure.is_some() && !degraded {
            "unavailable"
        } else if degraded || last_failure.is_some() {
            "degraded"
        } else {
            "healthy"
        };

        EtwProducerHealth {
            health: health.to_string(),
            heartbeat_at_ms: nonzero_timestamp(
                self.callback_state.heartbeat_at_ms.load(Ordering::Relaxed),
            ),
            last_event_time_ms: nonzero_timestamp(
                self.callback_state.last_event_time_ms.load(Ordering::Relaxed),
            ),
            events_lost,
            buffers_lost,
            realtime_buffers_lost,
            raw_queue_depth,
            dropped_events: raw_dropped.saturating_add(output_dropped),
            callback_latency_micros: self
                .callback_state
                .callback_latency_micros
                .load(Ordering::Relaxed),
            producer_restart_count: self.producer_restart_count,
            parse_error_count,
            last_failure,
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn output_queue_depth(&self) -> usize {
        self.output_queue
            .lock()
            .map(|queue| queue.len())
            .unwrap_or(OUTPUT_QUEUE_CAPACITY)
    }

    pub fn stop(&mut self) {
        if self.consumer_thread.is_none() && self.parser_thread.is_none() {
            return;
        }
        self.running.store(false, Ordering::SeqCst);
        self.callback_state.raw_queue_signal.notify_all();
        stop_trace_session(
            self.control_handle,
            &self.session_name,
            &mut self.properties,
        );
        unsafe {
            let _ = CloseTrace(self.process_handle);
        }
        if let Some(handle) = self.consumer_thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.parser_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for EtwProcessProducer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn spawn_trace_consumer(
    callback_state: Arc<EtwCallbackState>,
    running: Arc<AtomicBool>,
    process_handle: PROCESSTRACE_HANDLE,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let result = unsafe { ProcessTrace(&[process_handle], None, None) };
        let expected_stop =
            !running.load(Ordering::SeqCst) && matches!(result, ERROR_SUCCESS | ERROR_CANCELLED);
        if result != ERROR_SUCCESS && !expected_stop {
            callback_state.record_failure(win32_error("ProcessTrace", result.0));
        }
        running.store(false, Ordering::SeqCst);
        callback_state.raw_queue_signal.notify_all();
    })
}

fn spawn_parser_worker(
    callback_state: Arc<EtwCallbackState>,
    running: Arc<AtomicBool>,
    output_queue: Arc<Mutex<VecDeque<ProcessCreationEvent>>>,
    output_dropped_events: Arc<Mutex<usize>>,
    control_handle: CONTROLTRACE_HANDLE,
    session_name: Vec<u16>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut last_stats_query = Instant::now();
        loop {
            let raw_event = {
                let Ok(mut queue) = callback_state.raw_queue.lock() else {
                    callback_state.record_failure("ETW raw queue lock was poisoned.");
                    break;
                };
                while queue.is_empty() && running.load(Ordering::SeqCst) {
                    let Ok((next_queue, _)) = callback_state
                        .raw_queue_signal
                        .wait_timeout(queue, Duration::from_millis(250))
                    else {
                        callback_state.record_failure("ETW raw queue wait failed.");
                        return;
                    };
                    queue = next_queue;
                    if last_stats_query.elapsed() >= Duration::from_secs(1) {
                        break;
                    }
                }
                queue.pop_front()
            };

            if last_stats_query.elapsed() >= Duration::from_secs(1) {
                refresh_trace_loss_stats(control_handle, &session_name, &callback_state);
                last_stats_query = Instant::now();
            }

            if let Some(raw_event) = raw_event {
                match parse_process_event(&raw_event) {
                    Ok(Some(event)) => {
                        enqueue_output_event(&output_queue, &output_dropped_events, event);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        callback_state
                            .parse_error_count
                            .fetch_add(1, Ordering::Relaxed);
                        callback_state.record_failure(error);
                    }
                }
                continue;
            }

            let queue_empty = callback_state
                .raw_queue
                .lock()
                .map(|queue| queue.is_empty())
                .unwrap_or(true);
            if !running.load(Ordering::SeqCst) && queue_empty {
                break;
            }
        }
    })
}

unsafe extern "system" fn etw_event_record_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }
    let started = Instant::now();
    let record = &*event_record;
    if record.EventHeader.ProviderId != KERNEL_PROCESS_PROVIDER_GUID
        || !is_process_event_id(record.EventHeader.EventDescriptor.Id)
    {
        return;
    }
    let callback_state = (record.UserContext as *const EtwCallbackState).as_ref();
    let Some(callback_state) = callback_state else {
        return;
    };

    let user_data = if record.UserData.is_null() || record.UserDataLength == 0 {
        Vec::new()
    } else {
        slice::from_raw_parts(record.UserData as *const u8, record.UserDataLength as usize).to_vec()
    };
    let received_at_ms = now_ms();
    callback_state.heartbeat_at_ms.store(received_at_ms, Ordering::Relaxed);
    callback_state
        .last_event_time_ms
        .store(received_at_ms, Ordering::Relaxed);
    callback_state.enqueue_raw(RawEtwEvent {
        event_header: record.EventHeader,
        buffer_context: record.BufferContext,
        user_data,
        received_at_ms,
    });
    callback_state.callback_latency_micros.fetch_max(
        started.elapsed().as_micros().min(u64::MAX as u128) as u64,
        Ordering::Relaxed,
    );
}

unsafe extern "system" fn etw_buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    if logfile.is_null() {
        return 1;
    }
    let logfile = &*logfile;
    let callback_state = (logfile.Context as *const EtwCallbackState).as_ref();
    if let Some(callback_state) = callback_state {
        callback_state
            .events_lost
            .store(logfile.EventsLost as usize, Ordering::Relaxed);
        callback_state.heartbeat_at_ms.store(now_ms(), Ordering::Relaxed);
    }
    1
}

fn parse_process_event(raw: &RawEtwEvent) -> Result<Option<ProcessCreationEvent>, String> {
    let event_id = raw.event_header.EventDescriptor.Id;
    if !is_process_event_id(event_id) {
        return Ok(None);
    }

    let properties = read_event_properties(raw)?;
    let pid = property_u32(&properties, &["processid", "process_id"])
        .unwrap_or(raw.event_header.ProcessId);
    if pid == 0 {
        return Ok(None);
    }
    let creation_time_ms = property_u64(&properties, &["createtime", "create_time"])
        .and_then(filetime_or_unix_to_unix_ms);
    let parent_pid = property_u32(
        &properties,
        &["parentprocessid", "parent_process_id", "parentid"],
    );
    let session_id = property_u32(&properties, &["sessionid", "session_id"]);
    let image_path = property_string(
        &properties,
        &["imagename", "image_name", "imagepath", "image_path"],
    );
    let command_line = property_string(&properties, &["commandline", "command_line"]);
    let name = image_path
        .as_deref()
        .and_then(executable_name)
        .or_else(|| {
            command_line
                .as_deref()
                .and_then(|command| command.split_whitespace().next())
                .and_then(executable_name)
        })
        .unwrap_or_default();

    let still_running = matches!(event_id, EVENT_ID_PROCESS_START | EVENT_ID_PROCESS_RUNDOWN);
    Ok(Some(ProcessCreationEvent {
        pid,
        name,
        executable_path: image_path,
        creation_time_ms,
        parent_pid,
        session_id,
        command_line,
        observed_at_ms: raw.received_at_ms,
        still_running,
    }))
}

#[derive(Debug)]
struct EventProperty {
    normalized_name: String,
    in_type: u16,
    bytes: Vec<u8>,
}

fn read_event_properties(raw: &RawEtwEvent) -> Result<Vec<EventProperty>, String> {
    let mut user_data = raw.user_data.clone();
    let event_record = EVENT_RECORD {
        EventHeader: raw.event_header,
        BufferContext: raw.buffer_context,
        UserDataLength: user_data.len().min(u16::MAX as usize) as u16,
        UserData: if user_data.is_empty() {
            ptr::null_mut()
        } else {
            user_data.as_mut_ptr() as *mut c_void
        },
        ..Default::default()
    };

    let mut required_size = 0u32;
    let first_status =
        unsafe { TdhGetEventInformation(&event_record, None, None, &mut required_size) };
    if first_status != ERROR_INSUFFICIENT_BUFFER.0 || required_size == 0 {
        return Err(win32_error("TdhGetEventInformation(size)", first_status));
    }

    let mut metadata = AlignedByteBuffer::new(required_size as usize);
    let status = unsafe {
        TdhGetEventInformation(
            &event_record,
            None,
            Some(metadata.as_mut_ptr() as *mut TRACE_EVENT_INFO),
            &mut required_size,
        )
    };
    if status != ERROR_SUCCESS.0 {
        return Err(win32_error("TdhGetEventInformation", status));
    }

    let info = unsafe { &*(metadata.as_ptr() as *const TRACE_EVENT_INFO) };
    let property_count = info.TopLevelPropertyCount.min(info.PropertyCount) as usize;
    let property_array = unsafe {
        slice::from_raw_parts(
            ptr::addr_of!(info.EventPropertyInfoArray) as *const EVENT_PROPERTY_INFO,
            property_count,
        )
    };
    let mut result = Vec::with_capacity(property_count);

    for property in property_array {
        let name = read_metadata_wide_string(metadata.as_bytes(), property.NameOffset as usize)?;
        if name.is_empty() {
            continue;
        }
        let property_name_ptr =
            unsafe { metadata.as_ptr().add(property.NameOffset as usize) as *const u16 };
        let descriptor = PROPERTY_DATA_DESCRIPTOR {
            PropertyName: property_name_ptr as usize as u64,
            ArrayIndex: u32::MAX,
            Reserved: 0,
        };
        let mut property_size = 0u32;
        let size_status = unsafe {
            TdhGetPropertySize(
                &event_record,
                None,
                slice::from_ref(&descriptor),
                &mut property_size,
            )
        };
        if size_status != ERROR_SUCCESS.0 || property_size == 0 {
            continue;
        }
        let mut bytes = vec![0u8; property_size as usize];
        let read_status = unsafe {
            TdhGetProperty(
                &event_record,
                None,
                slice::from_ref(&descriptor),
                &mut bytes,
            )
        };
        if read_status != ERROR_SUCCESS.0 {
            continue;
        }
        let in_type = unsafe { property.Anonymous1.nonStructType.InType };
        result.push(EventProperty {
            normalized_name: normalize_property_name(&name),
            in_type,
            bytes,
        });
    }
    Ok(result)
}

#[derive(Debug)]
struct AlignedByteBuffer {
    storage: Vec<u64>,
    byte_len: usize,
}

impl AlignedByteBuffer {
    fn new(byte_len: usize) -> Self {
        Self {
            storage: vec![0; byte_len.div_ceil(size_of::<u64>())],
            byte_len,
        }
    }

    fn as_ptr(&self) -> *const u8 {
        self.storage.as_ptr() as *const u8
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.storage.as_mut_ptr() as *mut u8
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.as_ptr(), self.byte_len) }
    }
}

fn property_u32(properties: &[EventProperty], names: &[&str]) -> Option<u32> {
    find_property(properties, names).and_then(|property| {
        if property.bytes.len() >= 4 {
            Some(u32::from_le_bytes(property.bytes[..4].try_into().ok()?))
        } else {
            None
        }
    })
}

fn property_u64(properties: &[EventProperty], names: &[&str]) -> Option<u64> {
    find_property(properties, names).and_then(|property| {
        if property.bytes.len() >= 8 {
            Some(u64::from_le_bytes(property.bytes[..8].try_into().ok()?))
        } else if property.bytes.len() >= 4 {
            Some(u32::from_le_bytes(property.bytes[..4].try_into().ok()?) as u64)
        } else {
            None
        }
    })
}

fn property_string(properties: &[EventProperty], names: &[&str]) -> Option<String> {
    find_property(properties, names)
        .and_then(decode_property_string)
        .filter(|value| !value.is_empty())
}

fn find_property<'a>(
    properties: &'a [EventProperty],
    names: &[&str],
) -> Option<&'a EventProperty> {
    properties.iter().find(|property| {
        names
            .iter()
            .any(|name| property.normalized_name == normalize_property_name(name))
    })
}

fn decode_property_string(property: &EventProperty) -> Option<String> {
    let in_type = property.in_type as i32;
    if in_type == TDH_INTYPE_UNICODESTRING.0 {
        let units = property
            .bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .take_while(|unit| *unit != 0)
            .collect::<Vec<_>>();
        return Some(String::from_utf16_lossy(&units).trim().to_string());
    }
    if in_type == TDH_INTYPE_ANSISTRING.0 {
        let length = property
            .bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(property.bytes.len());
        return Some(
            String::from_utf8_lossy(&property.bytes[..length])
                .trim()
                .to_string(),
        );
    }
    None
}

fn normalize_property_name(name: &str) -> String {
    name.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn read_metadata_wide_string(buffer: &[u8], offset: usize) -> Result<String, String> {
    if offset >= buffer.len() || offset % 2 != 0 {
        return Err(format!("Invalid TDH metadata string offset {offset}."));
    }
    let mut units = Vec::new();
    let mut cursor = offset;
    while cursor.saturating_add(2) <= buffer.len() {
        let unit = u16::from_le_bytes([buffer[cursor], buffer[cursor + 1]]);
        if unit == 0 {
            return Ok(String::from_utf16_lossy(&units));
        }
        units.push(unit);
        cursor = cursor.saturating_add(2);
    }
    Err("Unterminated TDH metadata string.".to_string())
}

fn executable_name(path: &str) -> Option<String> {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .or_else(|| {
            path.rsplit(['\\', '/'])
                .next()
                .filter(|name| !name.is_empty())
                .map(str::to_string)
        })
}

fn filetime_or_unix_to_unix_ms(value: u64) -> Option<u64> {
    if value >= FILETIME_UNIX_EPOCH_OFFSET {
        Some(value.saturating_sub(FILETIME_UNIX_EPOCH_OFFSET) / 10_000)
    } else if value > 10_000_000_000 {
        Some(value)
    } else if value > 0 {
        Some(value.saturating_mul(1_000))
    } else {
        None
    }
}

fn enqueue_output_event(
    output_queue: &Arc<Mutex<VecDeque<ProcessCreationEvent>>>,
    output_dropped_events: &Arc<Mutex<usize>>,
    event: ProcessCreationEvent,
) {
    if let Ok(mut queue) = output_queue.lock() {
        if queue.len() >= OUTPUT_QUEUE_CAPACITY {
            queue.pop_front();
            if let Ok(mut dropped) = output_dropped_events.lock() {
                *dropped = dropped.saturating_add(1);
            }
        }
        queue.push_back(event);
    } else if let Ok(mut dropped) = output_dropped_events.lock() {
        *dropped = dropped.saturating_add(1);
    }
}

fn refresh_trace_loss_stats(
    control_handle: CONTROLTRACE_HANDLE,
    session_name: &[u16],
    callback_state: &EtwCallbackState,
) {
    let mut properties = TracePropertiesBuffer::new(session_name);
    let status = unsafe {
        windows::Win32::System::Diagnostics::Etw::QueryTraceW(
            control_handle,
            PCWSTR(session_name.as_ptr()),
            properties.as_mut_ptr(),
        )
    };
    if status != ERROR_SUCCESS {
        return;
    }
    let properties = unsafe { &*properties.as_mut_ptr() };
    callback_state
        .events_lost
        .store(properties.EventsLost as usize, Ordering::Relaxed);
    callback_state
        .buffers_lost
        .store(properties.LogBuffersLost as usize, Ordering::Relaxed);
    callback_state
        .realtime_buffers_lost
        .store(properties.RealTimeBuffersLost as usize, Ordering::Relaxed);
}

fn stop_trace_session(
    control_handle: CONTROLTRACE_HANDLE,
    session_name: &[u16],
    properties: &mut TracePropertiesBuffer,
) {
    unsafe {
        let _ = ControlTraceW(
            control_handle,
            PCWSTR(session_name.as_ptr()),
            properties.as_mut_ptr(),
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

fn ensure_success(
    operation: &str,
    status: windows::Win32::Foundation::WIN32_ERROR,
) -> Result<(), String> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(win32_error(operation, status.0))
    }
}

fn win32_error(operation: &str, code: u32) -> String {
    format!("{operation} failed with Win32 error {code}.")
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn nonzero_timestamp(value: u64) -> Option<u64> {
    (value > 0).then_some(value)
}

fn is_process_event_id(event_id: u16) -> bool {
    matches!(
        event_id,
        EVENT_ID_PROCESS_START | EVENT_ID_PROCESS_STOP | EVENT_ID_PROCESS_RUNDOWN
    )
}

#[cfg(test)]
mod tests {
    use super::{
        decode_property_string, enqueue_output_event, executable_name,
        filetime_or_unix_to_unix_ms, is_process_event_id, normalize_property_name,
        property_u32, property_u64, read_metadata_wide_string, EtwCallbackState,
        EtwProcessProducer, EventProperty, RawEtwEvent, EVENT_ID_PROCESS_RUNDOWN,
        EVENT_ID_PROCESS_START, EVENT_ID_PROCESS_STOP, FILETIME_UNIX_EPOCH_OFFSET,
        OUTPUT_QUEUE_CAPACITY, RAW_QUEUE_CAPACITY,
    };
    use crate::process_watcher::ProcessCreationEvent;
    use std::collections::VecDeque;
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};
    use windows::Win32::System::Diagnostics::Etw::{
        ETW_BUFFER_CONTEXT, EVENT_HEADER, TDH_INTYPE_ANSISTRING, TDH_INTYPE_UNICODESTRING,
    };

    #[test]
    fn recognizes_only_process_start_stop_and_rundown_events() {
        assert!(is_process_event_id(EVENT_ID_PROCESS_START));
        assert!(is_process_event_id(EVENT_ID_PROCESS_STOP));
        assert!(is_process_event_id(EVENT_ID_PROCESS_RUNDOWN));
        assert!(!is_process_event_id(3));
    }

    #[test]
    fn converts_filetime_and_unix_seconds_to_unix_milliseconds() {
        assert_eq!(
            filetime_or_unix_to_unix_ms(FILETIME_UNIX_EPOCH_OFFSET + 50_000),
            Some(5)
        );
        assert_eq!(filetime_or_unix_to_unix_ms(1_700_000_000), Some(1_700_000_000_000));
        assert_eq!(filetime_or_unix_to_unix_ms(0), None);
    }

    #[test]
    fn normalizes_tdh_property_names_and_extracts_windows_image_name() {
        assert_eq!(normalize_property_name("Parent_Process-ID"), "parentprocessid");
        assert_eq!(
            executable_name("C:\\Program Files\\OBS Studio\\bin\\obs64.exe"),
            Some("obs64.exe".to_string())
        );
    }

    #[test]
    fn reads_utf16_metadata_string_with_bounds_checks() {
        let bytes = "ProcessId\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            read_metadata_wide_string(&bytes, 0).expect("metadata name"),
            "ProcessId"
        );
        assert!(read_metadata_wide_string(&bytes, bytes.len() + 2).is_err());
    }

    #[test]
    fn decodes_tdh_numeric_and_string_properties() {
        let unicode_bytes = "C:\\Tools\\obs64.exe\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let properties = vec![
            EventProperty {
                normalized_name: "processid".to_string(),
                in_type: 0,
                bytes: 42_u32.to_le_bytes().to_vec(),
            },
            EventProperty {
                normalized_name: "createtime".to_string(),
                in_type: 0,
                bytes: 123_u64.to_le_bytes().to_vec(),
            },
            EventProperty {
                normalized_name: "imagename".to_string(),
                in_type: TDH_INTYPE_UNICODESTRING.0 as u16,
                bytes: unicode_bytes,
            },
            EventProperty {
                normalized_name: "commandline".to_string(),
                in_type: TDH_INTYPE_ANSISTRING.0 as u16,
                bytes: b"obs64.exe --portable\0".to_vec(),
            },
        ];

        assert_eq!(property_u32(&properties, &["ProcessId"]), Some(42));
        assert_eq!(property_u64(&properties, &["CreateTime"]), Some(123));
        assert_eq!(
            decode_property_string(&properties[2]).as_deref(),
            Some("C:\\Tools\\obs64.exe")
        );
        assert_eq!(
            decode_property_string(&properties[3]).as_deref(),
            Some("obs64.exe --portable")
        );
    }

    #[test]
    fn callback_queue_is_bounded_and_reports_drops() {
        let state = EtwCallbackState::new();
        for index in 0..RAW_QUEUE_CAPACITY + 3 {
            state.enqueue_raw(RawEtwEvent {
                event_header: EVENT_HEADER::default(),
                buffer_context: ETW_BUFFER_CONTEXT::default(),
                user_data: Vec::new(),
                received_at_ms: index as u64,
            });
        }

        assert_eq!(
            state.raw_queue.lock().expect("queue").len(),
            RAW_QUEUE_CAPACITY
        );
        assert_eq!(
            state
                .raw_dropped_events
                .load(std::sync::atomic::Ordering::Relaxed),
            3
        );
    }

    #[test]
    fn output_queue_accepts_five_thousand_process_events_without_overflow() {
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let dropped = Arc::new(Mutex::new(0usize));
        for pid in 1..=5_000 {
            enqueue_output_event(
                &queue,
                &dropped,
                ProcessCreationEvent {
                    pid,
                    name: "stress.exe".to_string(),
                    executable_path: Some("C:\\Tools\\stress.exe".to_string()),
                    creation_time_ms: Some(pid as u64),
                    parent_pid: None,
                    session_id: Some(1),
                    command_line: None,
                    observed_at_ms: pid as u64,
                    still_running: true,
                },
            );
        }

        assert_eq!(queue.lock().expect("queue").len(), 5_000);
        assert_eq!(*dropped.lock().expect("dropped"), 0);
    }

    #[test]
    fn output_queue_is_bounded_and_accounts_for_overflow() {
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let dropped = Arc::new(Mutex::new(0usize));
        for pid in 1..=(OUTPUT_QUEUE_CAPACITY as u32 + 5) {
            enqueue_output_event(
                &queue,
                &dropped,
                ProcessCreationEvent {
                    pid,
                    name: "stress.exe".to_string(),
                    executable_path: None,
                    creation_time_ms: Some(pid as u64),
                    parent_pid: None,
                    session_id: None,
                    command_line: None,
                    observed_at_ms: pid as u64,
                    still_running: true,
                },
            );
        }

        assert_eq!(queue.lock().expect("queue").len(), OUTPUT_QUEUE_CAPACITY);
        assert_eq!(*dropped.lock().expect("dropped"), 5);
    }

    #[test]
    #[ignore = "requires Windows ETW permissions and creates a real process"]
    fn native_etw_session_observes_spawned_process() {
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let dropped = Arc::new(Mutex::new(0usize));
        let mut producer = EtwProcessProducer::start(
            Arc::clone(&queue),
            Arc::clone(&dropped),
            0,
        )
        .expect("real ETW producer must start");

        let mut child = Command::new("cmd.exe")
            .args(["/C", "exit", "0"])
            .spawn()
            .expect("spawn ETW probe process");
        let child_pid = child.id();
        let _ = child.wait();

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut observed = false;
        while Instant::now() < deadline {
            observed = queue
                .lock()
                .expect("queue")
                .iter()
                .any(|event| event.pid == child_pid);
            if observed {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let health = producer.health();
        producer.stop();

        assert!(observed, "ETW did not observe spawned pid {child_pid}");
        assert_eq!(health.events_lost, 0);
        assert_eq!(health.buffers_lost, 0);
        assert_eq!(health.realtime_buffers_lost, 0);
        assert_eq!(*dropped.lock().expect("dropped"), 0);
    }
}
