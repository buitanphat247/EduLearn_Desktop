use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const AUDIT_LOG_ENV: &str = "EDULEARN_EXAM_AUDIT_LOG";
const AUDIT_PENDING_ENV: &str = "EDULEARN_EXAM_AUDIT_PENDING_QUEUE";
const AUDIT_MAX_BYTES_ENV: &str = "EDULEARN_EXAM_AUDIT_MAX_BYTES";
const DEFAULT_MAX_AUDIT_BYTES: u64 = 25 * 1024 * 1024;
const AUDIT_SCHEMA_VERSION: u16 = 2;
const AUDIT_SIGNATURE_VERSION: &str = "local-hash-chain-v2";
const DEFAULT_AUDIT_BATCH_LIMIT: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventV2 {
    pub audit_id: String,
    pub session_id: String,
    pub exam_id: String,
    pub user_id: String,
    pub device_id: String,
    pub runtime_id: String,
    pub timestamp_utc: u64,
    pub event_type: String,
    pub severity: String,
    pub producer: String,
    pub runtime_state: String,
    pub payload: Value,
    pub previous_hash: Option<String>,
    pub current_hash: String,
    pub signature_version: String,
    pub schema_version: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingAuditUpload {
    pub audit_id: String,
    pub queued_at_ms: u64,
    pub attempt_count: u32,
    pub next_retry_at_ms: u64,
    pub last_failure: Option<String>,
    pub event: AuditEventV2,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditUploadBatch {
    pub schema_version: u16,
    pub queue_depth_before_drain: usize,
    pub events: Vec<AuditEventV2>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditChainVerification {
    pub checked: bool,
    pub valid: bool,
    pub event_count: usize,
    pub broken_at_audit_id: Option<String>,
    pub last_hash: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditHealthSnapshot {
    pub audit_enabled: bool,
    pub audit_health: String,
    pub audit_queue_depth: usize,
    pub pending_uploads: usize,
    pub failed_uploads: usize,
    pub last_successful_upload: Option<u64>,
    pub last_failure: Option<String>,
    pub hash_chain_status: String,
    pub sync_latency_ms: Option<u64>,
    pub audit_log_path: Option<String>,
    pub pending_queue_path: Option<String>,
}

pub fn configured_audit_path() -> Option<PathBuf> {
    std::env::var(AUDIT_LOG_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn configured_pending_path(audit_path: &Path) -> PathBuf {
    std::env::var(AUDIT_PENDING_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| audit_path.with_extension("pending.jsonl"))
}

fn configured_max_audit_bytes() -> u64 {
    std::env::var(AUDIT_MAX_BYTES_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value >= 1024)
        .unwrap_or(DEFAULT_MAX_AUDIT_BYTES)
}

pub fn append_audit_event(
    timestamp: u64,
    event: &str,
    severity: &str,
    session_state: &str,
    active_session_id: Option<&str>,
    policy_digest_sha256: &str,
    data: Value,
) -> io::Result<bool> {
    let session_id = active_session_id.unwrap_or("unknown-session");
    let exam_id = data
        .get("examId")
        .and_then(Value::as_str)
        .unwrap_or("unknown-exam");
    let user_id = data
        .get("userId")
        .and_then(Value::as_str)
        .unwrap_or("unknown-user");
    let device_id = data
        .get("deviceId")
        .and_then(Value::as_str)
        .unwrap_or("unknown-device");
    let runtime_id = std::env::var("EDULEARN_EXAM_RUNTIME_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "rust-core".to_string());
    let payload = json!({
        "message": event,
        "policyDigestSha256": policy_digest_sha256,
        "data": data,
    });

    append_audit_event_v2(AuditEventInput {
        timestamp_utc: timestamp,
        event_type: event.to_string(),
        severity: severity.to_string(),
        session_id: session_id.to_string(),
        exam_id: exam_id.to_string(),
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        runtime_id,
        producer: "rust-core".to_string(),
        runtime_state: session_state.to_string(),
        payload,
    })
}

#[derive(Debug, Clone)]
pub struct AuditEventInput {
    pub session_id: String,
    pub exam_id: String,
    pub user_id: String,
    pub device_id: String,
    pub runtime_id: String,
    pub timestamp_utc: u64,
    pub event_type: String,
    pub severity: String,
    pub producer: String,
    pub runtime_state: String,
    pub payload: Value,
}

pub fn append_audit_event_v2(input: AuditEventInput) -> io::Result<bool> {
    let Some(path) = configured_audit_path() else {
        return Ok(false);
    };
    ensure_parent(&path)?;
    let pending_path = configured_pending_path(&path);
    ensure_parent(&pending_path)?;

    let previous_hash = read_last_audit_hash(&path)?;
    rotate_if_needed(&path, configured_max_audit_bytes(), input.timestamp_utc)?;
    let mut event = AuditEventV2 {
        audit_id: generate_uuid_v4()?,
        session_id: required_or_unknown(input.session_id, "unknown-session"),
        exam_id: required_or_unknown(input.exam_id, "unknown-exam"),
        user_id: required_or_unknown(input.user_id, "unknown-user"),
        device_id: required_or_unknown(input.device_id, "unknown-device"),
        runtime_id: required_or_unknown(input.runtime_id, "rust-core"),
        timestamp_utc: input.timestamp_utc,
        event_type: required_or_unknown(input.event_type, "Unknown"),
        severity: required_or_unknown(input.severity, "INFO"),
        producer: required_or_unknown(input.producer, "rust-core"),
        runtime_state: required_or_unknown(input.runtime_state, "UNKNOWN"),
        payload: redact_value(input.payload),
        previous_hash,
        current_hash: String::new(),
        signature_version: AUDIT_SIGNATURE_VERSION.to_string(),
        schema_version: AUDIT_SCHEMA_VERSION,
    };
    event.current_hash = audit_event_hash(&event)?;

    append_json_line(&path, &event)?;
    append_json_line(
        &pending_path,
        &PendingAuditUpload {
            audit_id: event.audit_id.clone(),
            queued_at_ms: event.timestamp_utc,
            attempt_count: 0,
            next_retry_at_ms: event.timestamp_utc,
            last_failure: None,
            event,
        },
    )?;
    Ok(true)
}

pub fn verify_audit_chain() -> io::Result<AuditChainVerification> {
    let Some(path) = configured_audit_path() else {
        return Ok(AuditChainVerification {
            checked: false,
            valid: true,
            event_count: 0,
            broken_at_audit_id: None,
            last_hash: None,
            detail: "Audit log is not configured.".to_string(),
        });
    };
    verify_audit_chain_at(&path)
}

pub fn verify_audit_chain_at(path: &Path) -> io::Result<AuditChainVerification> {
    let Ok(file) = fs::File::open(path) else {
        return Ok(AuditChainVerification {
            checked: true,
            valid: true,
            event_count: 0,
            broken_at_audit_id: None,
            last_hash: None,
            detail: "Audit log does not exist yet.".to_string(),
        });
    };

    let mut previous_seen: Option<String> = None;
    let mut count = 0;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let event: AuditEventV2 = serde_json::from_str(&line)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if count > 0 && event.previous_hash != previous_seen {
            return Ok(AuditChainVerification {
                checked: true,
                valid: false,
                event_count: count + 1,
                broken_at_audit_id: Some(event.audit_id),
                last_hash: previous_seen,
                detail: "Audit previousHash does not match the preceding currentHash.".to_string(),
            });
        }
        let expected = audit_event_hash(&event)?;
        if expected != event.current_hash {
            return Ok(AuditChainVerification {
                checked: true,
                valid: false,
                event_count: count + 1,
                broken_at_audit_id: Some(event.audit_id),
                last_hash: previous_seen,
                detail: "Audit currentHash does not match canonical event content.".to_string(),
            });
        }
        previous_seen = Some(event.current_hash);
        count += 1;
    }

    Ok(AuditChainVerification {
        checked: true,
        valid: true,
        event_count: count,
        broken_at_audit_id: None,
        last_hash: previous_seen,
        detail: "Audit hash chain is intact.".to_string(),
    })
}

pub fn drain_audit_upload_batch(limit: usize) -> io::Result<AuditUploadBatch> {
    let Some(path) = configured_audit_path() else {
        return Ok(AuditUploadBatch {
            schema_version: AUDIT_SCHEMA_VERSION,
            queue_depth_before_drain: 0,
            events: Vec::new(),
        });
    };
    let pending = read_pending_records(&configured_pending_path(&path))?;
    let limit = limit.clamp(1, DEFAULT_AUDIT_BATCH_LIMIT);
    Ok(AuditUploadBatch {
        schema_version: AUDIT_SCHEMA_VERSION,
        queue_depth_before_drain: pending.len(),
        events: pending
            .into_iter()
            .take(limit)
            .map(|pending| pending.event)
            .collect(),
    })
}

pub fn ack_audit_upload_batch(audit_ids: &[String], uploaded_at_ms: u64) -> io::Result<usize> {
    let Some(path) = configured_audit_path() else {
        return Ok(0);
    };
    let pending_path = configured_pending_path(&path);
    let acknowledged = audit_ids.iter().cloned().collect::<HashSet<_>>();
    let pending = read_pending_records(&pending_path)?;
    let before = pending.len();
    let remaining = pending
        .into_iter()
        .filter(|record| !acknowledged.contains(&record.audit_id))
        .collect::<Vec<_>>();
    rewrite_pending_records(&pending_path, &remaining)?;
    write_last_upload_marker(&pending_path, uploaded_at_ms)?;
    Ok(before.saturating_sub(remaining.len()))
}

pub fn record_audit_upload_failure(
    audit_ids: &[String],
    reason: &str,
    failed_at_ms: u64,
) -> io::Result<usize> {
    let Some(path) = configured_audit_path() else {
        return Ok(0);
    };
    let pending_path = configured_pending_path(&path);
    let failed = audit_ids.iter().cloned().collect::<HashSet<_>>();
    let mut touched = 0;
    let mut records = read_pending_records(&pending_path)?;
    for record in &mut records {
        if failed.contains(&record.audit_id) {
            touched += 1;
            record.attempt_count = record.attempt_count.saturating_add(1);
            record.next_retry_at_ms =
                failed_at_ms.saturating_add(retry_delay_ms(record.attempt_count));
            record.last_failure = Some(reason.to_string());
        }
    }
    rewrite_pending_records(&pending_path, &records)?;
    Ok(touched)
}

pub fn audit_status() -> io::Result<AuditHealthSnapshot> {
    let Some(path) = configured_audit_path() else {
        return Ok(AuditHealthSnapshot {
            audit_enabled: false,
            audit_health: "disabled".to_string(),
            audit_queue_depth: 0,
            pending_uploads: 0,
            failed_uploads: 0,
            last_successful_upload: None,
            last_failure: None,
            hash_chain_status: "not-configured".to_string(),
            sync_latency_ms: None,
            audit_log_path: None,
            pending_queue_path: None,
        });
    };
    let pending_path = configured_pending_path(&path);
    let pending = read_pending_records(&pending_path)?;
    let verification = verify_audit_chain_at(&path)?;
    let failed_uploads = pending
        .iter()
        .filter(|record| record.attempt_count > 0)
        .count();
    let last_failure = pending
        .iter()
        .rev()
        .find_map(|record| record.last_failure.clone());
    let last_successful_upload = read_last_upload_marker(&pending_path).ok().flatten();
    let hash_chain_status = if verification.valid {
        "intact"
    } else {
        "tampered"
    };
    let audit_health = if !verification.valid {
        "tampered"
    } else if failed_uploads > 0 {
        "degraded"
    } else {
        "healthy"
    };
    Ok(AuditHealthSnapshot {
        audit_enabled: true,
        audit_health: audit_health.to_string(),
        audit_queue_depth: pending.len(),
        pending_uploads: pending.len(),
        failed_uploads,
        last_successful_upload,
        last_failure,
        hash_chain_status: hash_chain_status.to_string(),
        sync_latency_ms: None,
        audit_log_path: Some(path.display().to_string()),
        pending_queue_path: Some(pending_path.display().to_string()),
    })
}

fn audit_event_hash(event: &AuditEventV2) -> io::Result<String> {
    let payload = json!({
        "auditId": event.audit_id,
        "sessionId": event.session_id,
        "examId": event.exam_id,
        "userId": event.user_id,
        "deviceId": event.device_id,
        "runtimeId": event.runtime_id,
        "timestampUtc": event.timestamp_utc,
        "eventType": event.event_type,
        "severity": event.severity,
        "producer": event.producer,
        "runtimeState": event.runtime_state,
        "payload": event.payload,
        "previousHash": event.previous_hash,
        "signatureVersion": event.signature_version,
        "schemaVersion": event.schema_version,
    });
    let bytes = serde_jcs::to_vec(&payload)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut hasher = Sha256::new();
    hasher.update(event.previous_hash.as_deref().unwrap_or("GENESIS").as_bytes());
    hasher.update(bytes);
    Ok(hex_digest(hasher.finalize().as_slice()))
}

fn read_last_audit_hash(path: &Path) -> io::Result<Option<String>> {
    let Ok(file) = fs::File::open(path) else {
        return Ok(None);
    };
    let mut last_line = None;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if !line.trim().is_empty() {
            last_line = Some(line);
        }
    }
    let Some(line) = last_line else {
        return Ok(None);
    };
    let value: Value = serde_json::from_str(&line)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(value
        .get("currentHash")
        .and_then(Value::as_str)
        .map(str::to_string))
}

fn read_pending_records(path: &Path) -> io::Result<Vec<PendingAuditUpload>> {
    let Ok(file) = fs::File::open(path) else {
        return Ok(Vec::new());
    };
    let mut records = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        records.push(
            serde_json::from_str(&line)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
        );
    }
    Ok(records)
}

fn rewrite_pending_records(path: &Path, records: &[PendingAuditUpload]) -> io::Result<()> {
    ensure_parent(path)?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temporary)?;
        for record in records {
            serde_json::to_writer(&mut file, record)?;
            file.write_all(b"\n")?;
        }
        file.flush()?;
    }
    fs::rename(temporary, path)?;
    Ok(())
}

fn append_json_line<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.flush()
}

fn rotate_if_needed(path: &Path, max_bytes: u64, timestamp: u64) -> io::Result<()> {
    let Ok(metadata) = fs::metadata(path) else {
        return Ok(());
    };
    if metadata.len() < max_bytes {
        return Ok(());
    }
    let rotated = path.with_extension(format!("jsonl.{timestamp}.sealed"));
    fs::rename(path, rotated)?;
    Ok(())
}

fn write_last_upload_marker(pending_path: &Path, uploaded_at_ms: u64) -> io::Result<()> {
    let marker = pending_path.with_extension("last-upload");
    fs::write(marker, uploaded_at_ms.to_string())
}

fn read_last_upload_marker(pending_path: &Path) -> io::Result<Option<u64>> {
    let marker = pending_path.with_extension("last-upload");
    let Ok(contents) = fs::read_to_string(marker) else {
        return Ok(None);
    };
    Ok(contents.trim().parse::<u64>().ok())
}

fn retry_delay_ms(attempt_count: u32) -> u64 {
    match attempt_count {
        0 => 1_000,
        1 => 1_000,
        2 => 2_000,
        3 => 4_000,
        4 => 8_000,
        5 => 16_000,
        6 => 32_000,
        _ => 60_000,
    }
}

fn ensure_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn required_or_unknown(value: String, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn generate_uuid_v4() -> io::Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom(&mut bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    ))
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn redact_value(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    if is_sensitive_key(&key) {
                        (key, json!("[redacted]"))
                    } else {
                        (key, redact_value(value))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(redact_value).collect()),
        other => other,
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "signature",
        "privatekey",
        "receipt",
        "authorization",
        "examkey",
        "sessiontoken",
        "devicekey",
    ]
    .iter()
    .any(|sensitive| key.contains(sensitive))
}

#[cfg(test)]
mod tests {
    use super::{
        ack_audit_upload_batch, append_audit_event, audit_status, drain_audit_upload_batch,
        record_audit_upload_failure, redact_value, verify_audit_chain,
    };
    use serde_json::{json, Value};
    use std::fs;
    use std::sync::{Mutex, OnceLock};

    fn audit_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn configure_test_paths(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "edulearn-audit-v2-{name}-{}",
            std::process::id()
        ));
        let log = base.with_extension("jsonl");
        let pending = base.with_extension("pending.jsonl");
        let _ = fs::remove_file(&log);
        let _ = fs::remove_file(&pending);
        let _ = fs::remove_file(pending.with_extension("last-upload"));
        std::env::set_var("EDULEARN_EXAM_AUDIT_LOG", &log);
        std::env::set_var("EDULEARN_EXAM_AUDIT_PENDING_QUEUE", &pending);
        (log, pending)
    }

    fn cleanup(log: &std::path::Path, pending: &std::path::Path) {
        std::env::remove_var("EDULEARN_EXAM_AUDIT_LOG");
        std::env::remove_var("EDULEARN_EXAM_AUDIT_PENDING_QUEUE");
        let _ = fs::remove_file(log);
        let _ = fs::remove_file(pending);
        let _ = fs::remove_file(pending.with_extension("last-upload"));
    }

    #[test]
    fn redacts_nested_sensitive_fields() {
        let redacted = redact_value(json!({
            "cmd": "start_exam_session",
            "token": "abc",
            "nested": {
                "serviceAuthorization": {"signature": "sig"},
                "count": 1
            }
        }));

        assert_eq!(redacted["token"], "[redacted]");
        assert_eq!(redacted["nested"]["serviceAuthorization"], "[redacted]");
        assert_eq!(redacted["nested"]["count"], 1);
    }

    #[test]
    fn appends_jsonl_v2_when_configured() {
        let _lock = audit_test_lock().lock().unwrap();
        let (log, pending) = configure_test_paths("append");

        let wrote = append_audit_event(
            123,
            "SECURITY_COMMAND",
            "INFO",
            "EXAM_RUNNING",
            Some("session-1"),
            "digest",
            json!({"cmd": "run_runtime_monitor_tick", "signature": "secret"}),
        )
        .unwrap();

        let contents = fs::read_to_string(&log).unwrap();
        let pending_contents = fs::read_to_string(&pending).unwrap();
        cleanup(&log, &pending);
        assert!(wrote);
        assert!(contents.contains("\"eventType\":\"SECURITY_COMMAND\""));
        assert!(contents.contains("\"schemaVersion\":2"));
        assert!(contents.contains("\"currentHash\""));
        assert!(contents.contains("[redacted]"));
        assert!(pending_contents.contains("\"attemptCount\":0"));
    }

    #[test]
    fn audit_log_chains_records_and_verifies() {
        let _lock = audit_test_lock().lock().unwrap();
        let (log, pending) = configure_test_paths("chain");

        append_audit_event(
            1,
            "FIRST",
            "INFO",
            "INIT",
            None,
            "digest",
            json!({"ok": true}),
        )
        .unwrap();
        append_audit_event(
            2,
            "SECOND",
            "WARN",
            "EXAM_RUNNING",
            Some("session-1"),
            "digest",
            json!({"ok": false}),
        )
        .unwrap();

        let verification = verify_audit_chain().unwrap();
        let contents = fs::read_to_string(&log).unwrap();
        cleanup(&log, &pending);
        let lines = contents.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        let second: Value = serde_json::from_str(lines[1]).unwrap();
        assert!(first["previousHash"].is_null());
        assert_eq!(second["previousHash"], first["currentHash"]);
        assert!(verification.valid);
        assert_eq!(verification.event_count, 2);
    }

    #[test]
    fn detects_tampered_audit_payload() {
        let _lock = audit_test_lock().lock().unwrap();
        let (log, pending) = configure_test_paths("tamper");
        append_audit_event(
            1,
            "FIRST",
            "INFO",
            "INIT",
            None,
            "digest",
            json!({"ok": true}),
        )
        .unwrap();
        let mut value: Value =
            serde_json::from_str(&fs::read_to_string(&log).unwrap()).unwrap();
        value["payload"]["data"]["ok"] = json!(false);
        fs::write(&log, format!("{}\n", serde_json::to_string(&value).unwrap())).unwrap();

        let verification = verify_audit_chain().unwrap();
        cleanup(&log, &pending);
        assert!(!verification.valid);
        assert_eq!(verification.detail, "Audit currentHash does not match canonical event content.");
    }

    #[test]
    fn pending_queue_survives_ack_and_failure_updates() {
        let _lock = audit_test_lock().lock().unwrap();
        let (log, pending) = configure_test_paths("queue");
        append_audit_event(
            10,
            "FIRST",
            "INFO",
            "INIT",
            None,
            "digest",
            json!({"ok": true}),
        )
        .unwrap();
        append_audit_event(
            20,
            "SECOND",
            "INFO",
            "INIT",
            None,
            "digest",
            json!({"ok": true}),
        )
        .unwrap();

        let batch = drain_audit_upload_batch(10).unwrap();
        assert_eq!(batch.queue_depth_before_drain, 2);
        assert_eq!(batch.events.len(), 2);
        let failed_id = batch.events[0].audit_id.clone();
        let acked_id = batch.events[1].audit_id.clone();
        assert_eq!(
            record_audit_upload_failure(&[failed_id.clone()], "offline", 30).unwrap(),
            1
        );
        assert_eq!(ack_audit_upload_batch(&[acked_id], 40).unwrap(), 1);
        let status = audit_status().unwrap();
        cleanup(&log, &pending);
        assert_eq!(status.pending_uploads, 1);
        assert_eq!(status.failed_uploads, 1);
        assert_eq!(status.last_failure.as_deref(), Some("offline"));
        assert_eq!(status.last_successful_upload, Some(40));
    }
}
