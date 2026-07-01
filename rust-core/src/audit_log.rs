use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;

const AUDIT_LOG_ENV: &str = "EDULEARN_EXAM_AUDIT_LOG";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditRecordBody<'a> {
    version: u8,
    timestamp: u64,
    level: &'a str,
    event: &'a str,
    component: &'a str,
    session_state: &'a str,
    active_session_id: Option<&'a str>,
    policy_digest_sha256: &'a str,
    message: &'a str,
    data: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditRecord<'a> {
    #[serde(flatten)]
    body: AuditRecordBody<'a>,
    previous_hash: Option<String>,
    current_hash: String,
}

pub fn configured_audit_path() -> Option<PathBuf> {
    std::env::var(AUDIT_LOG_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
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
    let Some(path) = configured_audit_path() else {
        return Ok(false);
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let previous_hash = read_last_audit_hash(&path)?;
    let body = AuditRecordBody {
        version: 1,
        timestamp,
        level: severity,
        event,
        component: "rust-core",
        session_state,
        active_session_id,
        policy_digest_sha256,
        message: event,
        data: redact_value(data),
    };
    let current_hash = audit_record_hash(&body, previous_hash.as_deref())?;
    let record = AuditRecord {
        body,
        previous_hash,
        current_hash,
    };

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, &record)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(true)
}

fn audit_record_hash(body: &AuditRecordBody<'_>, previous_hash: Option<&str>) -> io::Result<String> {
    let payload = json!({
        "body": body,
        "previousHash": previous_hash,
    });
    let bytes = serde_json::to_vec(&payload)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn read_last_audit_hash(path: &PathBuf) -> io::Result<Option<String>> {
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
    ]
    .iter()
    .any(|sensitive| key.contains(sensitive))
}

#[cfg(test)]
mod tests {
    use super::{append_audit_event, redact_value};
    use serde_json::json;
    use std::fs;
    use std::sync::{Mutex, OnceLock};

    fn audit_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
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
    fn appends_jsonl_when_configured() {
        let _lock = audit_test_lock().lock().unwrap();
        let path = std::env::temp_dir().join(format!(
            "edulearn-audit-test-{}.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        std::env::set_var("EDULEARN_EXAM_AUDIT_LOG", &path);

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

        std::env::remove_var("EDULEARN_EXAM_AUDIT_LOG");
        let contents = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);
        assert!(wrote);
        assert!(contents.contains("\"event\":\"SECURITY_COMMAND\""));
        assert!(contents.contains("\"currentHash\""));
        assert!(contents.contains("[redacted]"));
    }

    #[test]
    fn audit_log_chains_records_with_previous_hash() {
        let _lock = audit_test_lock().lock().unwrap();
        let path = std::env::temp_dir().join(format!(
            "edulearn-audit-chain-test-{}.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        std::env::set_var("EDULEARN_EXAM_AUDIT_LOG", &path);

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

        std::env::remove_var("EDULEARN_EXAM_AUDIT_LOG");
        let contents = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);
        let lines = contents.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert!(first["previousHash"].is_null());
        assert_eq!(second["previousHash"], first["currentHash"]);
        assert_ne!(first["currentHash"], second["currentHash"]);
    }
}
