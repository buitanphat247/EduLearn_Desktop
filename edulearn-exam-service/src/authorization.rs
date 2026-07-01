use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const REQUEST_WINDOW_MS: u64 = 30_000;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExamPolicy {
    pub policy_version: String,
    pub exam_id: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    #[serde(default)]
    pub blocked_processes: Vec<String>,
    #[serde(default)]
    pub allowed_processes: Vec<String>,
    #[serde(default)]
    pub remote_processes: Vec<String>,
    #[serde(default)]
    pub screen_capture_processes: Vec<String>,
    #[serde(default)]
    pub virtual_machine_processes: Vec<String>,
    #[serde(default)]
    pub debug_processes: Vec<String>,
    pub instant_kill: bool,
    pub allow_vm: bool,
    pub max_monitor_count: usize,
    pub capture_protection_required: bool,
    #[serde(default = "default_remediation_failure_mode")]
    pub remediation_failure_mode: String,
    #[serde(default)]
    pub browser_processes: Vec<String>,
    #[serde(default)]
    pub communication_processes: Vec<String>,
}

fn default_remediation_failure_mode() -> String {
    "recoveryRequired".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPolicy {
    pub algorithm: String,
    pub key_id: String,
    pub policy: ExamPolicy,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExamReceipt {
    pub user_id: u64,
    pub exam_id: String,
    pub session_id: String,
    pub policy_version: String,
    pub device_id: String,
    pub scope: String,
    pub verified_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReceipt {
    pub algorithm: String,
    pub key_id: String,
    pub receipt: ExamReceipt,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ElevatedTerminationRequest {
    pub version: u8,
    pub nonce: String,
    pub timestamp_ms: u64,
    pub target_pid: u32,
    pub device_public_key: String,
    pub policy: SignedPolicy,
    pub receipt: SignedReceipt,
    pub signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminationContent<'a> {
    version: u8,
    nonce: &'a str,
    timestamp_ms: u64,
    target_pid: u32,
    device_public_key: &'a str,
    policy: &'a SignedPolicy,
    receipt: &'a SignedReceipt,
}

#[derive(Debug, Default)]
pub struct ServiceAuthorizer {
    trusted_server_keys: BTreeMap<String, VerifyingKey>,
    seen_nonces: BTreeMap<String, u64>,
}

impl ServiceAuthorizer {
    pub fn from_base64_keys(keys: BTreeMap<String, String>) -> Result<Self, String> {
        let mut trusted_server_keys = BTreeMap::new();
        for (key_id, encoded) in keys {
            let bytes = STANDARD
                .decode(encoded)
                .map_err(|error| format!("Invalid server key encoding: {error}"))?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "Server Ed25519 public key must contain 32 bytes.".to_string())?;
            trusted_server_keys.insert(
                key_id,
                VerifyingKey::from_bytes(&bytes)
                    .map_err(|error| format!("Invalid server public key: {error}"))?,
            );
        }
        if trusted_server_keys.is_empty() {
            return Err("At least one trusted server key is required.".to_string());
        }
        Ok(Self {
            trusted_server_keys,
            seen_nonces: BTreeMap::new(),
        })
    }

    pub fn authorize_termination(
        &mut self,
        request: &ElevatedTerminationRequest,
        actual_process_name: &str,
        now_ms: u64,
        service_pid: u32,
    ) -> Result<(), String> {
        if request.version != 1
            || request.target_pid == 0
            || request.target_pid == service_pid
        {
            return Err("Service request version or target PID is invalid.".to_string());
        }
        if request.nonce.len() < 24 || request.nonce.len() > 128 {
            return Err("Service request nonce is invalid.".to_string());
        }
        if request.timestamp_ms > now_ms.saturating_add(5_000)
            || now_ms.saturating_sub(request.timestamp_ms) > REQUEST_WINDOW_MS
        {
            return Err("Service request timestamp is outside the accepted window.".to_string());
        }
        if self.seen_nonces.contains_key(&request.nonce) {
            return Err("Service request nonce was replayed.".to_string());
        }

        self.verify_server_signature(
            &request.policy.key_id,
            &serde_jcs::to_vec(&request.policy.policy)
                .map_err(|error| format!("Policy canonicalization failed: {error}"))?,
            &request.policy.signature,
        )?;
        self.verify_server_signature(
            &request.receipt.key_id,
            &serde_jcs::to_vec(&request.receipt.receipt)
                .map_err(|error| format!("Receipt canonicalization failed: {error}"))?,
            &request.receipt.signature,
        )?;
        if request.policy.algorithm != "Ed25519"
            || request.receipt.algorithm != "Ed25519"
        {
            return Err("Service request uses an unsupported server signature.".to_string());
        }
        let policy = &request.policy.policy;
        let receipt = &request.receipt.receipt;
        if receipt.exam_id != policy.exam_id
            || receipt.policy_version != policy.policy_version
            || receipt.scope != "elevated-remediation"
            || receipt.expires_at_ms <= now_ms
            || policy.expires_at_ms <= now_ms
        {
            return Err("Receipt and policy binding is invalid or expired.".to_string());
        }

        let device_key_bytes = STANDARD
            .decode(&request.device_public_key)
            .map_err(|error| format!("Invalid device public key: {error}"))?;
        let device_key_bytes: [u8; 32] = device_key_bytes
            .try_into()
            .map_err(|_| "Device public key must contain 32 bytes.".to_string())?;
        let device_id = Sha256::digest(device_key_bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if device_id != receipt.device_id {
            return Err("Device public key does not match the server receipt.".to_string());
        }
        let device_key = VerifyingKey::from_bytes(&device_key_bytes)
            .map_err(|error| format!("Invalid device public key: {error}"))?;
        verify_signature(
            &device_key,
            &serde_jcs::to_vec(&TerminationContent {
                version: request.version,
                nonce: &request.nonce,
                timestamp_ms: request.timestamp_ms,
                target_pid: request.target_pid,
                device_public_key: &request.device_public_key,
                policy: &request.policy,
                receipt: &request.receipt,
            })
            .map_err(|error| format!("Service request canonicalization failed: {error}"))?,
            &request.signature,
        )?;

        let process_name = actual_process_name.trim().to_ascii_lowercase();
        if policy
            .allowed_processes
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&process_name))
        {
            return Err("Target executable is explicitly allowed by policy.".to_string());
        }
        let mut blocked = BTreeSet::new();
        for list in [
            &policy.blocked_processes,
            &policy.remote_processes,
            &policy.screen_capture_processes,
            &policy.debug_processes,
        ] {
            blocked.extend(list.iter().map(|name| name.to_ascii_lowercase()));
        }
        if !policy.allow_vm {
            blocked.extend(
                policy
                    .virtual_machine_processes
                    .iter()
                    .map(|name| name.to_ascii_lowercase()),
            );
        }
        if !blocked.contains(&process_name) {
            return Err(format!(
                "Target executable {process_name} is not prohibited by the signed policy."
            ));
        }

        self.seen_nonces
            .insert(request.nonce.clone(), request.timestamp_ms);
        self.seen_nonces
            .retain(|_, timestamp| now_ms.saturating_sub(*timestamp) <= REQUEST_WINDOW_MS);
        Ok(())
    }

    fn verify_server_signature(
        &self,
        key_id: &str,
        payload: &[u8],
        encoded_signature: &str,
    ) -> Result<(), String> {
        let key = self
            .trusted_server_keys
            .get(key_id)
            .ok_or_else(|| format!("Server key {key_id} is not trusted."))?;
        verify_signature(key, payload, encoded_signature)
    }
}

fn verify_signature(
    key: &VerifyingKey,
    payload: &[u8],
    encoded_signature: &str,
) -> Result<(), String> {
    let bytes = STANDARD
        .decode(encoded_signature)
        .map_err(|error| format!("Invalid signature encoding: {error}"))?;
    let signature =
        Signature::from_slice(&bytes).map_err(|error| format!("Invalid signature: {error}"))?;
    key.verify(payload, &signature)
        .map_err(|_| "Signature verification failed.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture() -> (
        ServiceAuthorizer,
        ElevatedTerminationRequest,
        SigningKey,
    ) {
        let server_key = SigningKey::from_bytes(&[3_u8; 32]);
        let device_key = SigningKey::from_bytes(&[4_u8; 32]);
        let device_public_key = STANDARD.encode(device_key.verifying_key().to_bytes());
        let device_id = Sha256::digest(device_key.verifying_key().to_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let policy = ExamPolicy {
            policy_version: "exam-1-v1".to_string(),
            exam_id: "exam-1".to_string(),
            issued_at_ms: 1_000,
            expires_at_ms: 20_000,
            blocked_processes: vec!["obs64.exe".to_string()],
            allowed_processes: Vec::new(),
            remote_processes: Vec::new(),
            screen_capture_processes: Vec::new(),
            virtual_machine_processes: Vec::new(),
            debug_processes: Vec::new(),
            instant_kill: true,
            allow_vm: false,
            max_monitor_count: 1,
            capture_protection_required: true,
            remediation_failure_mode: "recoveryRequired".to_string(),
            browser_processes: Vec::new(),
            communication_processes: Vec::new(),
        };
        let signed_policy = SignedPolicy {
            algorithm: "Ed25519".to_string(),
            key_id: "server".to_string(),
            signature: STANDARD.encode(
                server_key
                    .sign(&serde_jcs::to_vec(&policy).unwrap())
                    .to_bytes(),
            ),
            policy,
        };
        let receipt = ExamReceipt {
            user_id: 7,
            exam_id: "exam-1".to_string(),
            session_id: "session-1".to_string(),
            policy_version: "exam-1-v1".to_string(),
            device_id,
            scope: "elevated-remediation".to_string(),
            verified_at_ms: 1_500,
            expires_at_ms: 10_000,
        };
        let signed_receipt = SignedReceipt {
            algorithm: "Ed25519".to_string(),
            key_id: "server".to_string(),
            signature: STANDARD.encode(
                server_key
                    .sign(&serde_jcs::to_vec(&receipt).unwrap())
                    .to_bytes(),
            ),
            receipt,
        };
        let mut request = ElevatedTerminationRequest {
            version: 1,
            nonce: "service-request-nonce-123456".to_string(),
            timestamp_ms: 2_000,
            target_pid: 99,
            device_public_key,
            policy: signed_policy,
            receipt: signed_receipt,
            signature: String::new(),
        };
        request.signature = STANDARD.encode(
            device_key
                .sign(
                    &serde_jcs::to_vec(&TerminationContent {
                        version: request.version,
                        nonce: &request.nonce,
                        timestamp_ms: request.timestamp_ms,
                        target_pid: request.target_pid,
                        device_public_key: &request.device_public_key,
                        policy: &request.policy,
                        receipt: &request.receipt,
                    })
                    .unwrap(),
                )
                .to_bytes(),
        );
        let authorizer = ServiceAuthorizer::from_base64_keys(BTreeMap::from([(
            "server".to_string(),
            STANDARD.encode(server_key.verifying_key().to_bytes()),
        )]))
        .unwrap();
        (authorizer, request, device_key)
    }

    #[test]
    fn authorizes_only_exact_process_from_signed_policy() {
        let (mut authorizer, request, _) = fixture();
        assert!(authorizer
            .authorize_termination(&request, "obs64.exe", 2_001, 500)
            .is_ok());
    }

    #[test]
    fn rejects_replay_tampering_and_non_blocked_process() {
        let (mut authorizer, request, _) = fixture();
        authorizer
            .authorize_termination(&request, "obs64.exe", 2_001, 500)
            .unwrap();
        assert!(authorizer
            .authorize_termination(&request, "obs64.exe", 2_002, 500)
            .is_err());

        let (mut authorizer, request, _) = fixture();
        assert!(authorizer
            .authorize_termination(&request, "notepad.exe", 2_001, 500)
            .is_err());

        let (mut authorizer, mut request, _) = fixture();
        request.target_pid = 100;
        assert!(authorizer
            .authorize_termination(&request, "obs64.exe", 2_001, 500)
            .is_err());
    }

    #[test]
    fn rejects_malformed_requests_missing_signed_material() {
        let (_, request, _) = fixture();
        let mut payload = serde_json::to_value(&request).unwrap();

        for field in ["signature", "receipt", "policy"] {
            let mut candidate = payload.clone();
            candidate.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<ElevatedTerminationRequest>(candidate).is_err());
        }

        payload["targetPid"] = serde_json::json!(0);
        let invalid = serde_json::from_value::<ElevatedTerminationRequest>(payload).unwrap();
        let (mut authorizer, _, _) = fixture();
        assert!(authorizer
            .authorize_termination(&invalid, "obs64.exe", 2_001, 500)
            .is_err());
    }
}
