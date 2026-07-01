use base64::engine::general_purpose::STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use crate::policy_signature::TrustedPolicyKeys;
use crate::policy_signature::SignedExamPolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const DEVICE_KEY_FILE: &str = "device-key-v1.bin";
const MAX_ATTESTATION_LIFETIME_MS: u64 = 5 * 60 * 1_000;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExamChallengePayload {
    pub exam_id: String,
    pub session_id: String,
    pub policy_version: String,
    pub client_version: String,
    pub device_id: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExamDeviceIdentity {
    pub algorithm: String,
    pub device_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedExamChallenge {
    pub algorithm: String,
    pub device_id: String,
    pub public_key: String,
    pub payload: ExamChallengePayload,
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
pub struct SignedExamReceipt {
    pub algorithm: String,
    pub key_id: String,
    pub receipt: ExamReceipt,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ElevatedTerminationRequest {
    pub version: u8,
    pub nonce: String,
    pub timestamp_ms: u64,
    pub target_pid: u32,
    pub device_public_key: String,
    pub policy: SignedExamPolicy,
    pub receipt: SignedExamReceipt,
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
    policy: &'a SignedExamPolicy,
    receipt: &'a SignedExamReceipt,
}

pub fn build_elevated_termination_request(
    policy: &SignedExamPolicy,
    receipt: &SignedExamReceipt,
    target_pid: u32,
    now_ms: u64,
) -> Result<ElevatedTerminationRequest, String> {
    if target_pid == 0 || target_pid == std::process::id() {
        return Err("Elevated remediation target PID is invalid.".to_string());
    }
    let key = load_or_create_signing_key()?;
    let identity = identity_for(&key)?;
    if receipt.receipt.device_id != identity.device_id
        || receipt.receipt.exam_id != policy.policy.exam_id
        || receipt.receipt.policy_version != policy.policy.policy_version
        || receipt.receipt.scope != "elevated-remediation"
        || receipt.receipt.expires_at_ms <= now_ms
        || receipt
            .receipt
            .expires_at_ms
            .saturating_sub(receipt.receipt.verified_at_ms)
            > 8 * 60 * 60 * 1_000
    {
        return Err("Service request policy and receipt binding is invalid.".to_string());
    }
    let mut nonce_bytes = [0_u8; 24];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|error| format!("Unable to generate service request nonce: {error}"))?;
    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    let mut request = ElevatedTerminationRequest {
        version: 1,
        nonce,
        timestamp_ms: now_ms,
        target_pid,
        device_public_key: identity.public_key,
        policy: policy.clone(),
        receipt: receipt.clone(),
        signature: String::new(),
    };
    let canonical = serde_jcs::to_vec(&TerminationContent {
        version: request.version,
        nonce: &request.nonce,
        timestamp_ms: request.timestamp_ms,
        target_pid: request.target_pid,
        device_public_key: &request.device_public_key,
        policy: &request.policy,
        receipt: &request.receipt,
    })
    .map_err(|error| format!("Service request canonicalization failed: {error}"))?;
    request.signature = STANDARD.encode(key.sign(&canonical).to_bytes());
    Ok(request)
}

pub fn verify_exam_receipt(
    envelope: &SignedExamReceipt,
    trusted_keys: &TrustedPolicyKeys,
    expected_exam_id: &str,
    expected_session_id: &str,
    expected_policy_version: &str,
    now_ms: u64,
) -> Result<(), String> {
    if envelope.algorithm != "Ed25519" {
        return Err("Exam receipt signature algorithm is unsupported.".to_string());
    }
    let identity = get_exam_device_identity()?;
    verify_exam_receipt_for_device(
        envelope,
        trusted_keys,
        expected_exam_id,
        expected_session_id,
        expected_policy_version,
        &identity.device_id,
        "exam-entry",
        60_000,
        now_ms,
    )
}

pub fn verify_service_authorization(
    envelope: &SignedExamReceipt,
    trusted_keys: &TrustedPolicyKeys,
    expected_exam_id: &str,
    expected_session_id: &str,
    expected_policy_version: &str,
    now_ms: u64,
) -> Result<(), String> {
    let identity = get_exam_device_identity()?;
    verify_exam_receipt_for_device(
        envelope,
        trusted_keys,
        expected_exam_id,
        expected_session_id,
        expected_policy_version,
        &identity.device_id,
        "elevated-remediation",
        8 * 60 * 60 * 1_000,
        now_ms,
    )
}

fn verify_exam_receipt_for_device(
    envelope: &SignedExamReceipt,
    trusted_keys: &TrustedPolicyKeys,
    expected_exam_id: &str,
    expected_session_id: &str,
    expected_policy_version: &str,
    expected_device_id: &str,
    expected_scope: &str,
    maximum_lifetime_ms: u64,
    now_ms: u64,
) -> Result<(), String> {
    let receipt = &envelope.receipt;
    if receipt.exam_id != expected_exam_id
        || receipt.session_id != expected_session_id
        || receipt.policy_version != expected_policy_version
        || receipt.device_id != expected_device_id
        || receipt.scope != expected_scope
    {
        return Err("Exam receipt binding does not match this session.".to_string());
    }
    if receipt.verified_at_ms > now_ms.saturating_add(5_000)
        || receipt.expires_at_ms <= now_ms
        || receipt
            .expires_at_ms
            .saturating_sub(receipt.verified_at_ms)
            > maximum_lifetime_ms
    {
        return Err("Exam receipt is expired or has an invalid lifetime.".to_string());
    }
    let canonical = serde_jcs::to_vec(receipt)
        .map_err(|error| format!("Exam receipt canonicalization failed: {error}"))?;
    trusted_keys.verify_detached(
        &envelope.key_id,
        &canonical,
        &envelope.signature,
    )
}

pub fn get_exam_device_identity() -> Result<ExamDeviceIdentity, String> {
    identity_for(&load_or_create_signing_key()?)
}

pub fn sign_exam_challenge(
    payload: ExamChallengePayload,
    now_ms: u64,
) -> Result<SignedExamChallenge, String> {
    let key = load_or_create_signing_key()?;
    sign_exam_challenge_with(&key, payload, now_ms)
}

fn sign_exam_challenge_with(
    key: &SigningKey,
    payload: ExamChallengePayload,
    now_ms: u64,
) -> Result<SignedExamChallenge, String> {
    validate_challenge(&payload, now_ms)?;
    let identity = identity_for(key)?;
    if payload.device_id != identity.device_id {
        return Err("Challenge deviceId does not match this installation.".to_string());
    }
    let canonical = serde_jcs::to_vec(&payload)
        .map_err(|error| format!("Challenge canonicalization failed: {error}"))?;
    let signature = key.sign(&canonical);
    Ok(SignedExamChallenge {
        algorithm: "Ed25519".to_string(),
        device_id: identity.device_id,
        public_key: identity.public_key,
        payload,
        signature: STANDARD.encode(signature.to_bytes()),
    })
}

fn identity_for(key: &SigningKey) -> Result<ExamDeviceIdentity, String> {
    let public_key = key.verifying_key().to_bytes();
    let digest = Sha256::digest(public_key);
    let device_id = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(ExamDeviceIdentity {
        algorithm: "Ed25519".to_string(),
        device_id,
        public_key: STANDARD.encode(public_key),
    })
}

fn validate_challenge(payload: &ExamChallengePayload, now_ms: u64) -> Result<(), String> {
    for (field, value) in [
        ("examId", payload.exam_id.as_str()),
        ("sessionId", payload.session_id.as_str()),
        ("policyVersion", payload.policy_version.as_str()),
        ("clientVersion", payload.client_version.as_str()),
        ("deviceId", payload.device_id.as_str()),
        ("nonce", payload.nonce.as_str()),
    ] {
        if value.is_empty() || value.len() > 256 {
            return Err(format!("{field} must contain between 1 and 256 characters."));
        }
    }
    if payload.nonce.len() < 24 {
        return Err("Challenge nonce is too short.".to_string());
    }
    if payload.issued_at_ms > now_ms.saturating_add(5_000)
        || payload.expires_at_ms <= now_ms
        || payload.expires_at_ms <= payload.issued_at_ms
        || payload.expires_at_ms.saturating_sub(payload.issued_at_ms)
            > MAX_ATTESTATION_LIFETIME_MS
    {
        return Err("Challenge timestamp window is invalid or expired.".to_string());
    }
    Ok(())
}

fn device_key_path() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("Edulearn").join("ExamGuard").join(DEVICE_KEY_FILE)
}

fn load_or_create_signing_key() -> Result<SigningKey, String> {
    let path = device_key_path();
    if path.exists() {
        let protected = fs::read(&path)
            .map_err(|error| format!("Unable to read protected device key: {error}"))?;
        let seed = unprotect_seed(&protected)?;
        return Ok(SigningKey::from_bytes(&seed));
    }

    let mut seed = [0_u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|error| format!("Unable to generate device key: {error}"))?;
    let protected = protect_seed(&seed)?;
    persist_key_atomically(&path, &protected)?;
    seed.fill(0);
    let protected = fs::read(&path)
        .map_err(|error| format!("Unable to verify persisted device key: {error}"))?;
    let seed = unprotect_seed(&protected)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn persist_key_atomically(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "Device key path has no parent directory.".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Unable to create device key directory: {error}"))?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temporary, contents)
        .map_err(|error| format!("Unable to write temporary device key: {error}"))?;
    match fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(_error) if path.exists() => {
            let _ = fs::remove_file(&temporary);
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(format!("Unable to install protected device key: {error}"))
        }
    }
}

#[cfg(target_os = "windows")]
fn protect_seed(seed: &[u8; 32]) -> Result<Vec<u8>, String> {
    use windows::core::w;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: seed.len() as u32,
        pbData: seed.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(
            &input,
            w!("EduLearn Exam Guard device identity"),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(|error| format!("DPAPI CryptProtectData failed: {error}"))?;
    let protected =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    let _ = unsafe { LocalFree(HLOCAL(output.pbData as *mut _)) };
    Ok(protected)
}

#[cfg(target_os = "windows")]
fn unprotect_seed(protected: &[u8]) -> Result<[u8; 32], String> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(|error| format!("DPAPI CryptUnprotectData failed: {error}"))?;
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    let _ = unsafe { LocalFree(HLOCAL(output.pbData as *mut _)) };
    bytes
        .try_into()
        .map_err(|_| "Protected device key did not contain a 32-byte Ed25519 seed.".to_string())
}

#[cfg(not(target_os = "windows"))]
fn protect_seed(_seed: &[u8; 32]) -> Result<Vec<u8>, String> {
    Err("Device-key protection is only supported on Windows.".to_string())
}

#[cfg(not(target_os = "windows"))]
fn unprotect_seed(_protected: &[u8]) -> Result<[u8; 32], String> {
    Err("Device-key protection is only supported on Windows.".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        identity_for, sign_exam_challenge_with, verify_exam_receipt_for_device,
        ExamChallengePayload, ExamReceipt, SignedExamReceipt,
    };
    use crate::policy_signature::TrustedPolicyKeys;
    use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
    use base64::Engine;
    use std::collections::BTreeMap;

    fn payload(device_id: String) -> ExamChallengePayload {
        ExamChallengePayload {
            exam_id: "exam-1".to_string(),
            session_id: "session-1".to_string(),
            policy_version: "exam-2026-v1".to_string(),
            client_version: "1.0.0".to_string(),
            device_id,
            nonce: "nonce-with-at-least-24-characters".to_string(),
            issued_at_ms: 1_000,
            expires_at_ms: 10_000,
        }
    }

    #[test]
    fn signs_a_canonical_session_bound_challenge() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[5_u8; 32]);
        let identity = identity_for(&key).unwrap();
        let signed =
            sign_exam_challenge_with(&key, payload(identity.device_id.clone()), 2_000).unwrap();
        let public_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(signed.public_key)
            .unwrap()
            .try_into()
            .unwrap();
        let signature = Signature::from_slice(
            &base64::engine::general_purpose::STANDARD
                .decode(signed.signature)
                .unwrap(),
        )
        .unwrap();
        VerifyingKey::from_bytes(&public_bytes)
            .unwrap()
            .verify(&serde_jcs::to_vec(&signed.payload).unwrap(), &signature)
            .unwrap();
    }

    #[test]
    fn rejects_wrong_device_and_expired_challenge() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[5_u8; 32]);
        assert!(sign_exam_challenge_with(&key, payload("wrong".to_string()), 2_000).is_err());
        let identity = identity_for(&key).unwrap();
        assert!(
            sign_exam_challenge_with(&key, payload(identity.device_id), 10_000).is_err()
        );
    }

    #[test]
    fn verifies_receipt_signature_and_all_session_bindings() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[8_u8; 32]);
        let receipt = ExamReceipt {
            user_id: 7,
            exam_id: "exam-1".to_string(),
            session_id: "session-1".to_string(),
            policy_version: "exam-1-v1".to_string(),
            device_id: "device-1".to_string(),
            scope: "exam-entry".to_string(),
            verified_at_ms: 1_000,
            expires_at_ms: 10_000,
        };
        let signature = key.sign(&serde_jcs::to_vec(&receipt).unwrap());
        let envelope = SignedExamReceipt {
            algorithm: "Ed25519".to_string(),
            key_id: "receipt-key".to_string(),
            receipt,
            signature: base64::engine::general_purpose::STANDARD
                .encode(signature.to_bytes()),
        };
        let trusted = TrustedPolicyKeys::from_base64_map(BTreeMap::from([(
            "receipt-key".to_string(),
            base64::engine::general_purpose::STANDARD
                .encode(key.verifying_key().to_bytes()),
        )]))
        .unwrap();

        assert!(verify_exam_receipt_for_device(
            &envelope,
            &trusted,
            "exam-1",
            "session-1",
            "exam-1-v1",
            "device-1",
            "exam-entry",
            60_000,
            2_000,
        )
        .is_ok());
        assert!(verify_exam_receipt_for_device(
            &envelope,
            &trusted,
            "exam-1",
            "other-session",
            "exam-1-v1",
            "device-1",
            "exam-entry",
            60_000,
            2_000,
        )
        .is_err());
    }
}
