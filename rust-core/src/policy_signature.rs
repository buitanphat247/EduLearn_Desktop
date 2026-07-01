use crate::policy_model::ExamPolicy;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const POLICY_SIGNATURE_ALGORITHM: &str = "Ed25519";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedExamPolicy {
    pub algorithm: String,
    pub key_id: String,
    pub policy: ExamPolicy,
    pub signature: String,
}

#[derive(Debug, Clone, Default)]
pub struct TrustedPolicyKeys {
    keys: BTreeMap<String, VerifyingKey>,
}

impl TrustedPolicyKeys {
    pub fn from_base64_map(keys: BTreeMap<String, String>) -> Result<Self, String> {
        let mut trusted = BTreeMap::new();
        for (key_id, encoded_key) in keys {
            if key_id.trim().is_empty() || key_id.len() > 128 {
                return Err("Policy public key ID is invalid.".to_string());
            }
            let bytes = STANDARD
                .decode(encoded_key)
                .map_err(|error| format!("Invalid base64 public key {key_id}: {error}"))?;
            let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                format!("Ed25519 public key {key_id} must contain exactly 32 bytes.")
            })?;
            let key = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|error| format!("Invalid Ed25519 public key {key_id}: {error}"))?;
            trusted.insert(key_id, key);
        }
        Ok(Self { keys: trusted })
    }

    pub fn from_environment() -> Result<Self, String> {
        let raw = std::env::var("EDULEARN_EXAM_POLICY_PUBLIC_KEYS_JSON")
            .map_err(|_| "EDULEARN_EXAM_POLICY_PUBLIC_KEYS_JSON is not configured.".to_string())?;
        let keys: BTreeMap<String, String> = serde_json::from_str(&raw)
            .map_err(|error| format!("Invalid policy public-key configuration: {error}"))?;
        Self::from_base64_map(keys)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn verify(&self, envelope: &SignedExamPolicy) -> Result<String, String> {
        if envelope.algorithm != POLICY_SIGNATURE_ALGORITHM {
            return Err(format!(
                "Unsupported policy signature algorithm {}.",
                envelope.algorithm
            ));
        }
        let key = self
            .keys
            .get(&envelope.key_id)
            .ok_or_else(|| format!("Policy key {} is not trusted.", envelope.key_id))?;
        let signature_bytes = STANDARD
            .decode(&envelope.signature)
            .map_err(|error| format!("Invalid policy signature encoding: {error}"))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|error| format!("Invalid Ed25519 signature: {error}"))?;
        let canonical = canonical_policy_bytes(&envelope.policy)?;
        key.verify(&canonical, &signature)
            .map_err(|_| "Policy signature verification failed.".to_string())?;
        Ok(policy_sha256(&canonical))
    }

    pub fn verify_detached(
        &self,
        key_id: &str,
        payload: &[u8],
        encoded_signature: &str,
    ) -> Result<(), String> {
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| format!("Signature key {key_id} is not trusted."))?;
        let signature_bytes = STANDARD
            .decode(encoded_signature)
            .map_err(|error| format!("Invalid signature encoding: {error}"))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|error| format!("Invalid Ed25519 signature: {error}"))?;
        key.verify(payload, &signature)
            .map_err(|_| "Detached signature verification failed.".to_string())
    }
}

pub fn canonical_policy_bytes(policy: &ExamPolicy) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(policy).map_err(|error| format!("Policy canonicalization failed: {error}"))
}

pub fn policy_sha256(canonical: &[u8]) -> String {
    let digest = Sha256::digest(canonical);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_policy_bytes, SignedExamPolicy, TrustedPolicyKeys, POLICY_SIGNATURE_ALGORITHM,
    };
    use crate::policy_model::ExamPolicy;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;

    fn signed_policy() -> (SignedExamPolicy, TrustedPolicyKeys) {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let policy = ExamPolicy::strict_builtin();
        let signature = signing_key.sign(&canonical_policy_bytes(&policy).unwrap());
        let envelope = SignedExamPolicy {
            algorithm: POLICY_SIGNATURE_ALGORITHM.to_string(),
            key_id: "test-key".to_string(),
            policy,
            signature: STANDARD.encode(signature.to_bytes()),
        };
        let trusted = TrustedPolicyKeys::from_base64_map(BTreeMap::from([(
            "test-key".to_string(),
            STANDARD.encode(signing_key.verifying_key().to_bytes()),
        )]))
        .unwrap();
        (envelope, trusted)
    }

    #[test]
    fn accepts_a_valid_signature() {
        let (envelope, trusted) = signed_policy();
        let digest = trusted.verify(&envelope).unwrap();
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn rejects_policy_tampering_and_unknown_keys() {
        let (mut envelope, trusted) = signed_policy();
        envelope.policy.max_monitor_count = 2;
        assert!(trusted.verify(&envelope).is_err());

        envelope.key_id = "other-key".to_string();
        assert!(trusted.verify(&envelope).is_err());
    }
}
