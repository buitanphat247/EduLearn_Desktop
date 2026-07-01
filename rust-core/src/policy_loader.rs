use crate::policy_model::ExamPolicy;
use crate::policy_signature::{SignedExamPolicy, TrustedPolicyKeys};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadedExamPolicy {
    pub policy: ExamPolicy,
    pub source: String,
    pub key_id: Option<String>,
    pub digest_sha256: String,
    pub loaded_at_ms: u64,
    #[serde(skip)]
    pub signed_envelope: Option<SignedExamPolicy>,
}

impl LoadedExamPolicy {
    pub fn builtin() -> Self {
        Self {
            policy: ExamPolicy::strict_builtin(),
            source: "builtin".to_string(),
            key_id: None,
            digest_sha256: "builtin".to_string(),
            loaded_at_ms: 0,
            signed_envelope: None,
        }
    }
}

pub fn load_signed_exam_policy(
    envelope: SignedExamPolicy,
    trusted_keys: &TrustedPolicyKeys,
    expected_exam_id: &str,
    now_ms: u64,
) -> Result<LoadedExamPolicy, String> {
    if trusted_keys.is_empty() {
        return Err("No trusted exam-policy public keys are configured.".to_string());
    }
    let digest = trusted_keys.verify(&envelope)?;
    envelope.policy.validate_for(expected_exam_id, now_ms)?;

    Ok(LoadedExamPolicy {
        policy: envelope.policy.clone(),
        source: "signed".to_string(),
        key_id: Some(envelope.key_id.clone()),
        digest_sha256: digest,
        loaded_at_ms: now_ms,
        signed_envelope: Some(envelope),
    })
}

#[cfg(test)]
mod tests {
    use super::load_signed_exam_policy;
    use crate::policy_model::ExamPolicy;
    use crate::policy_signature::{
        canonical_policy_bytes, SignedExamPolicy, TrustedPolicyKeys, POLICY_SIGNATURE_ALGORITHM,
    };
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;

    fn fixture(exam_id: &str) -> (SignedExamPolicy, TrustedPolicyKeys) {
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        let mut policy = ExamPolicy::strict_builtin();
        policy.policy_version = "exam-2026-v1".to_string();
        policy.exam_id = exam_id.to_string();
        policy.issued_at_ms = 1_000;
        policy.expires_at_ms = 10_000;
        let signature = signing_key.sign(&canonical_policy_bytes(&policy).unwrap());
        let envelope = SignedExamPolicy {
            algorithm: POLICY_SIGNATURE_ALGORITHM.to_string(),
            key_id: "primary".to_string(),
            policy,
            signature: STANDARD.encode(signature.to_bytes()),
        };
        let trusted = TrustedPolicyKeys::from_base64_map(BTreeMap::from([(
            "primary".to_string(),
            STANDARD.encode(signing_key.verifying_key().to_bytes()),
        )]))
        .unwrap();
        (envelope, trusted)
    }

    #[test]
    fn loads_a_valid_policy_for_the_expected_exam() {
        let (envelope, trusted) = fixture("exam-1");
        let loaded =
            load_signed_exam_policy(envelope, &trusted, "exam-1", 2_000).unwrap();
        assert_eq!(loaded.source, "signed");
        assert_eq!(loaded.policy.policy_version, "exam-2026-v1");
    }

    #[test]
    fn rejects_wrong_exam_and_expired_policy() {
        let (envelope, trusted) = fixture("exam-1");
        assert!(load_signed_exam_policy(
            envelope.clone(),
            &trusted,
            "exam-2",
            2_000
        )
        .is_err());
        assert!(load_signed_exam_policy(envelope, &trusted, "exam-1", 10_000).is_err());
    }
}
