use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::collections::BTreeMap;

const FRAME_VERSION: u8 = 1;
const MAX_CLOCK_SKEW_MS: u64 = 30_000;
const MAX_REPLAY_ENTRIES: usize = 4_096;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticatedFrame {
    pub version: u8,
    pub kind: String,
    pub nonce: String,
    pub timestamp_ms: u64,
    pub payload: Value,
    pub mac: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MacContent<'a> {
    version: u8,
    kind: &'a str,
    nonce: &'a str,
    timestamp_ms: u64,
    payload: &'a Value,
}

pub struct IpcAuthenticator {
    secret: Vec<u8>,
    seen_nonces: BTreeMap<String, u64>,
}

impl IpcAuthenticator {
    pub fn from_base64_secret(encoded: &str) -> Result<Self, String> {
        let secret = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|error| format!("IPC secret is not valid base64url: {error}"))?;
        if secret.len() < 32 {
            return Err("IPC secret must contain at least 32 random bytes.".to_string());
        }
        Ok(Self {
            secret,
            seen_nonces: BTreeMap::new(),
        })
    }

    pub fn verify_request(
        &mut self,
        frame: &AuthenticatedFrame,
        now_ms: u64,
    ) -> Result<Value, String> {
        self.verify(frame, "request", now_ms)?;
        Ok(frame.payload.clone())
    }

    pub fn sign_response(
        &self,
        payload: Value,
        nonce: String,
        timestamp_ms: u64,
    ) -> Result<AuthenticatedFrame, String> {
        let mut frame = AuthenticatedFrame {
            version: FRAME_VERSION,
            kind: "response".to_string(),
            nonce,
            timestamp_ms,
            payload,
            mac: String::new(),
        };
        frame.mac = self.compute_mac(&frame)?;
        Ok(frame)
    }

    fn verify(
        &mut self,
        frame: &AuthenticatedFrame,
        expected_kind: &str,
        now_ms: u64,
    ) -> Result<(), String> {
        if frame.version != FRAME_VERSION || frame.kind != expected_kind {
            return Err("IPC frame version or kind is invalid.".to_string());
        }
        if frame.nonce.len() < 16 || frame.nonce.len() > 128 {
            return Err("IPC nonce length is invalid.".to_string());
        }
        if frame.timestamp_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS)
            || now_ms.saturating_sub(frame.timestamp_ms) > MAX_CLOCK_SKEW_MS
        {
            return Err("IPC frame timestamp is outside the accepted window.".to_string());
        }
        if self.seen_nonces.contains_key(&frame.nonce) {
            return Err("IPC frame nonce was replayed.".to_string());
        }
        let supplied = URL_SAFE_NO_PAD
            .decode(&frame.mac)
            .map_err(|error| format!("IPC MAC is not valid base64url: {error}"))?;
        let mut verifier = HmacSha256::new_from_slice(&self.secret)
            .map_err(|_| "Unable to initialize IPC MAC.".to_string())?;
        verifier.update(
            &serde_jcs::to_vec(&MacContent {
                version: frame.version,
                kind: &frame.kind,
                nonce: &frame.nonce,
                timestamp_ms: frame.timestamp_ms,
                payload: &frame.payload,
            })
            .map_err(|error| format!("IPC canonicalization failed: {error}"))?,
        );
        verifier
            .verify_slice(&supplied)
            .map_err(|_| "IPC frame MAC verification failed.".to_string())?;
        self.seen_nonces
            .insert(frame.nonce.clone(), frame.timestamp_ms);
        self.prune(now_ms);
        Ok(())
    }

    fn compute_mac(&self, frame: &AuthenticatedFrame) -> Result<String, String> {
        let canonical = serde_jcs::to_vec(&MacContent {
            version: frame.version,
            kind: &frame.kind,
            nonce: &frame.nonce,
            timestamp_ms: frame.timestamp_ms,
            payload: &frame.payload,
        })
        .map_err(|error| format!("IPC canonicalization failed: {error}"))?;
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|_| "Unable to initialize IPC MAC.".to_string())?;
        mac.update(&canonical);
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    fn prune(&mut self, now_ms: u64) {
        self.seen_nonces.retain(|_, timestamp| {
            now_ms.saturating_sub(*timestamp) <= MAX_CLOCK_SKEW_MS
        });
        while self.seen_nonces.len() > MAX_REPLAY_ENTRIES {
            let Some(oldest) = self
                .seen_nonces
                .iter()
                .min_by_key(|(_, timestamp)| *timestamp)
                .map(|(nonce, _)| nonce.clone())
            else {
                break;
            };
            self.seen_nonces.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthenticatedFrame, IpcAuthenticator};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde_json::json;

    fn authenticator() -> IpcAuthenticator {
        IpcAuthenticator::from_base64_secret(&URL_SAFE_NO_PAD.encode([7_u8; 32])).unwrap()
    }

    fn signed_request(auth: &IpcAuthenticator, now_ms: u64) -> AuthenticatedFrame {
        let response = auth
            .sign_response(
                json!({"requestId": "req-1", "cmd": "ping", "payload": {}}),
                "nonce-1234567890".to_string(),
                now_ms,
            )
            .unwrap();
        let mut request = AuthenticatedFrame {
            kind: "request".to_string(),
            ..response
        };
        request.mac = auth.compute_mac(&request).unwrap();
        request
    }

    #[test]
    fn accepts_valid_request_and_rejects_replay() {
        let mut auth = authenticator();
        let frame = signed_request(&auth, 10_000);
        assert!(auth.verify_request(&frame, 10_001).is_ok());
        assert!(auth.verify_request(&frame, 10_002).is_err());
    }

    #[test]
    fn rejects_tampering_and_expired_timestamp() {
        let mut auth = authenticator();
        let mut frame = signed_request(&auth, 10_000);
        frame.payload["cmd"] = json!("shutdown");
        assert!(auth.verify_request(&frame, 10_001).is_err());

        let mut auth = authenticator();
        let frame = signed_request(&auth, 10_000);
        assert!(auth.verify_request(&frame, 50_001).is_err());
    }
}
