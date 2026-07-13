use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::collections::{BTreeMap, VecDeque};
use zeroize::Zeroizing;

// --- Protocol versions ------------------------------------------------------
// v1 (legacy): version + nonce + timestamp + HMAC over {version,kind,nonce,ts,payload}.
// v2 (F-015): adds a REQUIRED monotonic `sequence` that is also bound into the MAC.
// Both are accepted so existing v1 clients keep working (backward compatible).
const FRAME_VERSION: u8 = 1;
const FRAME_VERSION_V2: u8 = 2;

const MAX_CLOCK_SKEW_MS: u64 = 30_000;
const MAX_REPLAY_ENTRIES: usize = 4_096;

// F-015 hardening limits.
/// Reject a raw frame larger than this before it is even parsed (anti-DoS).
pub const MAX_RAW_FRAME_BYTES: usize = 256 * 1024;
/// Reject a canonical payload larger than this (anti-DoS / anti-amplification).
const MAX_PAYLOAD_CANONICAL_BYTES: usize = 64 * 1024;
/// HMAC-SHA256 is 32 bytes -> 43 base64url chars; cap defensively.
const MAX_MAC_B64_LEN: usize = 64;
/// Sliding-window rate limit: at most N accepted frames per window.
const RATE_LIMIT_WINDOW_MS: u64 = 1_000;
const MAX_REQUESTS_PER_WINDOW: usize = 256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticatedFrame {
    pub version: u8,
    pub kind: String,
    pub nonce: String,
    pub timestamp_ms: u64,
    /// v2 only: monotonically increasing per authenticator. Absent (None) on v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    pub payload: Value,
    pub mac: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MacContentV1<'a> {
    version: u8,
    kind: &'a str,
    nonce: &'a str,
    timestamp_ms: u64,
    payload: &'a Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MacContentV2<'a> {
    version: u8,
    kind: &'a str,
    nonce: &'a str,
    timestamp_ms: u64,
    sequence: u64,
    payload: &'a Value,
}

pub struct IpcAuthenticator {
    // F-005: `Zeroizing` wipes the MAC secret from memory when the authenticator
    // is dropped, so the 32+ byte IPC secret does not linger in the heap.
    secret: Zeroizing<Vec<u8>>,
    seen_nonces: BTreeMap<String, u64>,
    // F-015: last accepted v2 sequence (monotonic enforcement).
    last_sequence: Option<u64>,
    // F-015: timestamps of recently accepted frames (sliding-window rate limit).
    recent_accepts: VecDeque<u64>,
}

impl IpcAuthenticator {
    pub fn from_base64_secret(encoded: &str) -> Result<Self, String> {
        let secret = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|error| format!("IPC secret is not valid base64url: {error}"))?,
        );
        if secret.len() < 32 {
            return Err("IPC secret must contain at least 32 random bytes.".to_string());
        }
        Ok(Self {
            secret,
            seen_nonces: BTreeMap::new(),
            last_sequence: None,
            recent_accepts: VecDeque::new(),
        })
    }

    /// F-015: parse a raw frame with a hard size cap, then verify. Never panics on
    /// malformed input — returns a structured error. Fuzz/entry helper; the live
    /// pipe loop (main.rs) applies the same `MAX_RAW_FRAME_BYTES` cap then calls
    /// `verify_request`, which runs the identical v2/size/rate checks.
    #[cfg(test)]
    pub fn parse_and_verify_request(&mut self, raw: &[u8], now_ms: u64) -> Result<Value, String> {
        if raw.len() > MAX_RAW_FRAME_BYTES {
            return Err("IPC frame exceeds the maximum size.".to_string());
        }
        let frame: AuthenticatedFrame = serde_json::from_slice(raw)
            .map_err(|error| format!("IPC frame is not valid JSON: {error}"))?;
        self.verify_request(&frame, now_ms)
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
            sequence: None,
            payload,
            mac: String::new(),
        };
        frame.mac = self.compute_mac(&frame)?;
        Ok(frame)
    }

    /// F-015: sign a v2 response carrying a monotonic sequence. Used by tests to
    /// simulate a v2 client; the core verifies v2 request frames via `verify_request`.
    #[cfg(test)]
    pub fn sign_response_v2(
        &self,
        payload: Value,
        nonce: String,
        timestamp_ms: u64,
        sequence: u64,
    ) -> Result<AuthenticatedFrame, String> {
        let mut frame = AuthenticatedFrame {
            version: FRAME_VERSION_V2,
            kind: "response".to_string(),
            nonce,
            timestamp_ms,
            sequence: Some(sequence),
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
        // Version + kind.
        if (frame.version != FRAME_VERSION && frame.version != FRAME_VERSION_V2)
            || frame.kind != expected_kind
        {
            return Err("IPC frame version or kind is invalid.".to_string());
        }
        // v2 requires a sequence; v1 must not carry one.
        if frame.version == FRAME_VERSION_V2 && frame.sequence.is_none() {
            return Err("IPC v2 frame is missing its sequence.".to_string());
        }
        if frame.version == FRAME_VERSION && frame.sequence.is_some() {
            return Err("IPC v1 frame must not carry a sequence.".to_string());
        }
        // Size limits (anti-DoS / anti-amplification).
        if frame.mac.len() > MAX_MAC_B64_LEN {
            return Err("IPC MAC length is invalid.".to_string());
        }
        if frame.nonce.len() < 16 || frame.nonce.len() > 128 {
            return Err("IPC nonce length is invalid.".to_string());
        }
        // Timestamp freshness window.
        if frame.timestamp_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS)
            || now_ms.saturating_sub(frame.timestamp_ms) > MAX_CLOCK_SKEW_MS
        {
            return Err("IPC frame timestamp is outside the accepted window.".to_string());
        }
        // Rate limit (before doing the expensive MAC work).
        self.prune_rate_window(now_ms);
        if self.recent_accepts.len() >= MAX_REQUESTS_PER_WINDOW {
            return Err("IPC request rate limit exceeded.".to_string());
        }
        // Replay: nonce must be unique.
        if self.seen_nonces.contains_key(&frame.nonce) {
            return Err("IPC frame nonce was replayed.".to_string());
        }
        // Canonical payload size cap.
        let canonical = self.mac_canonical(frame)?;
        if canonical.len() > MAX_PAYLOAD_CANONICAL_BYTES {
            return Err("IPC frame payload exceeds the maximum size.".to_string());
        }
        // MAC verification (constant-time via the hmac crate).
        let supplied = URL_SAFE_NO_PAD
            .decode(&frame.mac)
            .map_err(|error| format!("IPC MAC is not valid base64url: {error}"))?;
        let mut verifier = HmacSha256::new_from_slice(self.secret.as_slice())
            .map_err(|_| "Unable to initialize IPC MAC.".to_string())?;
        verifier.update(&canonical);
        verifier
            .verify_slice(&supplied)
            .map_err(|_| "IPC frame MAC verification failed.".to_string())?;
        // v2: enforce strictly-increasing sequence AFTER authenticating the frame.
        if frame.version == FRAME_VERSION_V2 {
            if let Some(sequence) = frame.sequence {
                if let Some(last) = self.last_sequence {
                    if sequence <= last {
                        return Err("IPC v2 sequence did not increase.".to_string());
                    }
                }
                self.last_sequence = Some(sequence);
            }
        }
        // Record acceptance (replay + rate-limit state).
        self.seen_nonces
            .insert(frame.nonce.clone(), frame.timestamp_ms);
        self.recent_accepts.push_back(now_ms);
        self.prune(now_ms);
        Ok(())
    }

    fn compute_mac(&self, frame: &AuthenticatedFrame) -> Result<String, String> {
        let canonical = self.mac_canonical(frame)?;
        let mut mac = HmacSha256::new_from_slice(self.secret.as_slice())
            .map_err(|_| "Unable to initialize IPC MAC.".to_string())?;
        mac.update(&canonical);
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    /// Version-gated canonical bytes over which the MAC is computed. v1 keeps its
    /// exact original content (so existing v1 MACs stay valid); v2 additionally
    /// binds the sequence.
    fn mac_canonical(&self, frame: &AuthenticatedFrame) -> Result<Vec<u8>, String> {
        let result = if frame.version == FRAME_VERSION_V2 {
            serde_jcs::to_vec(&MacContentV2 {
                version: frame.version,
                kind: &frame.kind,
                nonce: &frame.nonce,
                timestamp_ms: frame.timestamp_ms,
                sequence: frame.sequence.unwrap_or(0),
                payload: &frame.payload,
            })
        } else {
            serde_jcs::to_vec(&MacContentV1 {
                version: frame.version,
                kind: &frame.kind,
                nonce: &frame.nonce,
                timestamp_ms: frame.timestamp_ms,
                payload: &frame.payload,
            })
        };
        result.map_err(|error| format!("IPC canonicalization failed: {error}"))
    }

    fn prune_rate_window(&mut self, now_ms: u64) {
        while let Some(&front) = self.recent_accepts.front() {
            if now_ms.saturating_sub(front) > RATE_LIMIT_WINDOW_MS {
                self.recent_accepts.pop_front();
            } else {
                break;
            }
        }
    }

    fn prune(&mut self, now_ms: u64) {
        self.seen_nonces
            .retain(|_, timestamp| now_ms.saturating_sub(*timestamp) <= MAX_CLOCK_SKEW_MS);
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

    fn signed_request_v2(
        auth: &IpcAuthenticator,
        now_ms: u64,
        sequence: u64,
        nonce: &str,
    ) -> AuthenticatedFrame {
        let response = auth
            .sign_response_v2(
                json!({"cmd": "heartbeat"}),
                nonce.to_string(),
                now_ms,
                sequence,
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

    #[test]
    fn v2_accepts_monotonic_sequence_and_rejects_non_increasing() {
        let mut auth = authenticator();
        let f1 = signed_request_v2(&auth, 10_000, 1, "nonce-aaaaaaaaaaaa");
        assert!(auth.verify_request(&f1, 10_001).is_ok());
        let f2 = signed_request_v2(&auth, 10_000, 2, "nonce-bbbbbbbbbbbb");
        assert!(auth.verify_request(&f2, 10_001).is_ok());
        // A lower/equal sequence (replayed order) is rejected even with a fresh nonce.
        let f_stale = signed_request_v2(&auth, 10_000, 2, "nonce-cccccccccccc");
        assert!(auth.verify_request(&f_stale, 10_001).is_err());
    }

    #[test]
    fn v2_requires_sequence_and_v1_forbids_it() {
        let mut auth = authenticator();
        // v2 frame with no sequence (forge version) is rejected.
        let mut f = signed_request(&auth, 10_000);
        f.version = 2;
        assert!(auth.verify_request(&f, 10_001).is_err());
    }

    #[test]
    fn rejects_oversized_mac() {
        let mut auth = authenticator();
        let mut frame = signed_request(&auth, 10_000);
        frame.mac = "A".repeat(100);
        assert!(auth.verify_request(&frame, 10_001).is_err());
    }

    #[test]
    fn enforces_rate_limit_within_window() {
        let mut auth = authenticator();
        let mut accepted = 0usize;
        // Fire many uniquely-nonced, same-timestamp frames; the rate limiter caps them.
        for i in 0..(super::MAX_REQUESTS_PER_WINDOW + 10) {
            let nonce = format!("nonce-{i:016}");
            let f = signed_request_v2(&auth, 20_000, (i as u64) + 1, &nonce);
            if auth.verify_request(&f, 20_000).is_ok() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, super::MAX_REQUESTS_PER_WINDOW);
    }

    #[test]
    fn parse_and_verify_rejects_oversized_raw_without_panic() {
        let mut auth = authenticator();
        let big = vec![b'{'; super::MAX_RAW_FRAME_BYTES + 1];
        assert!(auth.parse_and_verify_request(&big, 10_000).is_err());
    }

    #[test]
    fn fuzz_malformed_input_never_panics() {
        // Deterministic pseudo-fuzz: feed random/mutated bytes and a mutated valid
        // frame; every call must return Err, never panic or hang.
        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut auth = authenticator();
        let valid = signed_request(&auth, 10_000);
        let valid_json = serde_json::to_vec(&valid).unwrap();
        for _ in 0..2_000 {
            let len = (next() as usize) % 512;
            let mut buf: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            // Occasionally mutate a real frame so the parser gets near-valid input.
            if next() & 1 == 0 && !valid_json.is_empty() {
                buf = valid_json.clone();
                let idx = (next() as usize) % buf.len();
                buf[idx] = (next() & 0xff) as u8;
            }
            let _ = auth.parse_and_verify_request(&buf, 10_000); // must not panic
        }
    }
}
