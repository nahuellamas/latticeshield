//! One-time VK download token store and HTTP handler.
//!
//! `VkShareStore` is initialised once at bridge startup and shared via Arc
//! between the admin endpoint handler (:8444) and the TLS listener (:8440).
//! Tokens are UUID v4, single-use, and expire after a configurable TTL.
//! Token state is in-memory only — lost on bridge restart (by design).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Default token TTL: 10 minutes (600 seconds) as per spec REQ-2.3.
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 600;

// ── Types ─────────────────────────────────────────────────────────────────────

/// A single token entry in the store.
pub struct VkShareEntry {
    pub vk_hex: String,
    pub fingerprint: String, // SHA-256 hex digest of the raw VK bytes (64 chars)
    pub expires_at: Instant,
    pub used: bool,
}

/// Shared in-memory token store.
/// `Arc<Mutex<...>>` — GET /vk/:token WRITES (marks used=true), so a Mutex
/// is correct and simpler than RwLock.
pub type VkShareStore = Arc<Mutex<HashMap<String, VkShareEntry>>>;

/// Creates a new, empty `VkShareStore`.
pub fn new_store() -> VkShareStore {
    Arc::new(Mutex::new(HashMap::new()))
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    hex_encode(&digest)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Creates a one-time download token for the given VK bytes.
///
/// Inserts the token into the store with the given TTL.
/// Returns `(token, fingerprint)` — token is UUID v4, fingerprint is SHA-256 hex.
pub fn create_token(store: &VkShareStore, vk_bytes: &[u8], ttl: Duration) -> (String, String) {
    let token = uuid::Uuid::new_v4().to_string();
    let vk_hex = hex_encode(vk_bytes);
    let fingerprint = sha256_hex(vk_bytes);
    let entry = VkShareEntry {
        vk_hex,
        fingerprint: fingerprint.clone(),
        expires_at: Instant::now() + ttl,
        used: false,
    };
    store
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(token.clone(), entry);
    (token, fingerprint)
}

/// Produces a raw HTTP/1.1 response for `GET /vk/:token`.
///
/// Checks token validity (exists, not expired, not used), marks the token as
/// used on success, and returns the response bytes to write to the TLS stream.
/// This function is synchronous — it only touches in-memory state.
pub fn vk_response(token: &str, store: &VkShareStore, peer: std::net::SocketAddr) -> Vec<u8> {
    let mut guard = store.lock().unwrap_or_else(|e| e.into_inner());
    match guard.get_mut(token) {
        None => {
            tracing::debug!(%peer, token, "vk-share: token not found");
            http_json_response(404, r#"{"error":"token not found"}"#)
        }
        Some(entry) if entry.expires_at < Instant::now() => {
            tracing::debug!(%peer, token, "vk-share: token expired");
            // Lazy expiry: remove the entry now that we know it's expired
            guard.remove(token);
            http_json_response(410, r#"{"error":"token expired"}"#)
        }
        Some(entry) if entry.used => {
            tracing::debug!(%peer, token, "vk-share: token already used");
            http_json_response(410, r#"{"error":"token already used"}"#)
        }
        Some(entry) => {
            entry.used = true;
            let body = format!(
                r#"{{"server_vk":"{}","fingerprint":"{}"}}"#,
                entry.vk_hex, entry.fingerprint
            );
            tracing::info!(%peer, token, "vk-share: token consumed successfully");
            http_json_response(200, &body)
        }
    }
}

fn http_json_response(status: u16, body: &str) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        410 => "Gone",
        _ => "Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    fn dummy_peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
    }

    fn dummy_vk_bytes() -> Vec<u8> {
        // Simulated VK bytes — 32 bytes of known data for deterministic tests
        (0u8..32).collect()
    }

    #[test]
    fn create_token_returns_uuid_v4() {
        let store = new_store();
        let vk_bytes = dummy_vk_bytes();
        let (token, _) = create_token(&store, &vk_bytes, Duration::from_secs(300));
        let parsed = uuid::Uuid::parse_str(&token).expect("token must be a valid UUID");
        assert_eq!(parsed.get_version_num(), 4, "token must be UUID v4");
    }

    #[test]
    fn create_token_fingerprint_is_sha256_hex() {
        let store = new_store();
        let vk_bytes = dummy_vk_bytes();
        let (_, fingerprint) = create_token(&store, &vk_bytes, Duration::from_secs(300));
        assert_eq!(fingerprint.len(), 64, "fingerprint must be 64 hex chars");
        assert!(
            fingerprint
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "fingerprint must be lowercase hex"
        );
    }

    #[test]
    fn create_token_inserted_in_store() {
        let store = new_store();
        let vk_bytes = dummy_vk_bytes();
        let (token, _) = create_token(&store, &vk_bytes, Duration::from_secs(300));
        assert!(
            store.lock().unwrap().contains_key(&token),
            "token must be present in store after create"
        );
    }

    #[test]
    fn vk_response_valid_token_returns_200() {
        let store = new_store();
        let vk_bytes = dummy_vk_bytes();
        let (token, _) = create_token(&store, &vk_bytes, Duration::from_secs(300));
        let response = vk_response(&token, &store, dummy_peer());
        let response_str = String::from_utf8(response).unwrap();
        assert!(
            response_str.starts_with("HTTP/1.1 200 OK"),
            "expected 200 OK, got: {response_str}"
        );
    }

    #[test]
    fn vk_response_marks_token_used() {
        let store = new_store();
        let vk_bytes = dummy_vk_bytes();
        let (token, _) = create_token(&store, &vk_bytes, Duration::from_secs(300));
        let _ = vk_response(&token, &store, dummy_peer());
        let guard = store.lock().unwrap();
        let entry = guard
            .get(&token)
            .expect("entry should still exist after use");
        assert!(entry.used, "entry.used must be true after first call");
    }

    #[test]
    fn vk_response_second_use_returns_410() {
        let store = new_store();
        let vk_bytes = dummy_vk_bytes();
        let (token, _) = create_token(&store, &vk_bytes, Duration::from_secs(300));
        let _ = vk_response(&token, &store, dummy_peer());
        let response2 = vk_response(&token, &store, dummy_peer());
        let response_str = String::from_utf8(response2).unwrap();
        assert!(
            response_str.starts_with("HTTP/1.1 410"),
            "second use must return 410 Gone, got: {response_str}"
        );
    }

    #[test]
    fn vk_response_expired_token_returns_410() {
        let store = new_store();
        let vk_bytes = dummy_vk_bytes();
        // TTL of 1 nanosecond — will be expired by the time we check
        let (token, _) = create_token(&store, &vk_bytes, Duration::from_nanos(1));
        std::thread::sleep(Duration::from_millis(5));
        let response = vk_response(&token, &store, dummy_peer());
        let response_str = String::from_utf8(response).unwrap();
        assert!(
            response_str.starts_with("HTTP/1.1 410"),
            "expired token must return 410 Gone, got: {response_str}"
        );
    }

    #[test]
    fn vk_response_unknown_token_returns_404() {
        let store = new_store();
        let response = vk_response("nonexistent-token", &store, dummy_peer());
        let response_str = String::from_utf8(response).unwrap();
        assert!(
            response_str.starts_with("HTTP/1.1 404"),
            "unknown token must return 404 Not Found, got: {response_str}"
        );
    }

    #[test]
    fn vk_response_body_contains_correct_fields() {
        let store = new_store();
        let vk_bytes = dummy_vk_bytes();
        let (token, expected_fp) = create_token(&store, &vk_bytes, Duration::from_secs(300));
        let response = vk_response(&token, &store, dummy_peer());
        let response_str = String::from_utf8(response).unwrap();
        // Extract body (after the blank line between headers and body)
        let body_start = response_str
            .find("\r\n\r\n")
            .expect("response must have header separator")
            + 4;
        let body: serde_json::Value =
            serde_json::from_str(&response_str[body_start..]).expect("body must be valid JSON");
        let server_vk = body["server_vk"]
            .as_str()
            .expect("server_vk must be present");
        let fingerprint = body["fingerprint"]
            .as_str()
            .expect("fingerprint must be present");
        assert_eq!(
            server_vk,
            hex_encode(&vk_bytes),
            "server_vk must match hex-encoded VK bytes"
        );
        assert_eq!(
            fingerprint, expected_fp,
            "fingerprint must match create_token output"
        );
    }

    #[test]
    fn hex_encode_known_value() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn sha256_hex_known_value() {
        // SHA-256 of empty byte slice — well-known constant
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(sha256_hex(&[]), expected);
    }

    #[test]
    fn create_token_recovers_from_poisoned_mutex() {
        let store = new_store();
        let store_clone = Arc::clone(&store);

        // Poison the mutex by panicking while holding the lock
        let _ = std::panic::catch_unwind(|| {
            let _guard = store_clone.lock().unwrap();
            panic!("intentional poison");
        });

        // Verify the mutex is poisoned
        assert!(store.lock().is_err(), "mutex should be poisoned");

        // create_token must not panic — should recover via unwrap_or_else and insert the token
        let vk_bytes = dummy_vk_bytes();
        let (token, _fingerprint) = create_token(&store, &vk_bytes, Duration::from_secs(300));

        // Token was actually inserted — recover from poison to inspect
        let guard = store.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            guard.contains_key(&token),
            "token must be present after create_token on poisoned mutex"
        );
    }

    #[test]
    fn vk_response_recovers_from_poisoned_mutex() {
        let store = new_store();
        let vk_bytes = dummy_vk_bytes();

        // Insert a token normally before poisoning
        let (token, _) = create_token(&store, &vk_bytes, Duration::from_secs(300));

        // Poison the mutex
        let store_clone = Arc::clone(&store);
        let _ = std::panic::catch_unwind(|| {
            let _guard = store_clone.lock().unwrap();
            panic!("intentional poison");
        });

        // vk_response must not panic — should recover via unwrap_or_else and return a valid response
        let response = vk_response(&token, &store, dummy_peer());
        let response_str = String::from_utf8(response).unwrap();

        // Token was inserted before poison, so it must still be found — expect 200
        assert!(
            response_str.starts_with("HTTP/1.1 200 OK"),
            "vk_response on poisoned mutex must not panic and must return 200, got: {response_str}"
        );
    }

    /// REQ-7.4-A: `GET /vk/:token` response body MUST contain only `server_vk`
    /// and `fingerprint` — no other keys (in particular, no signing key material).
    #[test]
    fn vk_response_body_contains_only_vk_and_fingerprint_fields() {
        let store = new_store();
        let vk_bytes = dummy_vk_bytes();
        let (token, _) = create_token(&store, &vk_bytes, Duration::from_secs(300));
        let response = vk_response(&token, &store, dummy_peer());
        let response_str = String::from_utf8(response).unwrap();
        let body_start = response_str
            .find("\r\n\r\n")
            .expect("response must have header separator")
            + 4;
        let body: serde_json::Value =
            serde_json::from_str(&response_str[body_start..]).expect("body must be valid JSON");
        let obj = body.as_object().expect("body must be a JSON object");
        // Only the two allowed fields must be present
        assert!(obj.contains_key("server_vk"), "server_vk must be present");
        assert!(
            obj.contains_key("fingerprint"),
            "fingerprint must be present"
        );
        assert_eq!(
            obj.len(),
            2,
            "response must contain ONLY server_vk and fingerprint, got keys: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }
}
