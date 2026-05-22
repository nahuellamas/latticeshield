//! Control plane heartbeat client.
//!
//! Registers the bridge agent on startup and sends periodic heartbeat POSTs.
//! All failures are non-fatal — the proxy continues operating if the control
//! plane is unreachable.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::ValidConfig;
use crate::identity::ServerIdentity;
use crate::metrics::MetricsState;

use latticeshield_crypto::signing::{Signature, VerifyingKey, VERIFYING_KEY_LEN};

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct RegistrationPayload {
    name: String,
    version: String,
    capabilities: Vec<String>,
    listen_addr: String,
    server_vk: String, // lowercase hex-encoded ML-DSA-65 VerifyingKey (3904 chars)
    #[serde(skip_serializing_if = "Option::is_none")]
    install_token: Option<String>,
}

#[derive(Deserialize)]
struct RegistrationResponse {
    agent_id: String,
}

#[derive(Serialize)]
struct SignableHeartbeatPayload {
    timestamp_unix: u64,
    uptime_secs: u64,
    status: &'static str,
    version: &'static str,
    metrics: HeartbeatMetrics,
}

#[derive(Serialize)]
struct SignedHeartbeatPayload {
    timestamp_unix: u64,
    uptime_secs: u64,
    status: &'static str,
    version: &'static str,
    metrics: HeartbeatMetrics,
    signature: String,
}

#[derive(Debug, Deserialize, Default)]
struct HeartbeatResponse {
    /// Legacy field — used only when `cloud_vk` is NOT configured (backward compat).
    /// When `cloud_vk` IS configured, this field is ignored; commands come from
    /// the signed inner payload.
    #[serde(default)]
    pending_commands: Option<Vec<BridgeCommand>>,

    /// New wire format (required when `cloud_vk_path` is set).
    /// Raw JSON string containing the canonical signed payload — the cloud
    /// serializes it ONCE and signs the exact bytes. The bridge verifies the
    /// signature over `signed_payload.as_bytes()` directly, eliminating any
    /// JSON-canonicalization mismatch between sides (C-R1).
    #[serde(default)]
    signed_payload: Option<String>,

    /// ML-DSA-65 signature (base64) over `signed_payload.as_bytes()`.
    #[serde(default)]
    response_signature: Option<String>,
}

/// Inner payload that the cloud signs.
/// Wire format: `{"pending_commands": [...], "ts": <unix_seconds>}`.
/// `ts` is freshness anchor — bridge rejects when `|now - ts| > 300` (C-R2 replay protection).
#[derive(Debug, Deserialize)]
struct SignedResponsePayload {
    #[serde(default)]
    pending_commands: Option<Vec<BridgeCommand>>,
    /// Unix seconds at signing time. Used for freshness window enforcement.
    ts: i64,
}

/// Maximum allowed drift between `signed_payload.ts` and the bridge's wall clock.
/// Replay protection: any captured signed response older (or further future) than
/// this is dropped. 5 minutes is a generous window that tolerates clock skew without
/// allowing meaningful replay windows.
const SIGNED_RESPONSE_FRESHNESS_SECS: i64 = 300;

/// Hard cap on the heartbeat response body buffered into memory.
/// A compromised or misbehaving cloud endpoint advertising or streaming a huge
/// body would otherwise OOM the bridge. 1 MiB is generous for legitimate
/// payloads (signed_payload is dominated by a base64 ML-DSA-65 signature ≈ 4416
/// chars + a small JSON envelope).
const MAX_HEARTBEAT_RESPONSE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum BridgeCommand {
    Rotate,
    #[serde(other)]
    Unknown,
}

#[derive(Serialize, Clone)]
struct HeartbeatMetrics {
    connections_active: u64,
    connections_total: u64,
    bytes_transmitted_total: u64,
    channel_errors_total: u64,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Registers the agent and starts the heartbeat loop.
/// Non-fatal: logs warnings on any failure, never panics.
pub async fn start(
    config: ValidConfig,
    metrics: Arc<MetricsState>,
    identity: Arc<ServerIdentity>,
    cmd_tx: tokio::sync::mpsc::Sender<BridgeCommand>,
    mut shutdown_rx: tokio::sync::watch::Receiver<()>,
) {
    // ── Load cloud VK for HeartbeatResponse signature verification (C1/H6) ──
    // If cloud_vk_path is set: load the VK and require signatures on responses.
    // If not set: warn and proceed without verification (backward compat).
    let cloud_vk: Option<Arc<VerifyingKey>> = match &config.cloud_vk_path {
        Some(path) => match load_cloud_vk(path) {
            Ok(vk) => {
                info!(path = %path.display(), "cloud verifying key loaded — HeartbeatResponse commands will be signature-verified");
                Some(Arc::new(vk))
            }
            Err(e) => {
                warn!("control plane: failed to load cloud_vk_path '{}': {e} — BridgeCommand verification disabled", path.display());
                None
            }
        },
        None => None, // startup warning already emitted in config validation (H5)
    };

    let client = match Client::builder().timeout(Duration::from_secs(10)).build() {
        Ok(c) => c,
        Err(e) => {
            warn!("control plane: failed to build HTTP client: {e}");
            return;
        }
    };

    let agent_id = match try_register(&client, &config, &identity).await {
        Some(id) => id,
        None => {
            warn!("control plane: registration failed, heartbeat disabled");
            return;
        }
    };

    let started_at = Instant::now();
    let mut rng = rand_core::OsRng;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(config.heartbeat_interval) => { /* send heartbeat below */ }
            _ = shutdown_rx.changed() => {
                info!("control_plane: shutdown signal, stopping heartbeat");
                break;
            }
        }

        let snapshot = metrics.snapshot();
        let signable = SignableHeartbeatPayload {
            timestamp_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            uptime_secs: started_at.elapsed().as_secs(),
            status: "healthy",
            version: env!("CARGO_PKG_VERSION"),
            metrics: HeartbeatMetrics {
                connections_active: snapshot.connections_active,
                connections_total: snapshot.connections_total,
                bytes_transmitted_total: snapshot.bytes_transmitted_total,
                channel_errors_total: snapshot.channel_errors_total,
            },
        };

        match send_heartbeat(
            &client,
            &config,
            &agent_id,
            &signable,
            &identity,
            &mut rng,
            cloud_vk.as_deref(),
        )
        .await
        {
            Ok(hb_resp) => {
                for cmd in hb_resp.pending_commands.unwrap_or_default() {
                    match cmd {
                        BridgeCommand::Unknown => {
                            tracing::warn!("unknown BridgeCommand received, skipping");
                        }
                        cmd => {
                            if let Err(e) = cmd_tx.send(cmd).await {
                                tracing::warn!("BridgeCommand channel closed: {e}");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("control plane: heartbeat failed (will retry): {e:#}");
            }
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

async fn try_register(
    client: &Client,
    config: &ValidConfig,
    identity: &ServerIdentity,
) -> Option<String> {
    let server_vk: String = identity
        .verifying_key
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let payload = RegistrationPayload {
        name: config.control_plane_agent_name.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec![
            "pqc-proxy".to_string(),
            "ml-kem-768".to_string(),
            "ml-dsa-65".to_string(),
        ],
        listen_addr: config.listen_addr.to_string(),
        server_vk,
        install_token: config.control_plane_install_token.clone(),
    };

    let url = format!("{}/api/v1/agents/register", config.control_plane_endpoint);
    let resp = match client.post(&url).json(&payload).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!("control plane: registration request failed: {e}");
            return None;
        }
    };

    let status = resp.status();
    if !status.is_success() {
        warn!(status = %status, "control plane: registration rejected");
        return None;
    }

    match resp.json::<RegistrationResponse>().await {
        Ok(body) => {
            info!(agent_id = %body.agent_id, endpoint = %config.control_plane_endpoint,
                  "registered with control plane");
            Some(body.agent_id)
        }
        Err(e) => {
            warn!("control plane: failed to parse registration response: {e}");
            None
        }
    }
}

async fn send_heartbeat(
    client: &Client,
    config: &ValidConfig,
    agent_id: &str,
    signable: &SignableHeartbeatPayload,
    identity: &ServerIdentity,
    rng: &mut impl rand_core::CryptoRngCore,
    cloud_vk: Option<&VerifyingKey>,
) -> anyhow::Result<HeartbeatResponse> {
    // 1. Canonical bytes
    let canonical = serde_json::to_vec(signable)
        .map_err(|e| anyhow::anyhow!("heartbeat serialize failed: {e}"))?;

    // 2. Sign with ML-DSA-65
    let sig = latticeshield_crypto::signing::sign(&identity.signing_key, &canonical, rng)
        .map_err(|e| anyhow::anyhow!("heartbeat sign failed: {e:?}"))?;

    // 3. Base64-encode
    let signature = STANDARD.encode(sig.to_bytes());

    // 4. Build flat signed payload
    let signed = SignedHeartbeatPayload {
        timestamp_unix: signable.timestamp_unix,
        uptime_secs: signable.uptime_secs,
        status: signable.status,
        version: signable.version,
        metrics: signable.metrics.clone(),
        signature,
    };

    // 5. POST
    let url = format!(
        "{}/api/v1/agents/{}/heartbeat",
        config.control_plane_endpoint.trim_end_matches('/'),
        agent_id
    );
    let resp = client
        .post(&url)
        .json(&signed)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("heartbeat request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("heartbeat non-2xx: {}", resp.status()));
    }

    // 6. Read response body, bounded by MAX_HEARTBEAT_RESPONSE_BYTES.
    //    Reject any advertised Content-Length that exceeds the cap before buffering.
    //    Defense against a hostile cloud sending an unbounded body to OOM the bridge.
    if let Some(len) = resp.content_length() {
        if len > MAX_HEARTBEAT_RESPONSE_BYTES {
            return Err(anyhow::anyhow!(
                "heartbeat response too large: content-length={len} bytes (max={MAX_HEARTBEAT_RESPONSE_BYTES})"
            ));
        }
    }
    let body_bytes = resp
        .bytes()
        .await
        .map_err(|e| anyhow::anyhow!("heartbeat read body failed: {e}"))?;
    if body_bytes.len() as u64 > MAX_HEARTBEAT_RESPONSE_BYTES {
        return Err(anyhow::anyhow!(
            "heartbeat response too large: {} bytes (max={MAX_HEARTBEAT_RESPONSE_BYTES})",
            body_bytes.len()
        ));
    }
    let hb_resp: HeartbeatResponse = serde_json::from_slice(&body_bytes).unwrap_or_default();

    // 7. If cloud VK is configured, verify ML-DSA-65 signature over signed_payload (C1/H6).
    //    Wire format: {"signed_payload": "<raw JSON>", "response_signature": "<b64>"}.
    //    signed_payload parses to {"pending_commands": [...], "ts": <unix_seconds>}.
    //    The cloud serializes the inner payload ONCE and signs `signed_payload.as_bytes()`
    //    exactly — bridge verifies over the same bytes (no canonicalization mismatch, C-R1).
    //    Freshness: |now - ts| <= SIGNED_RESPONSE_FRESHNESS_SECS (replay protection, C-R2).
    if let Some(vk) = cloud_vk {
        let signed_payload = match &hb_resp.signed_payload {
            None => {
                warn!("control plane: cloud_vk_path is set but response has no signed_payload — dropping all pending commands");
                return Ok(HeartbeatResponse::default());
            }
            Some(s) => s,
        };
        let sig_b64 = match &hb_resp.response_signature {
            None => {
                warn!("control plane: cloud_vk_path is set but response has no response_signature — dropping all pending commands");
                return Ok(HeartbeatResponse::default());
            }
            Some(s) => s,
        };

        // All malformed-signature failures degrade to "drop commands" instead of propagating an
        // error. This keeps the operator-visible failure mode coherent: every verification path
        // returns Ok(default()) with a warn!, so a bad cloud response never crashes the loop.
        let sig_bytes = match STANDARD.decode(sig_b64) {
            Ok(b) => b,
            Err(e) => {
                warn!("control plane: cloud sig base64 decode failed ({e}) — dropping all pending commands");
                return Ok(HeartbeatResponse::default());
            }
        };
        let sig = match Signature::from_bytes(&sig_bytes) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "control plane: cloud sig parse failed ({e:?}) — dropping all pending commands"
                );
                return Ok(HeartbeatResponse::default());
            }
        };

        // Verify over the EXACT bytes of signed_payload — no re-serialization.
        if let Err(e) = latticeshield_crypto::signing::verify(vk, signed_payload.as_bytes(), &sig) {
            warn!("control plane: cloud response signature verification FAILED ({e:?}) — dropping all pending commands");
            return Ok(HeartbeatResponse::default());
        }

        // Parse the (now-verified) inner payload.
        let inner: SignedResponsePayload = match serde_json::from_str(signed_payload) {
            Ok(p) => p,
            Err(e) => {
                warn!("control plane: signed_payload JSON parse failed ({e}) — dropping all pending commands");
                return Ok(HeartbeatResponse::default());
            }
        };

        // Freshness check — drops captured replays older than the window.
        // checked_sub guards against `i64::MIN` ts → otherwise (now - i64::MIN) overflows.
        // In debug builds the overflow panics; in release it wraps to a safe-but-wrong value.
        // Saturating to i64::MAX makes the drift test reject the response in BOTH profiles.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let drift = now
            .checked_sub(inner.ts)
            .map(|d| d.saturating_abs())
            .unwrap_or(i64::MAX);
        if drift > SIGNED_RESPONSE_FRESHNESS_SECS {
            warn!(
                drift_secs = drift,
                ts = inner.ts,
                now = now,
                "control plane: signed response outside freshness window — dropping all pending commands (replay protection)"
            );
            return Ok(HeartbeatResponse::default());
        }

        return Ok(HeartbeatResponse {
            pending_commands: inner.pending_commands,
            signed_payload: None,
            response_signature: None,
        });
    }

    // 8. No cloud VK configured — return response without verification (backward compat).
    //    Reads `pending_commands` directly from the top-level envelope.
    Ok(hb_resp)
}

/// Load a cloud ML-DSA-65 VerifyingKey from a raw binary file.
/// The file must contain exactly VERIFYING_KEY_LEN bytes.
fn load_cloud_vk(path: &std::path::Path) -> anyhow::Result<VerifyingKey> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("cannot read cloud_vk_path '{}': {e}", path.display()))?;
    if bytes.len() != VERIFYING_KEY_LEN {
        anyhow::bail!(
            "cloud_vk_path '{}' has {} bytes; expected {} (ML-DSA-65 VerifyingKey)",
            path.display(),
            bytes.len(),
            VERIFYING_KEY_LEN
        );
    }
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("cloud_vk_path '{}' parse failed: {e:?}", path.display()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn init_crypto() {
        static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        INIT.get_or_init(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    fn make_test_identity() -> (Arc<ServerIdentity>, TempDir) {
        let dir = TempDir::new().unwrap();
        ServerIdentity::generate_and_save(dir.path()).unwrap();
        let identity = ServerIdentity::load(&dir.path().join("server.sk")).unwrap();
        (Arc::new(identity), dir)
    }

    fn make_config(endpoint: String) -> ValidConfig {
        ValidConfig {
            listen_addr: "127.0.0.1:8443".parse().unwrap(),
            backend_addr: "127.0.0.1:8080".parse().unwrap(),
            metrics_addr: "127.0.0.1:8444".parse().unwrap(),
            max_frame_size: 65536,
            handshake_timeout_secs: 10,
            max_connections_per_ip: 50,
            signing_key_path: std::path::PathBuf::from("./keys/server.sk"),
            log_level: "info".to_string(),
            control_plane_enabled: true,
            control_plane_endpoint: endpoint,
            control_plane_agent_name: "test-agent".to_string(),
            heartbeat_interval: Duration::from_secs(30),
            key_rotation_enabled: false,
            max_bytes_per_key: 10_737_418_240,
            key_rotation_interval: Duration::from_secs(86_400),
            tls_enabled: false,
            tls_listen_addr: "127.0.0.1:8440".parse().unwrap(),
            tls_cert_path: std::path::PathBuf::from("./keys/tls.crt"),
            tls_key_path: std::path::PathBuf::from("./keys/tls.key"),
            quic_enabled: false,
            quic_listen_addr: "127.0.0.1:8441".parse().unwrap(),
            quic_cert_path: std::path::PathBuf::from("./keys/tls.crt"),
            quic_key_path: std::path::PathBuf::from("./keys/tls.key"),
            client_auth_enabled: false,
            client_vk_path: None,
            admin_enabled: false,
            admin_listen_addr: "127.0.0.1:0".parse().unwrap(),
            admin_control_plane_vk_path: None,
            admin_rate_limit_per_second: 5,
            admin_handshake_timeout_secs: 10,
            control_plane_install_token: None,
            cloud_vk_path: None,
            shutdown_timeout: Duration::from_secs(30),
            ws_enabled: false,
            ws_listen_addr: "127.0.0.1:8446".parse().unwrap(),
            ws_cert_path: std::path::PathBuf::from("./keys/ws.crt"),
            ws_key_path: std::path::PathBuf::from("./keys/ws.key"),
            ws_allowed_origins: Vec::new(),
            ws_handshake_timeout_secs: 10,
            ws_max_connections_per_ip: 100,
            vk_share_max_tokens: 1000,
        }
    }

    #[tokio::test]
    async fn registration_success_stores_agent_id() {
        init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/register"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({ "agent_id": "test-id-42" })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let agent_id = try_register(&client, &config, &identity).await;
        assert_eq!(agent_id, Some("test-id-42".to_string()));
    }

    #[tokio::test]
    async fn registration_failure_returns_none() {
        init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/register"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let result = try_register(&client, &config, &identity).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn registration_body_contains_correct_capabilities() {
        init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/register"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "agent_id": "cap-test" })),
            )
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let agent_id = try_register(&client, &config, &identity).await;
        assert!(agent_id.is_some());

        // Verify the request body contained correct capabilities via the received requests
        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        let caps = body["capabilities"].as_array().unwrap();
        let cap_strs: Vec<&str> = caps.iter().map(|c| c.as_str().unwrap()).collect();
        assert_eq!(cap_strs, vec!["pqc-proxy", "ml-kem-768", "ml-dsa-65"]);
    }

    #[tokio::test]
    async fn registration_body_contains_server_vk() {
        init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/register"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "agent_id": "vk-test" })),
            )
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let agent_id = try_register(&client, &config, &identity).await;
        assert!(agent_id.is_some());

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        let server_vk = body["server_vk"]
            .as_str()
            .expect("server_vk must be present in payload");
        assert_eq!(
            server_vk.len(),
            3904,
            "server_vk must be 3904 hex chars (1952 bytes * 2)"
        );
        assert!(
            server_vk
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f')),
            "server_vk must be lowercase hex"
        );
    }

    // ── Heartbeat tests ───────────────────────────────────────────────────────

    fn make_signable() -> SignableHeartbeatPayload {
        SignableHeartbeatPayload {
            timestamp_unix: 1_700_000_000,
            uptime_secs: 42,
            status: "healthy",
            version: "0.0.0",
            metrics: HeartbeatMetrics {
                connections_active: 1,
                connections_total: 10,
                bytes_transmitted_total: 1024,
                channel_errors_total: 0,
            },
        }
    }

    #[tokio::test]
    async fn heartbeat_url_includes_agent_id() {
        init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng = rand_core::OsRng;

        let result = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng,
            None,
        )
        .await;
        assert!(result.is_ok(), "send_heartbeat failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn heartbeat_body_contains_base64_signature() {
        init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng = rand_core::OsRng;

        send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng,
            None,
        )
        .await
        .unwrap();

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();

        let sig_b64 = body["signature"]
            .as_str()
            .expect("signature field must be present");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .expect("signature must be valid base64");
        assert_eq!(
            decoded.len(),
            latticeshield_crypto::signing::SIGNATURE_LEN,
            "decoded signature must be exactly {} bytes",
            latticeshield_crypto::signing::SIGNATURE_LEN
        );
    }

    #[tokio::test]
    async fn heartbeat_signature_verifies_with_verifying_key() {
        init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng = rand_core::OsRng;

        send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng,
            None,
        )
        .await
        .unwrap();

        let received = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();

        // Reconstruct the canonical bytes from the signable (same struct, same field order)
        let canonical = serde_json::to_vec(&signable).unwrap();

        // Decode the base64 signature
        let sig_b64 = body["signature"].as_str().unwrap();
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .unwrap();
        let sig = latticeshield_crypto::signing::Signature::from_bytes(&sig_bytes).unwrap();

        // Verify against the bridge's verifying key
        assert!(
            latticeshield_crypto::signing::verify(&identity.verifying_key, &canonical, &sig)
                .is_ok(),
            "signature must verify with the bridge's verifying key"
        );
    }

    #[tokio::test]
    async fn heartbeat_response_empty_body_returns_default() {
        init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng = rand_core::OsRng;

        let resp = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng,
            None,
        )
        .await
        .unwrap();

        assert!(
            resp.pending_commands.is_none(),
            "empty body should yield pending_commands: None, got: {:?}",
            resp.pending_commands
        );
    }

    #[tokio::test]
    async fn heartbeat_response_rotate_command_returned() {
        init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"pending_commands":[{"type":"Rotate"}]}"#),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng = rand_core::OsRng;

        let resp = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng,
            None,
        )
        .await
        .unwrap();

        let cmds = resp.pending_commands.expect("should have pending_commands");
        assert_eq!(cmds.len(), 1);
        assert!(matches!(cmds[0], BridgeCommand::Rotate));
    }

    #[tokio::test]
    async fn heartbeat_response_unknown_command_does_not_error() {
        init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"pending_commands":[{"type":"FutureUnknownCommand"}]}"#),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng = rand_core::OsRng;

        let resp = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng,
            None,
        )
        .await;

        // Must not error — Unknown variant absorbs unknown command types
        assert!(
            resp.is_ok(),
            "unknown command type should not cause an error: {:?}",
            resp.err()
        );
        let cmds = resp
            .unwrap()
            .pending_commands
            .expect("should have pending_commands");
        assert_eq!(cmds.len(), 1);
        assert!(matches!(cmds[0], BridgeCommand::Unknown));
    }

    // ── Registration install_token tests ──────────────────────────────────────

    #[tokio::test]
    async fn registration_body_contains_install_token_when_set() {
        init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/register"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({ "agent_id": "token-test" })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new();
        let mut config = make_config(server.uri());
        config.control_plane_install_token = Some("test-token-abc".to_string());

        let (identity, _dir) = make_test_identity();
        let agent_id = try_register(&client, &config, &identity).await;
        assert!(agent_id.is_some());

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        assert_eq!(
            body["install_token"].as_str(),
            Some("test-token-abc"),
            "install_token should be present in registration body"
        );
    }

    #[tokio::test]
    async fn registration_body_omits_install_token_when_none() {
        init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/register"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({ "agent_id": "no-token-test" })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri()); // control_plane_install_token: None

        let (identity, _dir) = make_test_identity();
        let agent_id = try_register(&client, &config, &identity).await;
        assert!(agent_id.is_some());

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        assert!(
            body.get("install_token").is_none(),
            "install_token should be absent from registration body when None, got: {:?}",
            body.get("install_token")
        );
    }

    // ── Cloud VK verification tests (C1/H6) ────────────────────────────────────

    /// H1: RegistrationPayload must NOT contain backend_addr.
    #[tokio::test]
    async fn registration_body_omits_backend_addr() {
        init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/register"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "agent_id": "no-backend-test" })),
            )
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let _ = try_register(&client, &config, &identity).await;

        let received = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        assert!(
            body.get("backend_addr").is_none(),
            "backend_addr must be absent from RegistrationPayload (H1 — topology leak prevention), got: {:?}",
            body.get("backend_addr")
        );
    }

    /// Helper: builds the wire body for a signed cloud heartbeat response.
    ///
    /// `ts_offset_secs` lets tests construct stale/future responses for replay tests.
    fn make_signed_body(
        cloud_sk: &latticeshield_crypto::signing::SigningKey,
        rng: &mut impl rand_core::CryptoRngCore,
        commands_json: &str,
        ts_offset_secs: i64,
    ) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ts = now + ts_offset_secs;
        // Cloud serializes the inner payload ONCE and signs the exact bytes.
        let signed_payload = format!(r#"{{"pending_commands":{commands_json},"ts":{ts}}}"#);
        let sig =
            latticeshield_crypto::signing::sign(cloud_sk, signed_payload.as_bytes(), rng).unwrap();
        let sig_b64 = STANDARD.encode(sig.to_bytes());
        // Embed signed_payload as a JSON string (escape quotes).
        let escaped = signed_payload.replace('\\', r"\\").replace('"', r#"\""#);
        format!(r#"{{"signed_payload":"{escaped}","response_signature":"{sig_b64}"}}"#)
    }

    /// C1: Valid cloud signature with fresh `ts` → command is dispatched.
    #[tokio::test]
    async fn cloud_vk_valid_sig_dispatches_command() {
        init_crypto();

        let mut rng = rand_core::OsRng;
        let (cloud_sk, cloud_vk) = latticeshield_crypto::signing::generate_keypair(&mut rng);
        let body = make_signed_body(&cloud_sk, &mut rng, r#"[{"type":"Rotate"}]"#, 0);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng2 = rand_core::OsRng;

        let resp = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng2,
            Some(&cloud_vk),
        )
        .await
        .unwrap();

        let cmds = resp
            .pending_commands
            .expect("should have pending_commands when sig is valid");
        assert!(matches!(cmds[0], BridgeCommand::Rotate));
    }

    /// C1: Invalid cloud signature → commands dropped, no panic.
    #[tokio::test]
    async fn cloud_vk_invalid_sig_drops_command() {
        init_crypto();

        let mut rng = rand_core::OsRng;
        let (_, cloud_vk) = latticeshield_crypto::signing::generate_keypair(&mut rng);

        // Build a signed_payload but pair it with an all-zeros (invalid) signature.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let signed_payload = format!(r#"{{"pending_commands":[{{"type":"Rotate"}}],"ts":{now}}}"#);
        let escaped = signed_payload.replace('"', r#"\""#);
        let bad_sig = vec![0u8; latticeshield_crypto::signing::SIGNATURE_LEN];
        let bad_sig_b64 = STANDARD.encode(&bad_sig);
        let body =
            format!(r#"{{"signed_payload":"{escaped}","response_signature":"{bad_sig_b64}"}}"#);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng2 = rand_core::OsRng;

        let resp = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng2,
            Some(&cloud_vk),
        )
        .await
        .unwrap();

        assert!(
            resp.pending_commands.is_none(),
            "invalid sig must drop all commands, got: {:?}",
            resp.pending_commands
        );
    }

    /// C-R2: A correctly-signed response whose `ts` is too far in the past → commands dropped.
    /// Captures the replay-attack defense: even with a valid signature, stale responses
    /// (e.g. captured weeks ago and re-injected via TLS MITM) are rejected.
    #[tokio::test]
    async fn cloud_vk_stale_ts_drops_command() {
        init_crypto();
        let mut rng = rand_core::OsRng;
        let (cloud_sk, cloud_vk) = latticeshield_crypto::signing::generate_keypair(&mut rng);
        // Sign with ts 1 hour in the past — well outside the 300s window.
        let body = make_signed_body(&cloud_sk, &mut rng, r#"[{"type":"Rotate"}]"#, -3600);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng2 = rand_core::OsRng;

        let resp = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng2,
            Some(&cloud_vk),
        )
        .await
        .unwrap();

        assert!(
            resp.pending_commands.is_none(),
            "stale ts must drop all commands (replay protection)"
        );
    }

    /// C-R2: A correctly-signed response whose `ts` is too far in the future → commands dropped.
    /// Catches forward-skew or clock-tampering attacks.
    #[tokio::test]
    async fn cloud_vk_future_ts_drops_command() {
        init_crypto();
        let mut rng = rand_core::OsRng;
        let (cloud_sk, cloud_vk) = latticeshield_crypto::signing::generate_keypair(&mut rng);
        let body = make_signed_body(&cloud_sk, &mut rng, r#"[{"type":"Rotate"}]"#, 3600);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng2 = rand_core::OsRng;

        let resp = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng2,
            Some(&cloud_vk),
        )
        .await
        .unwrap();

        assert!(
            resp.pending_commands.is_none(),
            "future ts must drop all commands"
        );
    }

    /// Helper: builds a signed body with an arbitrary `ts` value (not a relative offset).
    /// Lets tests reach extreme boundary values (i64::MIN, i64::MAX).
    fn make_signed_body_with_absolute_ts(
        cloud_sk: &latticeshield_crypto::signing::SigningKey,
        rng: &mut impl rand_core::CryptoRngCore,
        commands_json: &str,
        ts: i64,
    ) -> String {
        let signed_payload = format!(r#"{{"pending_commands":{commands_json},"ts":{ts}}}"#);
        let sig =
            latticeshield_crypto::signing::sign(cloud_sk, signed_payload.as_bytes(), rng).unwrap();
        let sig_b64 = STANDARD.encode(sig.to_bytes());
        let escaped = signed_payload.replace('\\', r"\\").replace('"', r#"\""#);
        format!(r#"{{"signed_payload":"{escaped}","response_signature":"{sig_b64}"}}"#)
    }

    /// Regression: `ts = i64::MIN` used to panic in debug builds because
    /// `now - i64::MIN` overflows i64. `checked_sub` guards now.
    #[tokio::test]
    async fn cloud_vk_ts_i64_min_drops_without_panic() {
        init_crypto();
        let mut rng = rand_core::OsRng;
        let (cloud_sk, cloud_vk) = latticeshield_crypto::signing::generate_keypair(&mut rng);
        let body = make_signed_body_with_absolute_ts(
            &cloud_sk,
            &mut rng,
            r#"[{"type":"Rotate"}]"#,
            i64::MIN,
        );

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng2 = rand_core::OsRng;

        let resp = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng2,
            Some(&cloud_vk),
        )
        .await
        .unwrap();
        assert!(
            resp.pending_commands.is_none(),
            "ts = i64::MIN must drop without panic"
        );
    }

    /// Mirror: `ts = i64::MAX` must also drop cleanly via saturating_abs.
    #[tokio::test]
    async fn cloud_vk_ts_i64_max_drops_without_panic() {
        init_crypto();
        let mut rng = rand_core::OsRng;
        let (cloud_sk, cloud_vk) = latticeshield_crypto::signing::generate_keypair(&mut rng);
        let body = make_signed_body_with_absolute_ts(
            &cloud_sk,
            &mut rng,
            r#"[{"type":"Rotate"}]"#,
            i64::MAX,
        );

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng2 = rand_core::OsRng;

        let resp = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng2,
            Some(&cloud_vk),
        )
        .await
        .unwrap();
        assert!(
            resp.pending_commands.is_none(),
            "ts = i64::MAX must drop without panic"
        );
    }

    /// `signed_payload` missing the `ts` field → JSON parse fails → commands dropped.
    /// SignedResponsePayload.ts has no #[serde(default)]; this is intentional and tested here.
    #[tokio::test]
    async fn cloud_vk_signed_payload_missing_ts_drops() {
        init_crypto();
        let mut rng = rand_core::OsRng;
        let (cloud_sk, cloud_vk) = latticeshield_crypto::signing::generate_keypair(&mut rng);
        // No "ts" field in the inner payload.
        let signed_payload = r#"{"pending_commands":[{"type":"Rotate"}]}"#;
        let sig =
            latticeshield_crypto::signing::sign(&cloud_sk, signed_payload.as_bytes(), &mut rng)
                .unwrap();
        let sig_b64 = STANDARD.encode(sig.to_bytes());
        let escaped = signed_payload.replace('"', r#"\""#);
        let body = format!(r#"{{"signed_payload":"{escaped}","response_signature":"{sig_b64}"}}"#);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng2 = rand_core::OsRng;

        let resp = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng2,
            Some(&cloud_vk),
        )
        .await
        .unwrap();
        assert!(
            resp.pending_commands.is_none(),
            "missing ts in signed_payload must drop without error"
        );
    }

    /// Malformed base64 signature → drop (Ok, not Err). Coherent fail-closed.
    #[tokio::test]
    async fn cloud_vk_signature_malformed_base64_drops_ok() {
        init_crypto();
        let mut rng = rand_core::OsRng;
        let (_, cloud_vk) = latticeshield_crypto::signing::generate_keypair(&mut rng);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let signed_payload = format!(r#"{{"pending_commands":[{{"type":"Rotate"}}],"ts":{now}}}"#);
        let escaped = signed_payload.replace('"', r#"\""#);
        // "not-valid-base64!" contains chars outside base64 alphabet
        let body =
            format!(r#"{{"signed_payload":"{escaped}","response_signature":"not-valid-base64!"}}"#);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng2 = rand_core::OsRng;

        // Must return Ok with dropped commands — not propagate the decode error.
        let resp = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng2,
            Some(&cloud_vk),
        )
        .await
        .expect("malformed sig must drop commands without propagating Err");
        assert!(resp.pending_commands.is_none());
    }

    /// Wrong-length signature bytes → drop (Ok). Coherent fail-closed.
    #[tokio::test]
    async fn cloud_vk_signature_wrong_length_drops_ok() {
        init_crypto();
        let mut rng = rand_core::OsRng;
        let (_, cloud_vk) = latticeshield_crypto::signing::generate_keypair(&mut rng);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let signed_payload = format!(r#"{{"pending_commands":[{{"type":"Rotate"}}],"ts":{now}}}"#);
        let escaped = signed_payload.replace('"', r#"\""#);
        // Valid base64 but only 32 bytes → wrong sig length (ML-DSA-65 = 3309)
        let short_sig = STANDARD.encode([0u8; 32]);
        let body =
            format!(r#"{{"signed_payload":"{escaped}","response_signature":"{short_sig}"}}"#);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng2 = rand_core::OsRng;

        let resp = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng2,
            Some(&cloud_vk),
        )
        .await
        .expect("wrong-length sig must drop commands without propagating Err");
        assert!(resp.pending_commands.is_none());
    }

    /// M-1: an oversized response body must be rejected before buffering.
    /// Even without a cloud VK configured, a hostile cloud sending a 1 GB
    /// body would OOM the bridge. Test sends a body just over the 1 MiB cap.
    #[tokio::test]
    async fn heartbeat_oversized_body_returns_err() {
        init_crypto();
        let oversized = "x".repeat((MAX_HEARTBEAT_RESPONSE_BYTES + 1) as usize);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_string(oversized))
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng = rand_core::OsRng;

        let result = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng,
            None,
        )
        .await;

        assert!(
            result.is_err(),
            "oversized heartbeat response must be rejected"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("too large"),
            "error message should mention size, got: {err}"
        );
    }

    /// C1: No cloud VK configured → commands dispatched (backward compat).
    #[tokio::test]
    async fn cloud_vk_not_configured_dispatches_command() {
        init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"pending_commands":[{"type":"Rotate"}]}"#),
            )
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng = rand_core::OsRng;

        let resp = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng,
            None, // no cloud VK → backward compat
        )
        .await
        .unwrap();

        let cmds = resp
            .pending_commands
            .expect("commands should be dispatched when no cloud VK");
        assert!(matches!(cmds[0], BridgeCommand::Rotate));
    }

    /// C1: response_signature absent when cloud_vk IS configured → commands rejected.
    #[tokio::test]
    async fn cloud_vk_set_but_signature_absent_drops_command() {
        init_crypto();

        let mut rng = rand_core::OsRng;
        let (_, cloud_vk) = latticeshield_crypto::signing::generate_keypair(&mut rng);

        let server = MockServer::start().await;
        // Response has no response_signature field
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent-id/heartbeat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"pending_commands":[{"type":"Rotate"}]}"#),
            )
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let (identity, _dir) = make_test_identity();
        let signable = make_signable();
        let mut rng2 = rand_core::OsRng;

        let resp = send_heartbeat(
            &client,
            &config,
            "test-agent-id",
            &signable,
            &identity,
            &mut rng2,
            Some(&cloud_vk), // VK set but no sig in response → reject
        )
        .await
        .unwrap();

        assert!(
            resp.pending_commands.is_none(),
            "missing response_signature when cloud_vk is set must drop all commands"
        );
    }
}
