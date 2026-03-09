//! Control plane heartbeat client.
//!
//! Registers the bridge agent on startup and sends periodic heartbeat POSTs.
//! All failures are non-fatal — the proxy continues operating if the control
//! plane is unreachable.

use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::ValidConfig;
use crate::metrics::MetricsState;

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct RegistrationPayload {
    name: String,
    version: String,
    capabilities: Vec<String>,
    listen_addr: String,
    backend_addr: String,
}

#[derive(Deserialize)]
struct RegistrationResponse {
    agent_id: String,
}

#[derive(Serialize)]
struct HeartbeatPayload {
    timestamp_unix: u64,
    uptime_secs: u64,
    status: &'static str,
    version: &'static str,
    metrics: HeartbeatMetrics,
}

#[derive(Serialize)]
struct HeartbeatMetrics {
    connections_active: u64,
    connections_total: u64,
    bytes_transmitted_total: u64,
    channel_errors_total: u64,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Registers the agent and starts the heartbeat loop.
/// Non-fatal: logs warnings on any failure, never panics.
pub async fn start(config: ValidConfig, metrics: Arc<MetricsState>) {
    let client = match Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("control plane: failed to build HTTP client: {e}");
            return;
        }
    };

    let agent_id = match try_register(&client, &config).await {
        Some(id) => id,
        None => {
            warn!("control plane: registration failed, heartbeat disabled");
            return;
        }
    };

    let started_at = Instant::now();
    loop {
        tokio::time::sleep(config.heartbeat_interval).await;

        let snapshot = metrics.snapshot();
        let payload = HeartbeatPayload {
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

        if let Err(e) = send_heartbeat(&client, &config, &agent_id, &payload).await {
            warn!("control plane: heartbeat failed (will retry): {e:#}");
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

async fn try_register(client: &Client, config: &ValidConfig) -> Option<String> {
    let payload = RegistrationPayload {
        name: config.control_plane_agent_name.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec![
            "pqc-proxy".to_string(),
            "ml-kem-768".to_string(),
            "ml-dsa-65".to_string(),
        ],
        listen_addr: config.listen_addr.to_string(),
        backend_addr: config.backend_addr.to_string(),
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
    payload: &HeartbeatPayload,
) -> anyhow::Result<()> {
    let url = format!(
        "{}/api/v1/agents/{}/heartbeat",
        config.control_plane_endpoint, agent_id
    );
    let resp = client
        .post(&url)
        .json(payload)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("heartbeat request failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("heartbeat returned HTTP {status}");
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_config(endpoint: String) -> ValidConfig {
        ValidConfig {
            listen_addr: "127.0.0.1:8443".parse().unwrap(),
            backend_addr: "127.0.0.1:8080".parse().unwrap(),
            metrics_addr: "127.0.0.1:8444".parse().unwrap(),
            max_frame_size: 65536,
            signing_key_path: std::path::PathBuf::from("./keys/server.sk"),
            log_level: "info".to_string(),
            control_plane_enabled: true,
            control_plane_endpoint: endpoint,
            control_plane_agent_name: "test-agent".to_string(),
            heartbeat_interval: Duration::from_secs(30),
        }
    }

    #[tokio::test]
    async fn registration_success_stores_agent_id() {
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
        let agent_id = try_register(&client, &config).await;
        assert_eq!(agent_id, Some("test-id-42".to_string()));
    }

    #[tokio::test]
    async fn registration_failure_returns_none() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/register"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new();
        let config = make_config(server.uri());
        let result = try_register(&client, &config).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn registration_body_contains_correct_capabilities() {
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
        let agent_id = try_register(&client, &config).await;
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
    async fn heartbeat_url_includes_agent_id() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/test-agent/heartbeat"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let config = make_config(server.uri());
        let payload = HeartbeatPayload {
            timestamp_unix: 0,
            uptime_secs: 0,
            status: "healthy",
            version: "0.1.0",
            metrics: HeartbeatMetrics {
                connections_active: 0,
                connections_total: 0,
                bytes_transmitted_total: 0,
                channel_errors_total: 0,
            },
        };

        send_heartbeat(&client, &config, "test-agent", &payload)
            .await
            .unwrap();
    }
}
