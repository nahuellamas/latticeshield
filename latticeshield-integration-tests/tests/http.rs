// Run ignored tests with: cargo test -p latticeshield-integration-tests -- --ignored

#[path = "common/mod.rs"]
mod common;

/// Verifies end-to-end HTTP round-trip through the full PQC stack.
#[tokio::test]
async fn http_baseline() {
    let backend_addr = common::mock_http::spawn_http_backend().await;
    let stack = common::spawn_stack(backend_addr).await.unwrap();

    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(false)
        // Disable connection pool so each request uses a fresh TCP connection
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();

    let url = format!("http://{}/", stack.client_addr);
    let resp = tokio::time::timeout(std::time::Duration::from_secs(10), client.get(&url).send())
        .await
        .expect("request should not time out")
        .expect("request should succeed");

    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "pong");
}

/// Verifies that after a bridge drop, HTTP clients can reconnect successfully.
///
/// HTTP is stateless and each request can use a new TCP connection through the
/// PQC tunnel. After a bridge drop, a new connection through the client listener
/// re-establishes the PQC session and succeeds.
#[tokio::test]
async fn http_drop() {
    let backend_addr = common::mock_http::spawn_http_backend().await;
    let stack = common::spawn_stack(backend_addr).await.unwrap();

    let client = reqwest::ClientBuilder::new()
        // Force new TCP connection per request — no pool reuse
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();

    let url = format!("http://{}/", stack.client_addr);

    // Baseline round-trip
    let resp = tokio::time::timeout(std::time::Duration::from_secs(10), client.get(&url).send())
        .await
        .expect("baseline request should not time out")
        .expect("baseline request should succeed");
    assert_eq!(resp.status().as_u16(), 200);

    // Kill the bridge
    stack.bridge_kill.kill_all();

    // Allow teardown to propagate
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Issue a new request — a completely new TCP connection is established
    let resp = tokio::time::timeout(std::time::Duration::from_secs(10), client.get(&url).send())
        .await
        .expect("post-drop request should not time out")
        .expect("post-drop request should succeed with a new connection");

    // Classification: OK
    assert_eq!(
        resp.status().as_u16(),
        200,
        "HTTP recovers after bridge drop"
    );
    let body = resp.text().await.unwrap();
    assert_eq!(body, "pong");
}
