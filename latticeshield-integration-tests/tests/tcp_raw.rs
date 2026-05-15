// Run ignored tests with: cargo test -p latticeshield-integration-tests -- --ignored

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Verifies end-to-end TCP raw echo through the full PQC stack.
#[tokio::test]
async fn tcp_raw_baseline() {
    let backend_addr = common::mock_tcp::spawn_echo_backend().await;
    let stack = common::spawn_stack(backend_addr).await.unwrap();

    let mut conn = tokio::net::TcpStream::connect(stack.client_addr)
        .await
        .expect("should connect to client listener");

    conn.write_all(b"hello").await.unwrap();
    conn.flush().await.unwrap();

    let mut buf = [0u8; 5];
    tokio::time::timeout(std::time::Duration::from_secs(5), conn.read_exact(&mut buf))
        .await
        .expect("read should not time out")
        .expect("read should succeed");

    assert_eq!(&buf, b"hello");
}

/// Verifies that dropping the bridge terminates the existing TCP raw connection.
///
/// TCP raw connections cannot reconnect transparently — they are terminal once
/// the bridge session is aborted. The client receives EOF or an I/O error.
#[tokio::test]
async fn tcp_raw_drop() {
    let backend_addr = common::mock_tcp::spawn_echo_backend().await;
    let stack = common::spawn_stack(backend_addr).await.unwrap();

    let mut conn = tokio::net::TcpStream::connect(stack.client_addr)
        .await
        .expect("should connect to client listener");

    // Baseline round-trip
    conn.write_all(b"ping").await.unwrap();
    conn.flush().await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(std::time::Duration::from_secs(5), conn.read_exact(&mut buf))
        .await
        .expect("baseline read should not time out")
        .expect("baseline read should succeed");
    assert_eq!(&buf, b"ping");

    // Give the session time to settle into the relay phase
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Kill the bridge — EOF propagates to the client connection
    stack.bridge_kill.kill_all();

    // Allow the kill to propagate
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Attempt to use the same socket — must error or return EOF
    conn.write_all(b"after-drop").await.ok(); // may or may not error

    let mut drain = vec![0u8; 64];
    let result =
        tokio::time::timeout(std::time::Duration::from_secs(3), conn.read(&mut drain)).await;

    // Classification: BROKEN
    match result {
        Ok(Ok(0)) | Ok(Err(_)) => {
            // EOF or I/O error — expected: connection is terminal after bridge drop
        }
        Err(_elapsed) => {
            panic!("connection should be terminated after bridge drop, but read is still blocking");
        }
        Ok(Ok(n)) => {
            panic!("unexpected {n} bytes read after bridge drop — connection should be terminal");
        }
    }
}

/// Verifies that a client transparently reconnects after a bridge drop (REQ-4/A).
///
/// Scenario: baseline round-trip, kill bridge, wait for ReconnectEvent::Reconnected,
/// do another round-trip — user TCP stays open throughout.
#[tokio::test]
async fn tcp_raw_reconnect_succeeds() {
    use latticeshield_client::config::ReconnectConfig;

    let backend_addr = common::mock_tcp::spawn_echo_backend().await;
    let (stack, mut reconnect_rx) = common::spawn_stack_with_reconnect(
        backend_addr,
        ReconnectConfig {
            max_retries: 3,
            base_delay_ms: 50,
            max_delay_ms: 500,
        },
    )
    .await
    .unwrap();

    let mut conn = tokio::net::TcpStream::connect(stack.client_addr)
        .await
        .expect("should connect to client listener");

    // Baseline round-trip
    conn.write_all(b"hello").await.unwrap();
    conn.flush().await.unwrap();
    let mut buf = [0u8; 5];
    tokio::time::timeout(std::time::Duration::from_secs(5), conn.read_exact(&mut buf))
        .await
        .expect("baseline read should not time out")
        .expect("baseline read should succeed");
    assert_eq!(&buf, b"hello");

    // Let session settle into relay phase
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Kill the bridge
    stack.bridge_kill.kill_all();

    // Wait for reconnect event (up to 3 s)
    let event = tokio::time::timeout(std::time::Duration::from_secs(3), reconnect_rx.recv())
        .await
        .expect("should receive reconnect event within 3s")
        .expect("channel should be open");

    match event {
        latticeshield_client::ReconnectEvent::Reconnected { attempt, .. } => {
            assert_eq!(attempt, 1, "first reconnect should be attempt 1");
        }
        latticeshield_client::ReconnectEvent::Exhausted { .. } => {
            panic!("expected Reconnected but got Exhausted");
        }
    }

    // User TCP should still be open — do another round-trip
    conn.write_all(b"world")
        .await
        .expect("user side should still be open");
    conn.flush().await.unwrap();
    let mut buf2 = [0u8; 5];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        conn.read_exact(&mut buf2),
    )
    .await
    .expect("post-reconnect read should not time out")
    .expect("post-reconnect read should succeed");
    assert_eq!(&buf2, b"world");
}

/// Verifies that all retries are exhausted and Exhausted event received (REQ-4/B).
///
/// Scenario: bridge killed and not restarted — client exhausts max_retries,
/// emits Exhausted event, user side receives EOF.
#[tokio::test]
async fn reconnect_exhausted() {
    use latticeshield_client::config::ReconnectConfig;

    let backend_addr = common::mock_tcp::spawn_echo_backend().await;
    let (stack, mut reconnect_rx) = common::spawn_stack_with_reconnect(
        backend_addr,
        ReconnectConfig {
            max_retries: 2,
            base_delay_ms: 50,
            max_delay_ms: 200,
        },
    )
    .await
    .unwrap();

    let mut conn = tokio::net::TcpStream::connect(stack.client_addr)
        .await
        .expect("should connect to client listener");

    // Baseline round-trip
    conn.write_all(b"ping").await.unwrap();
    conn.flush().await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(std::time::Duration::from_secs(5), conn.read_exact(&mut buf))
        .await
        .expect("baseline read should not time out")
        .expect("baseline read should succeed");
    assert_eq!(&buf, b"ping");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Kill ALL bridge session tasks AND explicitly abort the bridge listener
    // task so no new connections are accepted (dropping JoinHandle detaches,
    // it does NOT abort the task in Tokio).
    stack.bridge_kill.kill_all();
    stack.bridge_listener_task.abort();
    stack.client_listener_task.abort();

    // Drain events until we get Exhausted (may receive Reconnected first if
    // the client managed one reconnect before the listener was fully shut down).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut exhausted = false;
    let mut exhausted_attempts = 0u32;
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_millis(200), reconnect_rx.recv()).await
        {
            Ok(Some(latticeshield_client::ReconnectEvent::Exhausted { attempts, .. })) => {
                exhausted = true;
                exhausted_attempts = attempts;
                break;
            }
            Ok(Some(latticeshield_client::ReconnectEvent::Reconnected { .. })) => {
                // Bridge might have accepted one more connection — keep waiting.
                continue;
            }
            Ok(None) => break,  // channel closed
            Err(_) => continue, // timeout — keep polling
        }
    }

    assert!(
        exhausted,
        "expected Exhausted event within 5s — bridge was dropped"
    );
    assert!(
        exhausted_attempts <= 2,
        "attempts ({exhausted_attempts}) should be <= max_retries (2)"
    );

    // User side should receive EOF
    let mut drain = vec![0u8; 64];
    let result =
        tokio::time::timeout(std::time::Duration::from_secs(3), conn.read(&mut drain)).await;
    match result {
        Ok(Ok(0)) | Ok(Err(_)) => {} // EOF or error — expected
        Err(_) => panic!("user side should receive EOF after exhaustion"),
        Ok(Ok(n)) => panic!("unexpected {n} bytes — expected EOF after exhaustion"),
    }
}

/// Verifies that every reconnect attempt uses fresh PQC ephemerals (REQ-1).
///
/// A RecordingBridge mock captures the raw ClientResponse bytes from two
/// consecutive connections. The ML-KEM ciphertext (the bulk of CLIENT_RESPONSE)
/// must differ because OsRng draws fresh ephemerals on each `client_respond()`.
#[tokio::test]
async fn reconnect_pqc_invariant() {
    use latticeshield_client::config::ReconnectConfig;
    use latticeshield_crypto::{generate_keypair, ServerHandshake, CLIENT_RESPONSE_LEN};
    use rand_core::OsRng;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    // ── 1. Ephemeral server keypair ──────────────────────────────────────────
    let (signing_key, verifying_key) = generate_keypair(&mut OsRng);
    let vk_bytes: [u8; latticeshield_crypto::VERIFYING_KEY_LEN] = *verifying_key.to_bytes();
    let vk_for_client =
        Arc::new(latticeshield_crypto::VerifyingKey::from_bytes(&vk_bytes).expect("VK round-trip"));
    let signing_key = Arc::new(signing_key);

    // ── 2. RecordingBridge mock ──────────────────────────────────────────────
    // Accepts exactly 2 connections; records CLIENT_RESPONSE bytes from each.
    let recorded: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded_clone = Arc::clone(&recorded);
    let (bridge_done_tx, mut bridge_done_rx) = mpsc::channel::<()>(1);

    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();

    let sk_for_mock = Arc::clone(&signing_key);
    tokio::spawn(async move {
        let mut connections = 0usize;
        while connections < 2 {
            let Ok((mut stream, _)) = bridge_listener.accept().await else {
                break;
            };
            connections += 1;

            // Fresh ServerHandshake per connection (guarantees fresh server ephemerals too)
            let server = ServerHandshake::new(&mut OsRng);

            // Send SERVER_HELLO_SIGNED
            let hello_bytes = server
                .server_hello_signed_bytes(&sk_for_mock, &mut OsRng)
                .expect("server hello signing");
            if stream.write_all(&hello_bytes).await.is_err() {
                break;
            }

            // Read CLIENT_RESPONSE
            let mut cr_buf = [0u8; CLIENT_RESPONSE_LEN];
            if stream.read_exact(&mut cr_buf).await.is_err() {
                break;
            }

            // Record it
            {
                let mut r = recorded_clone.lock().unwrap_or_else(|e| e.into_inner());
                r.push(cr_buf.to_vec());
            }

            // Drop stream — triggers BridgeError on client side, causing reconnect
            drop(stream);
        }
        let _ = bridge_done_tx.send(()).await;
    });

    // ── 3. Client with reconnect enabled, pointed at the mock bridge ─────────
    let (reconnect_tx_ch, mut reconnect_rx) =
        mpsc::channel::<latticeshield_client::ReconnectEvent>(8);
    let reconnect_tx_arc = Arc::new(reconnect_tx_ch);

    let client_pool = Arc::new(latticeshield_client::pool::ConnectionPool::new(
        bridge_addr,
        latticeshield_client::config::PoolConfig {
            max_size: 1,
            idle_timeout_secs: 30,
            warm_size: 0,
            warm_interval_secs: 5,
        },
    ));

    let client_config = latticeshield_client::config::ValidClientConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        bridge_addr,
        server_vk_path: std::path::PathBuf::from("/dev/null"),
        client_sk_path: None,
        max_frame_size: 65536,
        log_level: "error".to_string(),
        pool: latticeshield_client::config::PoolConfig {
            max_size: 1,
            idle_timeout_secs: 30,
            warm_size: 0,
            warm_interval_secs: 5,
        },
        reconnect: ReconnectConfig {
            max_retries: 1,
            base_delay_ms: 50,
            max_delay_ms: 500,
        },
    };

    // Connect a user-side listener
    let user_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let user_addr = user_listener.local_addr().unwrap();

    let connect_task =
        tokio::spawn(async move { tokio::net::TcpStream::connect(user_addr).await.unwrap() });
    let (user_server_side, _peer) = user_listener.accept().await.unwrap();
    let _user_client = connect_task.await.unwrap();

    let peer: std::net::SocketAddr = "127.0.0.1:55555".parse().unwrap();

    // Run handle() — it will connect, get dropped, reconnect, get dropped again, then exhaust
    let _ = latticeshield_client::client_session::handle(
        user_server_side,
        peer,
        client_config,
        vk_for_client,
        None,
        client_pool,
        Some(reconnect_tx_arc),
    )
    .await;

    // Wait for bridge mock to finish recording both payloads
    tokio::time::timeout(std::time::Duration::from_secs(5), bridge_done_rx.recv())
        .await
        .expect("bridge mock should complete within 5s");

    // Drain reconnect events (don't care about the exact events here)
    while reconnect_rx.try_recv().is_ok() {}

    // ── 4. Assert CLIENT_RESPONSE payloads differ ────────────────────────────
    let payloads = recorded.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(
        payloads.len(),
        2,
        "mock bridge should have recorded exactly 2 ClientResponse payloads, got {}",
        payloads.len()
    );

    assert_ne!(
        payloads[0], payloads[1],
        "ClientResponse payloads must differ across reconnects — \
         same bytes would indicate key reuse (REQ-1 violation)"
    );
}
