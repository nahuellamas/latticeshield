//! Integration tests for latticeshield-client.
//!
//! These tests spin up a "mock bridge" that manually performs the server-side
//! PQC handshake using latticeshield-crypto directly (no latticeshield-bridge
//! binary crate dependency), then verify that client_session::handle completes
//! a full encrypted relay round-trip.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::io::Write;

use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use latticeshield_crypto::{
    generate_keypair, EncryptedChannel, FrameResult, ServerHandshake,
    CLIENT_RESPONSE_LEN,
};

// We need to reach into the client crate internals via the binary's lib paths.
// Since latticeshield-client only has a [[bin]] target we import via the
// path-based integration test approach — the test lives in the same workspace
// and cargo resolves latticeshield-client's src as the test's crate root.
use latticeshield_client::client_session;
use latticeshield_client::config::ValidClientConfig;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Spawns a trivial TCP echo backend (copies bytes back to sender).
/// Returns the bound SocketAddr.
async fn spawn_echo_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        // Accept exactly one connection and echo bidirectionally.
        if let Ok((stream, _)) = listener.accept().await {
            let (mut r, mut w) = tokio::io::split(stream);
            // Copy from read-half to write-half (echo).
            // When the writer closes (EOF on r), copy terminates.
            let _ = tokio::io::copy(&mut r, &mut w).await;
        }
    });

    addr
}

/// Builds a ValidClientConfig that points at the given bridge address.
fn make_client_config(bridge_addr: SocketAddr) -> ValidClientConfig {
    ValidClientConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        bridge_addr,
        server_vk_path: PathBuf::from("./keys/server.vk"),
        client_sk_path: None,
        max_frame_size: 65536,
        log_level: "info".to_string(),
        reconnect: latticeshield_client::config::ReconnectConfig::default(),
    }
}

// ── Mock bridge helpers ───────────────────────────────────────────────────────

/// Performs the server-side handshake on `stream` using `sk`, then returns
/// an `EncryptedChannel` ready for data exchange.
async fn server_handshake(
    stream: &mut TcpStream,
    sk: &latticeshield_crypto::SigningKey,
) -> EncryptedChannel {
    let mut rng = OsRng;

    // 1. Server generates ephemeral keys
    let server_hs = ServerHandshake::new(&mut rng);

    // 2. Send signed ServerHello
    let hello_bytes = server_hs
        .server_hello_signed_bytes(sk, &mut rng)
        .expect("server_hello_signed_bytes");
    stream.write_all(&hello_bytes).await.expect("write server hello");

    // 3. Read client response
    let mut client_resp_buf = [0u8; CLIENT_RESPONSE_LEN];
    stream
        .read_exact(&mut client_resp_buf)
        .await
        .expect("read client response");

    // 4. Derive session key
    let session_key = server_hs
        .complete_from_wire(&client_resp_buf)
        .expect("complete_from_wire");

    // 5. Build EncryptedChannel from server side
    EncryptedChannel::new(session_key.as_bytes(), 65536)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// vk-info subcommand: spawn the real binary, load a generated VK, verify output.
#[test]
fn vk_info_prints_fingerprint() {
    let mut rng = OsRng;
    let (_sk, vk) = generate_keypair(&mut rng);

    // Write VK bytes to a tempfile.
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(vk.to_bytes()).unwrap();
    tmp.flush().unwrap();

    let bin = env!("CARGO_BIN_EXE_latticeshield-client");
    let output = std::process::Command::new(bin)
        .args(["vk-info", tmp.path().to_str().unwrap()])
        .output()
        .expect("failed to spawn latticeshield-client");

    assert!(
        output.status.success(),
        "vk-info exited with non-zero status: {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Must contain a 64-char hex fingerprint on the "fingerprint:" line.
    let fp_line = stdout
        .lines()
        .find(|l| l.starts_with("fingerprint:"))
        .expect("output should contain a 'fingerprint:' line");
    let hex = fp_line.trim_start_matches("fingerprint:").trim();
    assert_eq!(hex.len(), 64, "fingerprint should be 64 hex chars, got: {hex}");
    assert!(
        hex.chars().all(|c| c.is_ascii_hexdigit()),
        "fingerprint should be hex, got: {hex}"
    );

    // Must contain the key size.
    assert!(
        stdout.contains("1952"),
        "output should reference VERIFYING_KEY_LEN=1952, got: {stdout}"
    );
}

/// Full round-trip: client connects to mock bridge, handshakes, sends data,
/// bridge relays to echo backend, data echoes back through the encrypted channel.
#[tokio::test]
async fn full_bridge_client_relay() {
    let mut rng = OsRng;
    let (sk, vk) = generate_keypair(&mut rng);

    // Echo backend
    let echo_addr = spawn_echo_backend().await;

    // Mock bridge listener
    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();

    // Spawn mock bridge task.
    //
    // The bridge reads exactly one encrypted DATA frame from the client,
    // forwards the plaintext to the echo backend, reads the echo response,
    // and sends it back encrypted to the client. The bridge does NOT wait
    // for client EOF — it responds immediately after one round-trip.
    tokio::spawn(async move {
        let (mut client_stream, _) = bridge_listener.accept().await.unwrap();

        // Perform server-side PQC handshake
        let mut channel = server_handshake(&mut client_stream, &sk).await;

        // Connect to echo backend
        let mut backend = TcpStream::connect(echo_addr).await.unwrap();

        let (mut client_r, mut client_w) = client_stream.split();
        let (mut backend_r, mut backend_w) = backend.split();

        // Step 1: read one encrypted DATA frame from client
        let plaintext = loop {
            match channel.read_frame(&mut client_r).await {
                Ok(FrameResult::Data(data)) => break data,
                Ok(FrameResult::KeyRotate(nonce)) => channel.rotate_key(&nonce),
                Err(_) => return,
            }
        };

        // Step 2: forward plaintext to echo backend, then signal EOF
        backend_w.write_all(&plaintext).await.unwrap();
        let _ = backend_w.shutdown().await;

        // Step 3: read echoed bytes from backend
        let mut echo_buf = Vec::new();
        backend_r.read_to_end(&mut echo_buf).await.unwrap();

        // Step 4: encrypt and send back to client
        if !echo_buf.is_empty() {
            channel.write_frame(&mut client_w, &echo_buf).await.unwrap();
        }
        // Shutting down client_w will cause the handle loop to break on bridge EOF
    });

    // Create user-side pipe: simulate a user TCP connection
    let user_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let user_addr = user_listener.local_addr().unwrap();

    // Connect the "user" side
    let user_connect = tokio::spawn(async move {
        TcpStream::connect(user_addr).await.unwrap()
    });
    let (user_server_side, _) = user_listener.accept().await.unwrap();
    let mut user_client_side = user_connect.await.unwrap();

    let peer: SocketAddr = "127.0.0.1:11111".parse().unwrap();
    let config = make_client_config(bridge_addr);

    // Spawn client_session::handle
    let handle_task = tokio::spawn(async move {
        client_session::handle(user_server_side, peer, config, Arc::new(vk), None, latticeshield_client::config::ReconnectConfig::default())
            .await
            .expect("client_session::handle failed")
    });

    // Send test payload — do NOT shut down yet; let the bridge echo it back first.
    let payload = b"hello integration test";
    user_client_side.write_all(payload).await.unwrap();

    // Read exactly payload-len bytes echoed back.
    let mut response = vec![0u8; payload.len()];
    user_client_side.read_exact(&mut response).await.unwrap();

    assert_eq!(
        response.as_slice(), payload as &[u8],
        "echo response should match sent payload"
    );

    // Now shut down cleanly
    user_client_side.shutdown().await.unwrap();
    handle_task.await.unwrap();
}

/// Same as full_bridge_client_relay, but the mock bridge sends a KEY_ROTATE
/// frame mid-session. The client must handle it transparently and continue
/// decrypting subsequent DATA frames with the rotated key.
#[tokio::test]
async fn key_rotate_survives_relay() {
    let mut rng = OsRng;
    let (sk, vk) = generate_keypair(&mut rng);

    let echo_addr = spawn_echo_backend().await;

    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut client_stream, _) = bridge_listener.accept().await.unwrap();

        let mut channel = server_handshake(&mut client_stream, &sk).await;

        let mut backend = TcpStream::connect(echo_addr).await.unwrap();
        let (mut client_r, mut client_w) = client_stream.split();
        let (mut backend_r, mut backend_w) = backend.split();

        // Track how many client frames we've relayed (to trigger KEY_ROTATE mid-session)
        let mut frames_relayed = 0usize;

        loop {
            tokio::select! {
                // client → backend (decrypt encrypted frames from client)
                frame = channel.read_frame(&mut client_r) => {
                    match frame {
                        Ok(FrameResult::Data(data)) => {
                            frames_relayed += 1;
                            backend_w.write_all(&data).await.unwrap();
                        }
                        Ok(FrameResult::KeyRotate(nonce)) => {
                            channel.rotate_key(&nonce);
                        }
                        Err(_) => break,
                    }
                }

                // backend → client (encrypt back to client)
                result = backend_r.read_u8() => {
                    match result {
                        Ok(byte) => {
                            let mut buf = vec![byte];
                            let mut tmp = [0u8; 4096];
                            loop {
                                match backend_r.try_read(&mut tmp) {
                                    Ok(0) => break,
                                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                                    Err(_) => break,
                                }
                            }

                            // After relaying the first payload back, send KEY_ROTATE
                            // then continue with the encrypted response.
                            if frames_relayed == 1 {
                                let mut rotation_nonce = [0u8; 32];
                                OsRng.fill_bytes(&mut rotation_nonce);
                                channel
                                    .send_key_rotate(&mut client_w, &rotation_nonce)
                                    .await
                                    .unwrap();
                                channel.rotate_key(&rotation_nonce);
                            }

                            channel.write_frame(&mut client_w, &buf).await.unwrap();
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    let user_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let user_addr = user_listener.local_addr().unwrap();

    let user_connect = tokio::spawn(async move {
        TcpStream::connect(user_addr).await.unwrap()
    });
    let (user_server_side, _) = user_listener.accept().await.unwrap();
    let mut user_client_side = user_connect.await.unwrap();

    let peer: SocketAddr = "127.0.0.1:22222".parse().unwrap();
    let config = make_client_config(bridge_addr);

    let handle_task = tokio::spawn(async move {
        client_session::handle(user_server_side, peer, config, Arc::new(vk), None, latticeshield_client::config::ReconnectConfig::default())
            .await
            .expect("client_session::handle failed")
    });

    // Send 3 payloads
    let payloads: [&[u8]; 3] = [b"payload-one", b"payload-two", b"payload-three"];
    let mut total_expected = Vec::new();

    for p in &payloads {
        user_client_side.write_all(p).await.unwrap();
        // Small delay to allow the relay loop to process each payload sequentially.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        total_expected.extend_from_slice(p);
    }

    user_client_side.shutdown().await.unwrap();

    let mut response = Vec::new();
    user_client_side.read_to_end(&mut response).await.unwrap();

    assert_eq!(
        response, total_expected,
        "all 3 payloads must echo back correctly after KEY_ROTATE"
    );

    handle_task.await.unwrap();
}
