//! Integration tests for latticeshield-client.
//!
//! These tests spin up a "mock bridge" that manually performs the server-side
//! PQC handshake using latticeshield-crypto directly (no latticeshield-bridge
//! binary crate dependency), then verify that client_session::handle completes
//! a full encrypted relay round-trip.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use latticeshield_crypto::{
    generate_keypair, EncryptedChannel, FrameResult, ServerHandshake,
    CLIENT_RESPONSE_LEN,
};

use latticeshield_client::client_session;
use latticeshield_client::config::{PoolConfig, ValidClientConfig};
use latticeshield_client::pool::ConnectionPool;

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
        pool: PoolConfig::default(),
    }
}

fn make_pool(bridge_addr: SocketAddr) -> Arc<ConnectionPool> {
    Arc::new(ConnectionPool::new(
        bridge_addr,
        PoolConfig { max_size: 1, idle_timeout_secs: 30, warm_size: 0, warm_interval_secs: 5 },
    ))
}

// ── Mock bridge helpers ───────────────────────────────────────────────────────

/// Performs the server-side handshake on `stream` using `sk`, then returns
/// an `EncryptedChannel` ready for data exchange.
async fn server_handshake(
    stream: &mut TcpStream,
    sk: &latticeshield_crypto::SigningKey,
) -> EncryptedChannel {
    let mut rng = OsRng;

    let server_hs = ServerHandshake::new(&mut rng);

    let hello_bytes = server_hs
        .server_hello_signed_bytes(sk, &mut rng)
        .expect("server_hello_signed_bytes");
    stream.write_all(&hello_bytes).await.expect("write server hello");

    let mut client_resp_buf = [0u8; CLIENT_RESPONSE_LEN];
    stream
        .read_exact(&mut client_resp_buf)
        .await
        .expect("read client response");

    let session_key = server_hs
        .complete_from_wire(&client_resp_buf)
        .expect("complete_from_wire");

    EncryptedChannel::new(session_key.as_bytes(), 65536)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Full round-trip: client connects to mock bridge, handshakes, sends data,
/// bridge relays to echo backend, data echoes back through the encrypted channel.
#[tokio::test]
async fn full_bridge_client_relay() {
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

        let plaintext = loop {
            match channel.read_frame(&mut client_r).await {
                Ok(FrameResult::Data(data)) => break data,
                Ok(FrameResult::KeyRotate(nonce)) => channel.rotate_key(&nonce),
                Err(_) => return,
            }
        };

        backend_w.write_all(&plaintext).await.unwrap();
        let _ = backend_w.shutdown().await;

        let mut echo_buf = Vec::new();
        backend_r.read_to_end(&mut echo_buf).await.unwrap();

        if !echo_buf.is_empty() {
            channel.write_frame(&mut client_w, &echo_buf).await.unwrap();
        }
    });

    let user_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let user_addr = user_listener.local_addr().unwrap();

    let user_connect = tokio::spawn(async move {
        TcpStream::connect(user_addr).await.unwrap()
    });
    let (user_server_side, _) = user_listener.accept().await.unwrap();
    let mut user_client_side = user_connect.await.unwrap();

    let peer: SocketAddr = "127.0.0.1:11111".parse().unwrap();
    let config = make_client_config(bridge_addr);
    let pool = make_pool(bridge_addr);

    let handle_task = tokio::spawn(async move {
        client_session::handle(user_server_side, peer, config, Arc::new(vk), None, pool)
            .await
            .expect("client_session::handle failed")
    });

    let payload = b"hello integration test";
    user_client_side.write_all(payload).await.unwrap();

    let mut response = vec![0u8; payload.len()];
    user_client_side.read_exact(&mut response).await.unwrap();

    assert_eq!(
        response.as_slice(), payload as &[u8],
        "echo response should match sent payload"
    );

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

        let mut frames_relayed = 0usize;

        loop {
            tokio::select! {
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
    let pool = make_pool(bridge_addr);

    let handle_task = tokio::spawn(async move {
        client_session::handle(user_server_side, peer, config, Arc::new(vk), None, pool)
            .await
            .expect("client_session::handle failed")
    });

    let payloads: [&[u8]; 3] = [b"payload-one", b"payload-two", b"payload-three"];
    let mut total_expected = Vec::new();

    for p in &payloads {
        user_client_side.write_all(p).await.unwrap();
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
