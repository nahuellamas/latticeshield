// Run ignored tests with: cargo test -p latticeshield-integration-tests -- --ignored

#[path = "common/mod.rs"]
mod common;

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
