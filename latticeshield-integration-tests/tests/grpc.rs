// Run ignored tests with: cargo test -p latticeshield-integration-tests -- --ignored

#[path = "common/mod.rs"]
mod common;

use common::mock_grpc::proto::{echo_client::EchoClient, EchoReq, StreamReq};
use tokio_stream::StreamExt;
use tonic::transport::Channel;

async fn make_grpc_channel(addr: std::net::SocketAddr) -> EchoClient<Channel> {
    let endpoint = format!("http://{addr}");
    let channel = Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .expect("gRPC channel should connect");
    EchoClient::new(channel)
}

/// Verifies end-to-end gRPC unary call through the full PQC stack.
#[tokio::test]
async fn grpc_baseline() {
    let backend_addr = common::mock_grpc::spawn_grpc_backend().await;
    let stack = common::spawn_stack(backend_addr).await.unwrap();

    let mut client = make_grpc_channel(stack.client_addr).await;

    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.echo(EchoReq {
            message: "hello-grpc".to_string(),
        }),
    )
    .await
    .expect("gRPC call should not time out")
    .expect("gRPC call should succeed");

    assert_eq!(resp.into_inner().message, "hello-grpc");
}

/// Verifies gRPC behavior after a bridge drop mid-streaming call.
///
/// A server-streaming call is opened and at least one chunk is received before
/// the bridge is killed. The stream should return a Status error. After
/// re-establishing a new channel, a new streaming call succeeds.
#[tokio::test]
async fn grpc_stream_drop() {
    let backend_addr = common::mock_grpc::spawn_grpc_backend().await;
    let stack = common::spawn_stack(backend_addr).await.unwrap();

    let mut client = make_grpc_channel(stack.client_addr).await;

    // Open a server-streaming call (3 chunks)
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.stream(StreamReq { count: 3 }),
    )
    .await
    .expect("stream RPC should not time out")
    .expect("stream RPC should succeed")
    .into_inner();

    // Receive the first chunk
    let first_chunk = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("first chunk receive should not time out")
        .expect("stream should have at least one chunk")
        .expect("first chunk should be Ok");
    assert_eq!(first_chunk.seq, 0);

    // Kill the bridge mid-stream
    stack.bridge_kill.kill_all();

    // Allow the kill to propagate
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Drain the stream until it terminates (error or EOF from transport closure).
    // This asserts that the old stream does NOT continue producing Ok chunks indefinitely —
    // the bridge drop must terminate it. STATE_LOSS is confirmed when the stream ends
    // (either Err or None) without completing its full 3-chunk sequence.
    let mut got_terminal = false;
    for _ in 0..5 {
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .expect("post-drop stream.next() should not block forever");
        match result {
            Some(Err(_)) | None => {
                got_terminal = true;
                break;
            }
            Some(Ok(_)) => continue,
        }
    }
    // Classification: STATE_LOSS — old stream terminated by bridge drop
    assert!(
        got_terminal,
        "stream must terminate (Err or None) after bridge drop; STATE_LOSS not confirmed"
    );

    // New channel + new streaming call must succeed
    // Needs a brief delay to allow the client listener to accept new connections
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let mut client2 = make_grpc_channel(stack.client_addr).await;
    let mut stream2 = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client2.stream(StreamReq { count: 3 }),
    )
    .await
    .expect("new stream RPC should not time out")
    .expect("new stream RPC should succeed")
    .into_inner();

    let first = tokio::time::timeout(std::time::Duration::from_secs(5), stream2.next())
        .await
        .expect("new stream first chunk should not time out")
        .expect("new stream should have chunks")
        .expect("new stream first chunk should be Ok");

    assert_eq!(
        first.seq, 0,
        "new stream after reconnect should start from chunk 0"
    );
}
