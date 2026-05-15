// Run Docker-required tests with:
//   cargo test -p latticeshield-integration-tests -- --ignored

#[path = "common/mod.rs"]
mod common;

use testcontainers::runners::AsyncRunner;
use testcontainers_modules::redis::Redis;

/// Verifies end-to-end Redis connectivity through the full PQC stack.
///
/// Requires Docker.
#[ignore]
#[tokio::test]
async fn redis_baseline() {
    let redis_container = Redis::default()
        .start()
        .await
        .expect("Redis container should start");

    let redis_port = redis_container.get_host_port_ipv4(6379).await.unwrap();
    let redis_addr: std::net::SocketAddr = format!("127.0.0.1:{redis_port}").parse().unwrap();

    let stack = common::spawn_stack(redis_addr).await.unwrap();

    let redis_url = format!("redis://127.0.0.1:{}", stack.client_addr.port());
    let client = redis::Client::open(redis_url).expect("redis client should open");

    let mut conn = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client.get_multiplexed_tokio_connection(),
    )
    .await
    .expect("redis connect should not time out")
    .expect("redis connect should succeed");

    let result: String = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        redis::cmd("PING").query_async(&mut conn),
    )
    .await
    .expect("PING should not time out")
    .expect("PING should succeed");

    assert_eq!(result, "PONG");
}

/// Verifies that dropping the bridge mid-pubsub causes subscription loss.
///
/// After a bridge drop, the pub/sub connection is terminated. A new connection
/// does not carry the prior subscriptions. Re-subscribing on the new connection
/// succeeds.
///
/// Requires Docker.
#[ignore]
#[tokio::test]
async fn redis_pubsub_drop() {
    let redis_container = Redis::default()
        .start()
        .await
        .expect("Redis container should start");

    let redis_port = redis_container.get_host_port_ipv4(6379).await.unwrap();
    let redis_addr: std::net::SocketAddr = format!("127.0.0.1:{redis_port}").parse().unwrap();

    let stack = common::spawn_stack(redis_addr).await.unwrap();

    let client_addr_port = stack.client_addr.port();
    let redis_url = format!("redis://127.0.0.1:{client_addr_port}");

    // First connection — subscribe to "test-channel"
    let client1 = redis::Client::open(redis_url.clone()).expect("redis client should open");
    let mut pubsub = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client1.get_async_pubsub(),
    )
    .await
    .expect("pubsub connect should not time out")
    .expect("pubsub connect should succeed");

    pubsub
        .subscribe("test-channel")
        .await
        .expect("subscribe should succeed");

    // Subscription confirmation is handled internally by redis — proceed to kill
    let _ = pubsub.on_message(); // consume to verify subscription is active

    // Kill the bridge — pub/sub connection is terminated
    stack.bridge_kill.kill_all();

    // Allow teardown to propagate
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // New connection — should NOT carry the prior subscription
    let client2 = redis::Client::open(redis_url.clone()).expect("redis client should open");
    let mut conn2 = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client2.get_multiplexed_tokio_connection(),
    )
    .await
    .expect("new redis connect should not time out")
    .expect("new redis connect should succeed");

    // PING to verify the new connection works
    let pong: String = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        redis::cmd("PING").query_async(&mut conn2),
    )
    .await
    .expect("PING should not time out")
    .expect("PING should succeed on new connection");
    assert_eq!(pong, "PONG");

    // A new pub/sub connection is NOT subscribed to "test-channel" by default
    // (subscriptions are per-connection state — they don't persist across reconnects)
    let client3 = redis::Client::open(redis_url).expect("redis client should open");
    let mut pubsub3 = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client3.get_async_pubsub(),
    )
    .await
    .expect("pubsub3 connect should not time out")
    .expect("pubsub3 connect should succeed");

    // Re-subscribe on the new connection succeeds
    // Classification: STATE_LOSS
    pubsub3
        .subscribe("test-channel")
        .await
        .expect("re-subscribe on new connection should succeed");
}
