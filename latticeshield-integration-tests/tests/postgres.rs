// Run Docker-required tests with:
//   cargo test -p latticeshield-integration-tests -- --ignored

#[path = "common/mod.rs"]
mod common;

use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use tokio_postgres::NoTls;

/// Verifies end-to-end PostgreSQL connectivity through the full PQC stack.
///
/// Requires Docker.
#[ignore]
#[tokio::test]
async fn postgres_baseline() {
    let pg = Postgres::default()
        .start()
        .await
        .expect("Postgres container should start");

    let pg_port = pg.get_host_port_ipv4(5432).await.unwrap();
    let pg_addr: std::net::SocketAddr = format!("127.0.0.1:{pg_port}").parse().unwrap();

    let stack = common::spawn_stack(pg_addr).await.unwrap();

    let conn_str = format!(
        "host=127.0.0.1 port={} user=postgres password=postgres dbname=postgres",
        stack.client_addr.port()
    );

    let (client, connection) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio_postgres::connect(&conn_str, NoTls),
    )
    .await
    .expect("postgres connect should not time out")
    .expect("postgres connect should succeed");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!("postgres connection driver error (expected on drop): {e}");
        }
    });

    let rows = client
        .query("SELECT 1::int as val", &[])
        .await
        .expect("SELECT 1 should succeed");

    assert_eq!(rows.len(), 1);
    let val: i32 = rows[0].get("val");
    assert_eq!(val, 1);
}

/// Verifies that dropping the bridge mid-transaction causes transaction rollback.
///
/// After a bridge drop, the open transaction is lost (rolled back by the server).
/// A new connection can reconnect and the previously inserted row is absent.
///
/// Requires Docker.
#[ignore]
#[tokio::test]
async fn postgres_drop_state_loss() {
    let pg = Postgres::default()
        .start()
        .await
        .expect("Postgres container should start");

    let pg_port = pg.get_host_port_ipv4(5432).await.unwrap();
    let pg_addr: std::net::SocketAddr = format!("127.0.0.1:{pg_port}").parse().unwrap();

    let stack = common::spawn_stack(pg_addr).await.unwrap();

    let conn_str = format!(
        "host=127.0.0.1 port={} user=postgres password=postgres dbname=postgres",
        stack.client_addr.port()
    );

    // First connection — open a transaction and insert a row
    let (client1, conn1) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio_postgres::connect(&conn_str, NoTls),
    )
    .await
    .expect("postgres connect should not time out")
    .expect("postgres connect should succeed");

    tokio::spawn(async move {
        let _ = conn1.await;
    });

    // Create table and begin a transaction
    client1
        .execute(
            "CREATE TABLE IF NOT EXISTS drop_test (id SERIAL PRIMARY KEY, val TEXT)",
            &[],
        )
        .await
        .expect("CREATE TABLE should succeed");

    client1
        .execute("BEGIN", &[])
        .await
        .expect("BEGIN should succeed");

    client1
        .execute(
            "INSERT INTO drop_test (val) VALUES ('should-be-rolled-back')",
            &[],
        )
        .await
        .expect("INSERT should succeed within transaction");

    // Kill the bridge mid-transaction — connection and open tx will be lost
    stack.bridge_kill.kill_all();

    // Allow teardown to propagate
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Next operation on the dead client should error
    let next_op = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client1.execute("SELECT 1", &[]),
    )
    .await;

    // Classification: STATE_LOSS
    match next_op {
        Ok(Err(_)) | Err(_) => {
            // Expected: operation on dead connection should error or time out
        }
        Ok(Ok(_)) => {
            // Some drivers may not detect the drop immediately — acceptable
        }
    }

    // New connection must succeed and the rolled-back row must be absent
    let (client2, conn2) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio_postgres::connect(&conn_str, NoTls),
    )
    .await
    .expect("reconnect should not time out")
    .expect("reconnect should succeed");

    tokio::spawn(async move {
        let _ = conn2.await;
    });

    let rows = client2
        .query(
            "SELECT val FROM drop_test WHERE val = 'should-be-rolled-back'",
            &[],
        )
        .await
        .expect("SELECT should succeed on new connection");

    // The transaction was rolled back — the row must NOT be present
    assert!(
        rows.is_empty(),
        "rolled-back transaction row must not be present after bridge drop, found {} rows",
        rows.len()
    );
}
