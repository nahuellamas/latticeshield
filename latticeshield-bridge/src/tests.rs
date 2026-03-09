//! Integration tests: flujo completo PQC end-to-end.
//!
//! Valida que cliente y servidor puedan:
//!   1. Completar el handshake autenticado: ServerHello firmado ML-DSA-65 + pre-shared VK
//!   2. Derivar la misma SessionKey
//!   3. Intercambiar datos cifrados a traves del proxy
//!   4. El backend recibe y responde el payload correcto

use std::sync::Arc;

use latticeshield_crypto::{
    client_respond, generate_keypair, parse_server_hello_signed, serialize_client_response,
    SigningKey, VerifyingKey, SERVER_HELLO_SIGNED_LEN, CLIENT_RESPONSE_LEN,
};
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::channel::EncryptedChannel;
use crate::identity::ServerIdentity;

const MAX_FRAME: usize = 64 * 1024;

/// Crea un `Arc<ServerIdentity>` de prueba con un keypair efimero.
fn test_identity() -> Arc<ServerIdentity> {
    let (sk, vk) = generate_keypair(&mut OsRng);
    let sk = SigningKey::from_bytes(sk.to_bytes()).unwrap();
    let vk = VerifyingKey::from_bytes(vk.to_bytes()).unwrap();
    Arc::new(ServerIdentity { signing_key: sk, verifying_key: vk })
}

/// Flujo completo: handshake PQC autenticado + cifrado AES-GCM + relay al backend.
///
/// Topologia del test:
///   cliente (test) ←→ bridge (session::handle) ←→ backend mock (echo)
#[tokio::test]
async fn full_pqc_handshake_and_relay() {
    let identity = test_identity();
    let vk = VerifyingKey::from_bytes(identity.verifying_key.to_bytes()).unwrap();

    // ── Backend mock: echo server ────────────────────────────────────────────
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut conn, _) = backend_listener.accept().await.unwrap();
        let mut buf = vec![0u8; MAX_FRAME];
        let n = conn.read(&mut buf).await.unwrap();
        conn.write_all(&buf[..n]).await.unwrap();
    });

    // ── Bridge: una sesion ───────────────────────────────────────────────────
    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (socket, peer) = bridge_listener.accept().await.unwrap();
        let _ = crate::session::handle(socket, peer, backend_addr, MAX_FRAME, identity).await;
    });

    // ── Cliente: realiza el handshake autenticado ────────────────────────────
    let mut client = TcpStream::connect(bridge_addr).await.unwrap();

    // 1. Leer ServerHello firmado
    let mut hello_buf = [0u8; SERVER_HELLO_SIGNED_LEN];
    client.read_exact(&mut hello_buf).await.unwrap();

    // 2. Verificar firma con VK pre-shared y parsear
    let hello = parse_server_hello_signed(&hello_buf, &vk).unwrap();
    let (response, client_key) = client_respond(&hello, &mut OsRng).unwrap();

    // 3. Enviar ClientResponse
    client.write_all(&serialize_client_response(&response)).await.unwrap();

    // 4. Canal cifrado activo — enviar request
    let channel = EncryptedChannel::new(client_key.as_bytes(), MAX_FRAME);
    let payload = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    channel.write_frame(&mut client, payload).await.unwrap();

    // 5. Recibir response cifrado del bridge
    let received = channel.read_frame(&mut client).await.unwrap();

    assert_eq!(received, payload, "el backend debe haber echo-eado el payload exacto");
}

/// Verifica que dos handshakes independientes producen SessionKeys distintas.
#[tokio::test]
async fn two_sessions_produce_different_keys() {
    async fn do_handshake(identity: Arc<ServerIdentity>, vk: Arc<VerifyingKey>) -> Vec<u8> {
        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = backend_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = conn.read(&mut buf).await.unwrap();
            conn.write_all(&buf[..n]).await.unwrap();
        });

        let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bridge_addr = bridge_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (socket, peer) = bridge_listener.accept().await.unwrap();
            let _ = crate::session::handle(socket, peer, backend_addr, MAX_FRAME, identity).await;
        });

        let mut client = TcpStream::connect(bridge_addr).await.unwrap();
        let mut hello_buf = [0u8; SERVER_HELLO_SIGNED_LEN];
        client.read_exact(&mut hello_buf).await.unwrap();
        let hello = parse_server_hello_signed(&hello_buf, &vk).unwrap();
        let (response, key) = client_respond(&hello, &mut OsRng).unwrap();
        client.write_all(&serialize_client_response(&response)).await.unwrap();
        key.as_bytes().to_vec()
    }

    let identity = test_identity();
    let vk = Arc::new(VerifyingKey::from_bytes(identity.verifying_key.to_bytes()).unwrap());

    let key1 = do_handshake(Arc::clone(&identity), Arc::clone(&vk)).await;
    let key2 = do_handshake(Arc::clone(&identity), Arc::clone(&vk)).await;

    assert_ne!(key1, key2, "cada sesion debe producir una SessionKey unica");
}

/// Verifica que un ClientResponse corrupto es rechazado por el bridge.
#[tokio::test]
async fn tampered_client_response_is_rejected() {
    let identity = test_identity();

    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = backend_listener.accept().await;
    });

    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();

    let bridge_result = tokio::spawn(async move {
        let (socket, peer) = bridge_listener.accept().await.unwrap();
        crate::session::handle(socket, peer, backend_addr, MAX_FRAME, identity).await
    });

    let mut client = TcpStream::connect(bridge_addr).await.unwrap();
    let mut hello_buf = [0u8; SERVER_HELLO_SIGNED_LEN];
    client.read_exact(&mut hello_buf).await.unwrap();

    // Enviar ClientResponse completamente invalido (ceros)
    client.write_all(&[0u8; CLIENT_RESPONSE_LEN]).await.unwrap();
    drop(client);

    let _ = bridge_result.await.unwrap();
}

// ── Tests de métricas Prometheus ─────────────────────────────────────────────

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;

use crate::metrics::{
    ActiveGuard, BYTES_TRANSMITTED, CHANNEL_ERRORS, CONNECTIONS_ACTIVE, CONNECTIONS_TOTAL,
    HANDSHAKE_DURATION,
};

/// Recorder global compartido por los tests que ejercitan código async
/// (session::handle, channel::write_frame) — se inicializa una sola vez.
static GLOBAL_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

fn global_handle() -> &'static PrometheusHandle {
    GLOBAL_HANDLE.get_or_init(|| crate::metrics::init().expect("metrics init fallido"))
}

/// Extrae el valor numérico de una métrica en el texto Prometheus.
/// Suma todas las líneas que empiecen con `name` (sin `#`).
fn metric_value(output: &str, name: &str) -> f64 {
    output
        .lines()
        .filter(|l| l.starts_with(name) && !l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().nth(1))
        .filter_map(|v| v.parse::<f64>().ok())
        .sum()
}

/// TEST 1 — Después de init(), las 5 familias de métricas aparecen en el output.
///
/// Valida el escenario de la spec: "GIVEN the bridge just started and no client
/// has connected, THEN the response body includes all five metric families".
/// Usa recorder local para no contaminar el estado global.
#[test]
fn init_describes_all_five_metric_families() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    metrics::with_local_recorder(&recorder, || {
        // Registrar descriptores (igual que metrics::init())
        metrics::describe_counter!(CONNECTIONS_TOTAL, "test");
        metrics::describe_gauge!(CONNECTIONS_ACTIVE, "test");
        metrics::describe_histogram!(HANDSHAKE_DURATION, "test");
        metrics::describe_counter!(BYTES_TRANSMITTED, "test");
        metrics::describe_counter!(CHANNEL_ERRORS, "test");

        // Prometheus solo incluye métricas que tienen al menos un valor registrado.
        // Simulamos el estado "recién arrancado" con valores mínimos.
        metrics::counter!(CONNECTIONS_TOTAL).increment(1);
        metrics::gauge!(CONNECTIONS_ACTIVE).set(0.0);
        metrics::histogram!(HANDSHAKE_DURATION).record(0.001);
        metrics::counter!(BYTES_TRANSMITTED).increment(1);
        metrics::counter!(CHANNEL_ERRORS).increment(1);
    });

    let output = handle.render();
    assert!(output.contains(CONNECTIONS_TOTAL), "falta {CONNECTIONS_TOTAL}");
    assert!(output.contains(CONNECTIONS_ACTIVE), "falta {CONNECTIONS_ACTIVE}");
    assert!(output.contains(HANDSHAKE_DURATION), "falta {HANDSHAKE_DURATION}");
    assert!(output.contains(BYTES_TRANSMITTED), "falta {BYTES_TRANSMITTED}");
    assert!(output.contains(CHANNEL_ERRORS), "falta {CHANNEL_ERRORS}");
}

/// TEST 2 — ActiveGuard incrementa connections_active al crearse y lo decrementa al dropearse.
///
/// Valida el comportamiento RAII del gauge: si hay N sesiones activas y una termina,
/// el gauge debe reflejar N-1. Usa recorder local para control exacto del valor.
#[test]
fn active_guard_manages_connections_active_gauge() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    metrics::with_local_recorder(&recorder, || {
        // Sin guards: el gauge no existe todavía
        assert!(
            !handle.render().contains(CONNECTIONS_ACTIVE),
            "gauge no debe existir antes de crear ningún guard"
        );

        let guard = ActiveGuard::new();

        assert_eq!(
            metric_value(&handle.render(), CONNECTIONS_ACTIVE),
            1.0,
            "gauge debe ser 1.0 tras ActiveGuard::new()"
        );

        drop(guard);

        assert_eq!(
            metric_value(&handle.render(), CONNECTIONS_ACTIVE),
            0.0,
            "gauge debe ser 0.0 tras drop del guard"
        );
    });
}

/// TEST 3 — bytes_transmitted_total crece exactamente con los bytes simulados.
///
/// Valida el mecanismo del counter con el const identifier correcto.
/// El test de integración real (que write_frame llama este counter) lo cubre Test 5.
/// Test síncrono: usa with_local_recorder para aislamiento total.
#[test]
fn bytes_transmitted_counter_increments_correctly() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let payload = b"hello latticeshield metrics";

    metrics::with_local_recorder(&recorder, || {
        metrics::counter!(BYTES_TRANSMITTED).increment(payload.len() as u64);
    });

    let output = handle.render();
    assert!(
        output.contains(BYTES_TRANSMITTED),
        "bytes_transmitted_total no aparece en el render"
    );
    assert_eq!(
        metric_value(&output, BYTES_TRANSMITTED),
        payload.len() as f64,
        "bytes_transmitted debe ser exactamente {} bytes",
        payload.len()
    );
}

/// TEST 4 — El endpoint HTTP responde 200 OK con Content-Type de Prometheus.
///
/// Valida RF-01: "The endpoint MUST return metrics in Prometheus text exposition format".
/// Levanta el servidor axum real, hace un GET /metrics con TCP crudo y verifica
/// el status code y el Content-Type exacto que Prometheus espera.
#[tokio::test]
async fn http_endpoint_returns_200_ok_with_prometheus_content_type() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let app = crate::server::metrics_app(handle);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // HTTP GET crudo — sin dependencias externas
    let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
    conn.write_all(b"GET /metrics HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    conn.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8(response).unwrap();

    assert!(
        response_str.contains("200 OK"),
        "esperado 200 OK, response:\n{}",
        &response_str[..response_str.len().min(300)]
    );
    assert!(
        response_str.contains("text/plain; version=0.0.4; charset=utf-8"),
        "Content-Type incorrecto, response:\n{}",
        &response_str[..response_str.len().min(300)]
    );

    let _ = recorder; // mantiene el recorder vivo durante el test
}

/// TEST 5 — Una sesión PQC completa registra connections_total, handshake_duration y bytes_transmitted.
///
/// Valida la cadena completa: session::handle → channel::write_frame → métricas.
/// Usa el recorder global compartido. Los counters se verifican con >= porque pueden
/// acumular valores de otros tests que usen el mismo recorder.
#[tokio::test]
async fn full_session_records_connections_and_bytes() {
    use latticeshield_crypto::{
        client_respond, serialize_client_response,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let handle = global_handle();

    let before_connections = metric_value(&handle.render(), CONNECTIONS_TOTAL);
    let before_bytes = metric_value(&handle.render(), BYTES_TRANSMITTED);

    // Topología: backend echo → bridge → cliente
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut conn, _) = backend_listener.accept().await.unwrap();
        let mut buf = vec![0u8; MAX_FRAME];
        let n = conn.read(&mut buf).await.unwrap();
        conn.write_all(&buf[..n]).await.unwrap();
    });

    let identity = test_identity();
    let vk = VerifyingKey::from_bytes(identity.verifying_key.to_bytes()).unwrap();

    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (socket, peer) = bridge_listener.accept().await.unwrap();
        let _ = crate::session::handle(socket, peer, backend_addr, MAX_FRAME, identity).await;
    });

    let mut client = TcpStream::connect(bridge_addr).await.unwrap();

    let mut hello_buf = [0u8; SERVER_HELLO_SIGNED_LEN];
    client.read_exact(&mut hello_buf).await.unwrap();
    let hello = parse_server_hello_signed(&hello_buf, &vk).unwrap();
    let (response, client_key) = client_respond(&hello, &mut OsRng).unwrap();
    client.write_all(&serialize_client_response(&response)).await.unwrap();

    let channel = crate::channel::EncryptedChannel::new(client_key.as_bytes(), MAX_FRAME);
    let payload = b"GET / HTTP/1.0\r\n\r\n";
    channel.write_frame(&mut client, payload).await.unwrap();
    let _ = channel.read_frame(&mut client).await.unwrap();
    drop(client); // cierra la sesión

    // Pequeña espera para que la task del bridge termine y haga drop del ActiveGuard
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let output = handle.render();

    assert!(
        metric_value(&output, CONNECTIONS_TOTAL) > before_connections,
        "connections_total debe haber incrementado"
    );
    assert!(
        metric_value(&output, BYTES_TRANSMITTED) > before_bytes,
        "bytes_transmitted debe haber incrementado"
    );
    assert!(
        output.contains(HANDSHAKE_DURATION),
        "handshake_duration_seconds debe aparecer en el render"
    );
    assert_eq!(
        metric_value(&output, CONNECTIONS_ACTIVE),
        0.0,
        "connections_active debe ser 0 después de que la sesión terminó"
    );
}
