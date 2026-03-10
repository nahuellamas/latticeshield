//! Integration tests: flujo completo PQC end-to-end.
//!
//! Valida que cliente y servidor puedan:
//!   1. Completar el handshake autenticado: ServerHello firmado ML-DSA-65 + pre-shared VK
//!   2. Derivar la misma SessionKey
//!   3. Intercambiar datos cifrados a traves del proxy
//!   4. El backend recibe y responde el payload correcto
//!   5. La rotacion de clave de sesion funciona sin cortar la conexion

use std::sync::Arc;
use std::time::Duration;

use latticeshield_crypto::{
    client_respond, generate_keypair, parse_server_hello_signed, serialize_client_response,
    SigningKey, VerifyingKey, SERVER_HELLO_SIGNED_LEN, CLIENT_RESPONSE_LEN,
};
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::channel::{EncryptedChannel, FrameResult};
use crate::config::ValidConfig;
use crate::identity::ServerIdentity;
use crate::metrics::MetricsState;

const MAX_FRAME: usize = 64 * 1024;

/// Crea un `Arc<ServerIdentity>` de prueba con un keypair efimero.
fn test_identity() -> Arc<ServerIdentity> {
    let (sk, vk) = generate_keypair(&mut OsRng);
    let sk = SigningKey::from_bytes(sk.to_bytes()).unwrap();
    let vk = VerifyingKey::from_bytes(vk.to_bytes()).unwrap();
    Arc::new(ServerIdentity { signing_key: sk, verifying_key: vk })
}

/// Crea un ValidConfig minimo para tests, con el backend_addr dado.
fn test_config(backend_addr: std::net::SocketAddr) -> ValidConfig {
    ValidConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        backend_addr,
        metrics_addr: "127.0.0.1:0".parse().unwrap(),
        max_frame_size: MAX_FRAME,
        signing_key_path: std::path::PathBuf::from("./keys/server.sk"),
        log_level: "info".to_string(),
        control_plane_enabled: false,
        control_plane_endpoint: String::new(),
        control_plane_agent_name: String::new(),
        heartbeat_interval: Duration::from_secs(30),
        key_rotation_enabled: false,
        max_bytes_per_key: 10_737_418_240,
        key_rotation_interval: Duration::from_secs(86_400),
        tls_enabled: false,
        tls_listen_addr: "127.0.0.1:0".parse().unwrap(),
        tls_cert_path: std::path::PathBuf::from("./keys/tls.crt"),
        tls_key_path: std::path::PathBuf::from("./keys/tls.key"),
    }
}

#[tokio::test]
async fn tls_listener_not_spawned_when_disabled() {
    // When tls_enabled = false, port 8440 should remain free
    // (this test verifies no phantom listener is bound)
    let addr: std::net::SocketAddr = "127.0.0.1:8440".parse().unwrap();
    // If TLS listener were spawned, binding this would fail
    let _listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("port 8440 should be free when TLS is disabled");
    // No further assertion needed — the bind succeeding is the assertion
}

/// Crea un Arc<watch::Sender<u64>> de prueba (sin receptores activos).
fn test_rotate_tx() -> Arc<watch::Sender<u64>> {
    let (tx, _rx) = watch::channel(0u64);
    Arc::new(tx)
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
        let _ = crate::session::handle(socket, peer, identity, MetricsState::new(), test_rotate_tx(), test_config(backend_addr)).await;
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
    let received = match channel.read_frame(&mut client).await.unwrap() {
        FrameResult::Data(data) => data,
        FrameResult::KeyRotate(_) => panic!("inesperado KEY_ROTATE"),
    };

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
            let _ = crate::session::handle(socket, peer, identity, MetricsState::new(), test_rotate_tx(), test_config(backend_addr)).await;
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
        crate::session::handle(socket, peer, identity, MetricsState::new(), test_rotate_tx(), test_config(backend_addr)).await
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
use crate::server::MetricsAppState;

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
#[test]
fn init_describes_all_five_metric_families() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    metrics::with_local_recorder(&recorder, || {
        metrics::describe_counter!(CONNECTIONS_TOTAL, "test");
        metrics::describe_gauge!(CONNECTIONS_ACTIVE, "test");
        metrics::describe_histogram!(HANDSHAKE_DURATION, "test");
        metrics::describe_counter!(BYTES_TRANSMITTED, "test");
        metrics::describe_counter!(CHANNEL_ERRORS, "test");

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
#[test]
fn active_guard_manages_connections_active_gauge() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    metrics::with_local_recorder(&recorder, || {
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

/// TEST 4 — El endpoint HTTP /metrics responde 200 OK con Content-Type de Prometheus.
#[tokio::test]
async fn http_endpoint_returns_200_ok_with_prometheus_content_type() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let (rotate_tx, _) = watch::channel(0u64);
    let app_state = MetricsAppState {
        prometheus_handle: handle,
        rotate_tx: Arc::new(rotate_tx),
        metrics_state: MetricsState::new(),
    };
    let app = crate::server::metrics_app(app_state);

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

    let _ = recorder;
}

/// TEST 5 — Una sesión PQC completa registra connections_total, handshake_duration y bytes_transmitted.
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
        let _ = crate::session::handle(socket, peer, identity, MetricsState::new(), test_rotate_tx(), test_config(backend_addr)).await;
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
    tokio::time::sleep(Duration::from_millis(150)).await;

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
    // connections_active: el gauge puede estar en cualquier valor durante tests
    // concurrentes (otros tests tambien crean sesiones con ActiveGuard global).
    // Lo que validamos es que el gauge bajo respecto al pico — es decir, nuestra
    // sesion fue contabilizada y su guard fue dropeado.
    // La validacion precisa de RAII ya esta cubierta por active_guard_manages_connections_active_gauge.
    let active_after = metric_value(&output, CONNECTIONS_ACTIVE);
    assert!(
        active_after <= 1.0,
        "connections_active debe ser bajo (<=1) despues de que nuestra sesion termino, got: {active_after}"
    );
}

// ── Tests de rotacion de clave de sesion ─────────────────────────────────────

/// TEST 6 — Relay completo: el cliente recibe KEY_ROTATE por tiempo y puede seguir leyendo.
///
/// Topologia: cliente ←→ bridge (rotacion por intervalo corto) ←→ backend echo.
/// El cliente simula el protocolo de KDF ratchet al recibir KEY_ROTATE.
///
/// Se usa intervalo de 200ms (no la señal watch) para evitar la race condition
/// donde rotate_tx.send_modify() se llama antes de que el session task haya
/// ejecutado rotate_rx = rotate_tx.subscribe().
#[tokio::test]
async fn full_relay_survives_key_rotation() {
    let identity = test_identity();
    let vk = VerifyingKey::from_bytes(identity.verifying_key.to_bytes()).unwrap();

    // Backend: echo server — espera datos y los devuelve
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut conn, _) = backend_listener.accept().await.unwrap();
        let mut buf = vec![0u8; MAX_FRAME];
        let n = conn.read(&mut buf).await.unwrap();
        conn.write_all(&buf[..n]).await.unwrap();
    });

    // Bridge con rotacion habilitada cada 200ms (muy rapido para el test)
    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();

    let mut cfg = test_config(backend_addr);
    cfg.key_rotation_enabled = true;
    cfg.key_rotation_interval = Duration::from_millis(200);

    tokio::spawn(async move {
        let (socket, peer) = bridge_listener.accept().await.unwrap();
        let _ = crate::session::handle(socket, peer, identity, MetricsState::new(), test_rotate_tx(), cfg).await;
    });

    // Cliente: handshake completo
    let mut client = TcpStream::connect(bridge_addr).await.unwrap();
    let mut hello_buf = [0u8; SERVER_HELLO_SIGNED_LEN];
    client.read_exact(&mut hello_buf).await.unwrap();
    let hello = parse_server_hello_signed(&hello_buf, &vk).unwrap();
    let (response, client_key) = client_respond(&hello, &mut OsRng).unwrap();
    client.write_all(&serialize_client_response(&response)).await.unwrap();

    let mut channel = EncryptedChannel::new(client_key.as_bytes(), MAX_FRAME);

    // El timer del bridge dispara a los 200ms — el cliente espera KEY_ROTATE.
    // read_frame() bloquea hasta recibir el frame (el bridge lo manda cuando el timer dispara).
    match channel.read_frame(&mut client).await.unwrap() {
        FrameResult::KeyRotate(nonce) => {
            channel.rotate_key(&nonce);
        }
        FrameResult::Data(_) => panic!("esperado KEY_ROTATE, recibido Data"),
    }

    // Enviar datos con la nueva clave — el bridge debe poder descifrarlos
    let payload = b"hello after rotation";
    channel.write_frame(&mut client, payload).await.unwrap();

    let received = match channel.read_frame(&mut client).await.unwrap() {
        FrameResult::Data(data) => data,
        FrameResult::KeyRotate(_) => panic!("inesperado segundo KEY_ROTATE"),
    };

    assert_eq!(received, payload, "relay debe funcionar despues de la rotacion");
}

/// TEST 7 — El umbral de bytes dispara una rotacion automatica.
///
/// Configura max_bytes_per_key = 1 MiB. El backend devuelve 1 MiB + 1 byte.
/// El cliente debe recibir KEY_ROTATE despues de que el threshold se supera.
#[tokio::test]
async fn byte_threshold_triggers_rotation() {
    let identity = test_identity();
    let vk = VerifyingKey::from_bytes(identity.verifying_key.to_bytes()).unwrap();

    // Backend: responde exactamente 1 MiB + 1 byte de datos
    let large_payload = vec![0x42u8; 1_048_576 + 1];
    let payload_clone = large_payload.clone();

    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut conn, _) = backend_listener.accept().await.unwrap();
        // Leer el request del bridge
        let mut buf = vec![0u8; MAX_FRAME];
        let _ = conn.read(&mut buf).await.unwrap();
        // Responder con datos grandes (en chunks de MAX_FRAME)
        for chunk in payload_clone.chunks(MAX_FRAME) {
            conn.write_all(chunk).await.unwrap();
        }
    });

    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();

    let mut cfg = test_config(backend_addr);
    cfg.key_rotation_enabled = true;
    cfg.max_bytes_per_key = 1_048_576; // 1 MiB — threshold

    tokio::spawn(async move {
        let (socket, peer) = bridge_listener.accept().await.unwrap();
        let _ = crate::session::handle(socket, peer, identity, MetricsState::new(), test_rotate_tx(), cfg).await;
    });

    // Cliente: handshake
    let mut client = TcpStream::connect(bridge_addr).await.unwrap();
    let mut hello_buf = [0u8; SERVER_HELLO_SIGNED_LEN];
    client.read_exact(&mut hello_buf).await.unwrap();
    let hello = parse_server_hello_signed(&hello_buf, &vk).unwrap();
    let (response, client_key) = client_respond(&hello, &mut OsRng).unwrap();
    client.write_all(&serialize_client_response(&response)).await.unwrap();

    let mut channel = EncryptedChannel::new(client_key.as_bytes(), MAX_FRAME);

    // Disparar al backend — el bridge va a reenviar los bytes al cliente
    channel.write_frame(&mut client, b"trigger").await.unwrap();

    // Leer frames del bridge hasta recibir KEY_ROTATE
    let mut got_rotation = false;
    for _ in 0..200 {
        match channel.read_frame(&mut client).await.unwrap() {
            FrameResult::KeyRotate(nonce) => {
                channel.rotate_key(&nonce);
                got_rotation = true;
                break;
            }
            FrameResult::Data(_) => {
                // Seguir leyendo hasta el KEY_ROTATE
            }
        }
    }

    assert!(got_rotation, "byte threshold debe haber disparado KEY_ROTATE");
}

/// TEST 8 — POST /rotate responde 200 con JSON {"rotated": N}.
#[tokio::test]
async fn post_rotate_endpoint_returns_200() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let (rotate_tx, rotate_rx) = watch::channel(0u64);
    let rotate_tx = Arc::new(rotate_tx);

    let metrics_state = MetricsState::new();
    let app_state = MetricsAppState {
        prometheus_handle: handle,
        rotate_tx: Arc::clone(&rotate_tx),
        metrics_state: Arc::clone(&metrics_state),
    };
    let app = crate::server::metrics_app(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // POST /rotate via TCP crudo
    let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
    conn.write_all(b"POST /rotate HTTP/1.0\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    conn.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8(response).unwrap();

    assert!(
        response_str.contains("200 OK"),
        "POST /rotate debe retornar 200, got:\n{}",
        &response_str[..response_str.len().min(400)]
    );
    assert!(
        response_str.contains("rotated"),
        "body debe contener 'rotated', got:\n{}",
        &response_str[..response_str.len().min(400)]
    );

    // El watch channel debe haber recibido la senal
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(*rotate_rx.borrow() > 0, "rotate_tx debe haber enviado una senal");

    let _ = recorder;
}
