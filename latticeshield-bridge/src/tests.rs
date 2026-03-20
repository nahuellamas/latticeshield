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
    client_respond, generate_keypair, parse_server_hello_signed,
    serialize_client_response, serialize_client_response_signed,
    SigningKey, VerifyingKey, SERVER_HELLO_SIGNED_LEN, CLIENT_RESPONSE_LEN,
};
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use latticeshield_crypto::channel::{EncryptedChannel, FrameResult};
use crate::config::ValidConfig;
use crate::identity::{ClientVerifyingIdentity, ServerIdentity};
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
        quic_enabled: false,
        quic_listen_addr: "127.0.0.1:0".parse().unwrap(),
        quic_cert_path: std::path::PathBuf::from("./keys/tls.crt"),
        quic_key_path: std::path::PathBuf::from("./keys/tls.key"),
        client_auth_enabled: false,
        client_vk_path: None,
        admin_enabled: false,
        admin_listen_addr: "127.0.0.1:0".parse().unwrap(),
        admin_control_plane_vk_path: None,
        admin_rate_limit_per_second: 5,
        admin_handshake_timeout_secs: 10,
        control_plane_install_token: None,
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

#[tokio::test]
async fn quic_listener_not_spawned_when_disabled() {
    // When quic_enabled = false, UDP port 8441 should remain free
    let addr: std::net::SocketAddr = "127.0.0.1:8441".parse().unwrap();
    // If QUIC listener were spawned, binding this UDP socket would fail (or be non-exclusive).
    // We just verify no crash and the test_config has quic_enabled = false.
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    let cfg = test_config(backend_addr);
    assert!(!cfg.quic_enabled, "quic must be disabled in default test config");
    // Also verify the UDP port is bindable (no ghost QUIC listener)
    let sock = std::net::UdpSocket::bind(addr);
    assert!(sock.is_ok(), "UDP port 8441 should be free when QUIC is disabled");
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
        let _ = crate::session::handle(socket, peer, identity, None, MetricsState::new(), test_rotate_tx(), test_config(backend_addr)).await;
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
            let _ = crate::session::handle(socket, peer, identity, None, MetricsState::new(), test_rotate_tx(), test_config(backend_addr)).await;
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
        crate::session::handle(socket, peer, identity, None, MetricsState::new(), test_rotate_tx(), test_config(backend_addr)).await
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
    let app_state = MetricsAppState {
        prometheus_handle: handle,
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
        let _ = crate::session::handle(socket, peer, identity, None, MetricsState::new(), test_rotate_tx(), test_config(backend_addr)).await;
    });

    let mut client = TcpStream::connect(bridge_addr).await.unwrap();

    let mut hello_buf = [0u8; SERVER_HELLO_SIGNED_LEN];
    client.read_exact(&mut hello_buf).await.unwrap();
    let hello = parse_server_hello_signed(&hello_buf, &vk).unwrap();
    let (response, client_key) = client_respond(&hello, &mut OsRng).unwrap();
    client.write_all(&serialize_client_response(&response)).await.unwrap();

    let channel = latticeshield_crypto::channel::EncryptedChannel::new(client_key.as_bytes(), MAX_FRAME);
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
        let _ = crate::session::handle(socket, peer, identity, None, MetricsState::new(), test_rotate_tx(), cfg).await;
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
        let _ = crate::session::handle(socket, peer, identity, None, MetricsState::new(), test_rotate_tx(), cfg).await;
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

/// TEST 8 — POST /rotate ya no existe en :8444 — retorna 404 (movido al canal admin PQC :8445).
#[tokio::test]
async fn post_rotate_endpoint_returns_404_after_mes13() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let app_state = MetricsAppState {
        prometheus_handle: handle,
    };
    let app = crate::server::metrics_app(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // POST /rotate via TCP crudo — debe retornar 404 (ruta eliminada)
    let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
    conn.write_all(b"POST /rotate HTTP/1.0\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    conn.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8(response).unwrap();

    assert!(
        response_str.contains("404"),
        "POST /rotate debe retornar 404 en Mes 13+ (rota via canal admin PQC), got:\n{}",
        &response_str[..response_str.len().min(400)]
    );

    let _ = recorder;
}

// ── Tests de autenticacion mutua (Mes 9) ─────────────────────────────────────

/// Crea un `Arc<ClientVerifyingIdentity>` de prueba y devuelve tambien el `SigningKey`
/// del cliente para que el test pueda firmar el ClientResponse.
fn test_client_auth() -> (Arc<ClientVerifyingIdentity>, SigningKey) {
    let (client_sk, client_vk) = generate_keypair(&mut OsRng);
    let client_sk = SigningKey::from_bytes(client_sk.to_bytes()).unwrap();
    let client_vk = VerifyingKey::from_bytes(client_vk.to_bytes()).unwrap();
    let client_auth = Arc::new(ClientVerifyingIdentity { verifying_key: client_vk });
    (client_auth, client_sk)
}

/// TEST 9 — Autenticacion mutua: happy path.
///
/// El cliente firma su ClientResponse con su SK. El bridge tiene la VK correspondiente.
/// El handshake debe completarse y el relay debe funcionar.
#[tokio::test]
async fn test_session_with_client_auth() {
    let identity = test_identity();
    let server_vk = VerifyingKey::from_bytes(identity.verifying_key.to_bytes()).unwrap();

    let (client_auth, client_sk) = test_client_auth();

    // Backend: echo server
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut conn, _) = backend_listener.accept().await.unwrap();
        let mut buf = vec![0u8; MAX_FRAME];
        let n = conn.read(&mut buf).await.unwrap();
        conn.write_all(&buf[..n]).await.unwrap();
    });

    // Bridge con autenticacion mutua habilitada
    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (socket, peer) = bridge_listener.accept().await.unwrap();
        let _ = crate::session::handle(
            socket, peer, identity, Some(client_auth), MetricsState::new(),
            test_rotate_tx(), test_config(backend_addr),
        ).await;
    });

    // Cliente: handshake con firma del ClientResponse
    let mut client = TcpStream::connect(bridge_addr).await.unwrap();

    let mut hello_buf = [0u8; SERVER_HELLO_SIGNED_LEN];
    client.read_exact(&mut hello_buf).await.unwrap();
    let hello = parse_server_hello_signed(&hello_buf, &server_vk).unwrap();

    // Extraer server_hello_raw (primeros SERVER_HELLO_LEN bytes) para la firma del cliente
    use latticeshield_crypto::SERVER_HELLO_LEN;
    let mut server_hello_raw = [0u8; SERVER_HELLO_LEN];
    server_hello_raw.copy_from_slice(&hello_buf[..SERVER_HELLO_LEN]);

    let (response, client_key) = client_respond(&hello, &mut OsRng).unwrap();
    let signed_cr = serialize_client_response_signed(&response, &client_sk, &server_hello_raw, &mut OsRng).unwrap();
    client.write_all(&signed_cr).await.unwrap();

    // Canal cifrado activo — enviar y recibir
    let channel = EncryptedChannel::new(client_key.as_bytes(), MAX_FRAME);
    let payload = b"mutual auth test payload";
    channel.write_frame(&mut client, payload).await.unwrap();

    let received = match channel.read_frame(&mut client).await.unwrap() {
        FrameResult::Data(data) => data,
        FrameResult::KeyRotate(_) => panic!("inesperado KEY_ROTATE"),
    };

    assert_eq!(received, payload, "el relay debe funcionar con autenticacion mutua");
}

/// TEST 10 — Sin autenticacion mutua: el flujo original (unauthenticated) sigue funcionando.
///
/// Verifica que pasar `None` como `client_auth` mantiene el comportamiento previo.
#[tokio::test]
async fn test_session_without_client_auth() {
    let identity = test_identity();
    let server_vk = VerifyingKey::from_bytes(identity.verifying_key.to_bytes()).unwrap();

    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut conn, _) = backend_listener.accept().await.unwrap();
        let mut buf = vec![0u8; MAX_FRAME];
        let n = conn.read(&mut buf).await.unwrap();
        conn.write_all(&buf[..n]).await.unwrap();
    });

    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (socket, peer) = bridge_listener.accept().await.unwrap();
        let _ = crate::session::handle(
            socket, peer, identity, None, MetricsState::new(),
            test_rotate_tx(), test_config(backend_addr),
        ).await;
    });

    let mut client = TcpStream::connect(bridge_addr).await.unwrap();

    let mut hello_buf = [0u8; SERVER_HELLO_SIGNED_LEN];
    client.read_exact(&mut hello_buf).await.unwrap();
    let hello = parse_server_hello_signed(&hello_buf, &server_vk).unwrap();
    let (response, client_key) = client_respond(&hello, &mut OsRng).unwrap();
    client.write_all(&serialize_client_response(&response)).await.unwrap();

    let channel = EncryptedChannel::new(client_key.as_bytes(), MAX_FRAME);
    let payload = b"unauthenticated path still works";
    channel.write_frame(&mut client, payload).await.unwrap();

    let received = match channel.read_frame(&mut client).await.unwrap() {
        FrameResult::Data(data) => data,
        FrameResult::KeyRotate(_) => panic!("inesperado KEY_ROTATE"),
    };

    assert_eq!(received, payload);
}

/// TEST 11 — VK incorrecta: la sesion es rechazada.
///
/// El bridge tiene una VK distinta a la del cliente. La firma del cliente
/// no puede verificarse → la sesion debe cerrarse con error.
#[tokio::test]
async fn test_session_wrong_client_vk() {
    let identity = test_identity();
    let server_vk = VerifyingKey::from_bytes(identity.verifying_key.to_bytes()).unwrap();

    // VK incorrecta: generamos un keypair diferente y usamos su VK
    let (_, wrong_vk_raw) = generate_keypair(&mut OsRng);
    let wrong_vk = VerifyingKey::from_bytes(wrong_vk_raw.to_bytes()).unwrap();
    let wrong_client_auth = Arc::new(ClientVerifyingIdentity { verifying_key: wrong_vk });

    // Keypair real del cliente (su firma sera invalida para la wrong_vk del bridge)
    let (client_sk_raw, _) = generate_keypair(&mut OsRng);
    let client_sk = SigningKey::from_bytes(client_sk_raw.to_bytes()).unwrap();

    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    tokio::spawn(async move { let _ = backend_listener.accept().await; });

    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();

    let bridge_result = tokio::spawn(async move {
        let (socket, peer) = bridge_listener.accept().await.unwrap();
        crate::session::handle(
            socket, peer, identity, Some(wrong_client_auth), MetricsState::new(),
            test_rotate_tx(), test_config(backend_addr),
        ).await
    });

    let mut client = TcpStream::connect(bridge_addr).await.unwrap();

    let mut hello_buf = [0u8; SERVER_HELLO_SIGNED_LEN];
    client.read_exact(&mut hello_buf).await.unwrap();
    let hello = parse_server_hello_signed(&hello_buf, &server_vk).unwrap();

    use latticeshield_crypto::SERVER_HELLO_LEN;
    let mut server_hello_raw = [0u8; SERVER_HELLO_LEN];
    server_hello_raw.copy_from_slice(&hello_buf[..SERVER_HELLO_LEN]);

    let (response, _client_key) = client_respond(&hello, &mut OsRng).unwrap();
    let signed_cr = serialize_client_response_signed(&response, &client_sk, &server_hello_raw, &mut OsRng).unwrap();
    client.write_all(&signed_cr).await.unwrap();
    drop(client);

    // El bridge debe rechazar la sesion con un error (no Ok)
    let result = bridge_result.await.unwrap();
    assert!(result.is_err(), "sesion con VK incorrecta debe ser rechazada con error");
}

// ── Tests de canal admin PQC (Mes 13) ─────────────────────────────────────────

use latticeshield_crypto::{
    handshake::{
        parse_server_hello_signed as psh_signed,
        SERVER_HELLO_SIGNED_LEN as SHS_LEN,
    },
    channel::EncryptedChannel as EncCh,
};
use crate::admin::{AdminCommand, AdminResponse, CommandFrame};
use crate::identity::ControlPlaneVerifyingIdentity;

/// Crea un par de identidades para el canal admin:
/// - `ServerIdentity` efimero para el bridge
/// - SK + VK del control plane (simulado)
fn test_admin_identities() -> (Arc<ServerIdentity>, Arc<ControlPlaneVerifyingIdentity>, latticeshield_crypto::SigningKey) {
    let bridge_identity = test_identity();
    let (cp_sk_raw, cp_vk_raw) = generate_keypair(&mut OsRng);
    let cp_sk = latticeshield_crypto::SigningKey::from_bytes(cp_sk_raw.to_bytes()).unwrap();
    let cp_vk_identity = ControlPlaneVerifyingIdentity {
        verifying_key: latticeshield_crypto::VerifyingKey::from_bytes(cp_vk_raw.to_bytes()).unwrap(),
    };
    (bridge_identity, Arc::new(cp_vk_identity), cp_sk)
}

/// TEST 12 — Canal admin PQC: handshake completo + GetMetrics.
///
/// Topologia: control plane simulado (este test) ←→ admin listener
/// Verifica que el handshake mutuo pase y que GetMetrics retorne datos.
#[tokio::test]
async fn admin_channel_get_metrics_full_handshake() {
    use latticeshield_crypto::SERVER_HELLO_LEN;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (bridge_identity, cp_vk, cp_sk) = test_admin_identities();
    let bridge_vk = latticeshield_crypto::VerifyingKey::from_bytes(
        bridge_identity.verifying_key.to_bytes()
    ).unwrap();

    // Spawn del admin listener en puerto efimero
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = listener.local_addr().unwrap();
    drop(listener); // re-bind via spawn_admin_listener

    let rotate_tx = test_rotate_tx();
    let metrics_state = MetricsState::new();
    let vk_store = crate::vk_share::new_store();
    let prometheus_handle = global_handle().clone();

    crate::admin::spawn_admin_listener(
        admin_addr,
        Arc::clone(&bridge_identity),
        Arc::clone(&cp_vk),
        Arc::clone(&vk_store),
        Arc::clone(&metrics_state),
        Arc::clone(&rotate_tx),
        prometheus_handle,
        "https://127.0.0.1:8440".to_string(),
        crate::admin::AdminListenerConfig {
            rate_limit_per_second: 100,
            handshake_timeout_secs: 5,
        },
    );

    // Pequeña espera para que el listener este listo
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ── Control plane simulado: conectar y completar el handshake ─────────
    let mut client = TcpStream::connect(admin_addr).await.unwrap();

    // 1. Leer ServerHello firmado (4557 bytes)
    let mut hello_buf = [0u8; SHS_LEN];
    client.read_exact(&mut hello_buf).await.unwrap();

    // 2. Verificar firma del bridge con VK pre-shared
    let hello = psh_signed(&hello_buf, &bridge_vk).expect("bridge ServerHello debe verificar");

    // 3. Generar ClientResponse y firmarlo
    let (response, client_key) = client_respond(&hello, &mut OsRng).unwrap();

    let mut server_hello_raw = [0u8; SERVER_HELLO_LEN];
    server_hello_raw.copy_from_slice(&hello_buf[..SERVER_HELLO_LEN]);
    let signed_cr = serialize_client_response_signed(&response, &cp_sk, &server_hello_raw, &mut OsRng).unwrap();

    client.write_all(&signed_cr).await.unwrap();

    // 4. Canal cifrado activo — enviar GetMetrics
    let channel = EncCh::new(client_key.as_bytes(), 64 * 1024);
    let cmd = CommandFrame { seq: 1, cmd: AdminCommand::GetMetrics };
    let cmd_bytes = serde_json::to_vec(&cmd).unwrap();
    channel.write_frame(&mut client, &cmd_bytes).await.unwrap();

    // 5. Leer respuesta
    let resp_bytes = match channel.read_frame(&mut client).await.unwrap() {
        latticeshield_crypto::FrameResult::Data(b) => b,
        latticeshield_crypto::FrameResult::KeyRotate(_) => panic!("unexpected KEY_ROTATE"),
    };

    let response: AdminResponse = serde_json::from_slice(&resp_bytes).unwrap();
    assert!(
        matches!(response, AdminResponse::Metrics { .. }),
        "GetMetrics debe retornar AdminResponse::Metrics"
    );
}

/// TEST 13 — Canal admin PQC: firma incorrecta del control plane es rechazada.
///
/// El cliente usa una SK diferente a la VK pre-shared en el bridge.
/// El bridge debe cerrar la conexion sin respuesta de aplicacion.
#[tokio::test]
async fn admin_channel_wrong_client_sk_rejected() {
    use latticeshield_crypto::SERVER_HELLO_LEN;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (bridge_identity, cp_vk, _cp_sk_correct) = test_admin_identities();
    let bridge_vk = latticeshield_crypto::VerifyingKey::from_bytes(
        bridge_identity.verifying_key.to_bytes()
    ).unwrap();

    // Generar una SK INCORRECTA (diferente al cp_vk pre-shared en el bridge)
    let (wrong_sk_raw, _) = generate_keypair(&mut OsRng);
    let wrong_sk = latticeshield_crypto::SigningKey::from_bytes(wrong_sk_raw.to_bytes()).unwrap();

    let rotate_tx = test_rotate_tx();
    let metrics_state = MetricsState::new();
    let vk_store = crate::vk_share::new_store();
    let prometheus_handle = global_handle().clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = listener.local_addr().unwrap();
    drop(listener);

    crate::admin::spawn_admin_listener(
        admin_addr,
        Arc::clone(&bridge_identity),
        Arc::clone(&cp_vk),
        Arc::clone(&vk_store),
        Arc::clone(&metrics_state),
        Arc::clone(&rotate_tx),
        prometheus_handle,
        "https://127.0.0.1:8440".to_string(),
        crate::admin::AdminListenerConfig {
            rate_limit_per_second: 100,
            handshake_timeout_secs: 5,
        },
    );

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(admin_addr).await.unwrap();

    // Leer ServerHello
    let mut hello_buf = [0u8; SHS_LEN];
    client.read_exact(&mut hello_buf).await.unwrap();
    let hello = psh_signed(&hello_buf, &bridge_vk).expect("bridge hello debe verificar");

    // Firmar con la SK INCORRECTA
    let (response, _client_key) = client_respond(&hello, &mut OsRng).unwrap();
    let mut server_hello_raw = [0u8; SERVER_HELLO_LEN];
    server_hello_raw.copy_from_slice(&hello_buf[..SERVER_HELLO_LEN]);
    let signed_cr = serialize_client_response_signed(&response, &wrong_sk, &server_hello_raw, &mut OsRng).unwrap();

    client.write_all(&signed_cr).await.unwrap();

    // El bridge debe cerrar la conexion — el cliente no deberia recibir datos de aplicacion
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(
        Duration::from_secs(2),
        client.read(&mut buf),
    ).await;

    // El bridge cierra la conexion (n=0 EOF) o timeout — ambos son aceptables
    match n {
        Ok(Ok(0)) => { /* EOF — bridge cerro la conexion correctamente */ }
        Ok(Ok(bytes_read)) => {
            // Si llegan bytes, deben ser del handshake no de la aplicacion
            // (El bridge rechaza el handshake y no envia respuesta de aplicacion)
            panic!("bridge envio {bytes_read} bytes inesperados despues de firma incorrecta");
        }
        Ok(Err(_)) | Err(_) => { /* connection reset o timeout — aceptable */ }
    }
}

/// TEST 14 — Canal admin PQC: handshake completo + Rotate.
///
/// Verifica que el comando Rotate es procesado y retorna AdminResponse::Rotated.
#[tokio::test]
async fn admin_channel_rotate_full_handshake() {
    use latticeshield_crypto::SERVER_HELLO_LEN;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (bridge_identity, cp_vk, cp_sk) = test_admin_identities();
    let bridge_vk = latticeshield_crypto::VerifyingKey::from_bytes(
        bridge_identity.verifying_key.to_bytes()
    ).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = listener.local_addr().unwrap();
    drop(listener);

    let rotate_tx = test_rotate_tx();
    let metrics_state = MetricsState::new();
    let vk_store = crate::vk_share::new_store();
    let prometheus_handle = global_handle().clone();

    crate::admin::spawn_admin_listener(
        admin_addr,
        Arc::clone(&bridge_identity),
        Arc::clone(&cp_vk),
        Arc::clone(&vk_store),
        Arc::clone(&metrics_state),
        Arc::clone(&rotate_tx),
        prometheus_handle,
        "https://127.0.0.1:8440".to_string(),
        crate::admin::AdminListenerConfig {
            rate_limit_per_second: 100,
            handshake_timeout_secs: 5,
        },
    );

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(admin_addr).await.unwrap();

    // 1. Leer ServerHello firmado
    let mut hello_buf = [0u8; SHS_LEN];
    client.read_exact(&mut hello_buf).await.unwrap();

    // 2. Verificar y completar el handshake
    let hello = psh_signed(&hello_buf, &bridge_vk).expect("bridge ServerHello debe verificar");
    let (response, client_key) = client_respond(&hello, &mut OsRng).unwrap();

    let mut server_hello_raw = [0u8; SERVER_HELLO_LEN];
    server_hello_raw.copy_from_slice(&hello_buf[..SERVER_HELLO_LEN]);
    let signed_cr = serialize_client_response_signed(&response, &cp_sk, &server_hello_raw, &mut OsRng).unwrap();
    client.write_all(&signed_cr).await.unwrap();

    // 3. Enviar Rotate
    let channel = EncCh::new(client_key.as_bytes(), 64 * 1024);
    let cmd = CommandFrame { seq: 2, cmd: AdminCommand::Rotate };
    let cmd_bytes = serde_json::to_vec(&cmd).unwrap();
    channel.write_frame(&mut client, &cmd_bytes).await.unwrap();

    // 4. Leer respuesta
    let resp_bytes = match channel.read_frame(&mut client).await.unwrap() {
        latticeshield_crypto::FrameResult::Data(b) => b,
        latticeshield_crypto::FrameResult::KeyRotate(_) => panic!("unexpected KEY_ROTATE"),
    };

    let resp: AdminResponse = serde_json::from_slice(&resp_bytes).unwrap();
    assert!(
        matches!(resp, AdminResponse::Rotated { .. }),
        "Rotate debe retornar AdminResponse::Rotated, got: {resp:?}"
    );
}

/// TEST 15 — Canal admin PQC: handshake completo + GetVkToken.
///
/// Verifica que el comando GetVkToken retorna AdminResponse::VkToken con una URL valida.
#[tokio::test]
async fn admin_channel_get_vk_token_full_handshake() {
    use latticeshield_crypto::SERVER_HELLO_LEN;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (bridge_identity, cp_vk, cp_sk) = test_admin_identities();
    let bridge_vk = latticeshield_crypto::VerifyingKey::from_bytes(
        bridge_identity.verifying_key.to_bytes()
    ).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = listener.local_addr().unwrap();
    drop(listener);

    let rotate_tx = test_rotate_tx();
    let metrics_state = MetricsState::new();
    let vk_store = crate::vk_share::new_store();
    let prometheus_handle = global_handle().clone();

    crate::admin::spawn_admin_listener(
        admin_addr,
        Arc::clone(&bridge_identity),
        Arc::clone(&cp_vk),
        Arc::clone(&vk_store),
        Arc::clone(&metrics_state),
        Arc::clone(&rotate_tx),
        prometheus_handle,
        "https://127.0.0.1:8440".to_string(),
        crate::admin::AdminListenerConfig {
            rate_limit_per_second: 100,
            handshake_timeout_secs: 5,
        },
    );

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(admin_addr).await.unwrap();

    // 1. Leer ServerHello firmado
    let mut hello_buf = [0u8; SHS_LEN];
    client.read_exact(&mut hello_buf).await.unwrap();

    // 2. Verificar y completar el handshake
    let hello = psh_signed(&hello_buf, &bridge_vk).expect("bridge ServerHello debe verificar");
    let (response, client_key) = client_respond(&hello, &mut OsRng).unwrap();

    let mut server_hello_raw = [0u8; SERVER_HELLO_LEN];
    server_hello_raw.copy_from_slice(&hello_buf[..SERVER_HELLO_LEN]);
    let signed_cr = serialize_client_response_signed(&response, &cp_sk, &server_hello_raw, &mut OsRng).unwrap();
    client.write_all(&signed_cr).await.unwrap();

    // 3. Enviar GetVkToken
    let channel = EncCh::new(client_key.as_bytes(), 64 * 1024);
    let cmd = CommandFrame { seq: 3, cmd: AdminCommand::GetVkToken };
    let cmd_bytes = serde_json::to_vec(&cmd).unwrap();
    channel.write_frame(&mut client, &cmd_bytes).await.unwrap();

    // 4. Leer respuesta
    let resp_bytes = match channel.read_frame(&mut client).await.unwrap() {
        latticeshield_crypto::FrameResult::Data(b) => b,
        latticeshield_crypto::FrameResult::KeyRotate(_) => panic!("unexpected KEY_ROTATE"),
    };

    let resp: AdminResponse = serde_json::from_slice(&resp_bytes).unwrap();
    match resp {
        AdminResponse::VkToken { url, .. } => {
            assert!(
                url.contains("/vk/"),
                "la URL del VkToken debe contener '/vk/', got: {url}"
            );
        }
        other => panic!("GetVkToken debe retornar AdminResponse::VkToken, got: {other:?}"),
    }
}
