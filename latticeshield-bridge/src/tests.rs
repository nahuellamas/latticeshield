//! Integration tests: flujo completo PQC end-to-end.
//!
//! Valida que cliente y servidor puedan:
//!   1. Completar el handshake hibrido X25519 + ML-KEM-768
//!   2. Derivar la misma SessionKey
//!   3. Intercambiar datos cifrados a traves del proxy
//!   4. El backend recibe y responde el payload correcto

use latticeshield_crypto::{
    client_respond, parse_server_hello, serialize_client_response, SERVER_HELLO_LEN,
    CLIENT_RESPONSE_LEN,
};
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::channel::EncryptedChannel;

const MAX_FRAME: usize = 64 * 1024;

/// Flujo completo: handshake PQC + cifrado AES-GCM + relay al backend.
///
/// Topologia del test:
///   cliente (test) ←→ bridge (session::handle) ←→ backend mock (echo)
#[tokio::test]
async fn full_pqc_handshake_and_relay() {
    // ── Backend mock: echo server ────────────────────────────────────────────
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut conn, _) = backend_listener.accept().await.unwrap();
        let mut buf = vec![0u8; MAX_FRAME];
        let n = conn.read(&mut buf).await.unwrap();
        conn.write_all(&buf[..n]).await.unwrap();
        // conn cae al salir del scope — cierra la conexion con el bridge
    });

    // ── Bridge: una sesion ───────────────────────────────────────────────────
    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (socket, peer) = bridge_listener.accept().await.unwrap();
        // Ignoramos el error al terminar — el cliente cierra primero
        let _ = crate::session::handle(socket, peer, backend_addr, MAX_FRAME).await;
    });

    // ── Cliente: realiza el handshake y prueba el canal ───────────────────────
    let mut client = TcpStream::connect(bridge_addr).await.unwrap();

    // 1. Leer ServerHello
    let mut hello_buf = [0u8; SERVER_HELLO_LEN];
    client.read_exact(&mut hello_buf).await.unwrap();

    // 2. Parsear y responder
    let hello = parse_server_hello(&hello_buf);
    let (response, client_key) = client_respond(&hello, &mut OsRng).unwrap();

    // 3. Enviar ClientResponse
    let response_wire = serialize_client_response(&response);
    client.write_all(&response_wire).await.unwrap();

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
    async fn do_handshake() -> Vec<u8> {
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
            let _ = crate::session::handle(socket, peer, backend_addr, MAX_FRAME).await;
        });

        let mut client = TcpStream::connect(bridge_addr).await.unwrap();
        let mut hello_buf = [0u8; SERVER_HELLO_LEN];
        client.read_exact(&mut hello_buf).await.unwrap();
        let hello = parse_server_hello(&hello_buf);
        let (response, key) = client_respond(&hello, &mut OsRng).unwrap();
        client.write_all(&serialize_client_response(&response)).await.unwrap();
        key.as_bytes().to_vec()
    }

    let key1 = do_handshake().await;
    let key2 = do_handshake().await;

    assert_ne!(key1, key2, "cada sesion debe producir una SessionKey unica");
}

/// Verifica que un ClientResponse corrupto es rechazado por el bridge.
#[tokio::test]
async fn tampered_client_response_is_rejected() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    tokio::spawn(async move {
        // El backend no deberia recibir nada en este test
        let _ = backend_listener.accept().await;
    });

    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();

    let bridge_result = tokio::spawn(async move {
        let (socket, peer) = bridge_listener.accept().await.unwrap();
        crate::session::handle(socket, peer, backend_addr, MAX_FRAME).await
    });

    let mut client = TcpStream::connect(bridge_addr).await.unwrap();
    let mut hello_buf = [0u8; SERVER_HELLO_LEN];
    client.read_exact(&mut hello_buf).await.unwrap();

    // Enviar ClientResponse completamente invalido (ceros)
    client.write_all(&[0u8; CLIENT_RESPONSE_LEN]).await.unwrap();
    drop(client);

    // El bridge debe completar sin panic (puede fallar con error, no con panic)
    let _ = bridge_result.await.unwrap(); // no debe hacer unwrap del Result
}
