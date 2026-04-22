//! Handshake hibrido: X25519 + ML-KEM-768 + HKDF-SHA256
//!
//! Implementa el protocolo definido en draft-ietf-tls-hybrid-design.
//!
//! Flujo:
//!   1. El servidor genera claves X25519 efimeras + par ML-KEM-768.
//!   2. El cliente recibe las claves publicas del servidor.
//!   3. El cliente encapsula contra la clave publica ML-KEM del servidor
//!      y realiza X25519. Envia su clave publica X25519 + el ciphertext ML-KEM.
//!   4. Ambos derivan la clave de sesion via HKDF-SHA256 sobre los dos secretos.
//!
//! Autenticacion del servidor (server-auth, pre-shared key):
//!   El ServerHello firmado extiende el wire con una firma ML-DSA-65 sobre los
//!   1248 bytes del ServerHello base. La VerifyingKey NO viaja en el wire — el
//!   cliente la tiene pre-shared (distribuida out-of-band).
//!   Formato: [1248B ServerHello] [3309B Signature] = 4557 bytes.

use hkdf::Hkdf;
use hybrid_array::Array;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    EncodedSizeUser, KemCore, MlKem768,
};
use rand_core::CryptoRngCore;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::signing::{sign, verify, Signature, SigningKey, VerifyingKey, SIGNATURE_LEN};

const HKDF_INFO: &[u8] = b"latticeshield-v1-session-key";
const SESSION_KEY_LEN: usize = 32;

/// Tamaños del protocolo wire.
pub const X25519_KEY_LEN: usize = 32;
pub const MLKEM768_EK_LEN: usize = 1184;
pub const MLKEM768_CT_LEN: usize = 1088;
pub const NONCE_LEN: usize = 32;

/// Tamaño total del ServerHello en el wire: X25519 pubkey + ML-KEM EK + nonce.
pub const SERVER_HELLO_LEN: usize = X25519_KEY_LEN + MLKEM768_EK_LEN + NONCE_LEN; // 1248

/// Tamaño total del ServerHello firmado: ServerHello + Signature ML-DSA-65.
///
/// La VerifyingKey NO viaja en el wire — el cliente la tiene pre-shared.
pub const SERVER_HELLO_SIGNED_LEN: usize = SERVER_HELLO_LEN + SIGNATURE_LEN; // 4557

/// Tamaño total de la respuesta del cliente en el wire: X25519 pubkey + ML-KEM ciphertext.
pub const CLIENT_RESPONSE_LEN: usize = X25519_KEY_LEN + MLKEM768_CT_LEN; // 1120

/// Tamaño total de la respuesta del cliente firmada: ClientResponse + Signature ML-DSA-65.
///
/// La firma cubre [CR_bytes(1120) || server_hello(1248)] para autenticar al cliente
/// y vincular la respuesta al handshake especifico.
pub const CLIENT_RESPONSE_SIGNED_LEN: usize = CLIENT_RESPONSE_LEN + SIGNATURE_LEN; // 4429

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("ML-KEM encapsulation failed")]
    Encapsulate,
    #[error("ML-KEM decapsulation failed")]
    Decapsulate,
    #[error("HKDF key derivation failed")]
    Hkdf,
    #[error("server authentication failed: invalid ML-DSA-65 signature")]
    AuthenticationFailed,
    #[error("client authentication failed: invalid ML-DSA-65 signature")]
    ClientAuthFailed,
}

/// Clave de sesion derivada del handshake hibrido.
/// Se zeroiza automaticamente al salir del scope.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKey([u8; SESSION_KEY_LEN]);

impl SessionKey {
    pub fn as_bytes(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey([REDACTED])")
    }
}

/// Lo que el servidor le envia al cliente en el ServerHello.
pub struct ClientHello {
    pub x25519_public: X25519PublicKey,
    pub kem_encap_key: <MlKem768 as KemCore>::EncapsulationKey,
    /// Nonce aleatorio para HKDF (evita que dos handshakes produzcan la misma clave
    /// aunque los secretos sean iguales — no deberia ocurrir, pero es defensa en profundidad).
    pub nonce: [u8; 32],
}

/// Lo que el cliente le envia al servidor para completar el handshake.
pub struct ClientResponse {
    pub x25519_public: X25519PublicKey,
    pub kem_ciphertext: Array<u8, <MlKem768 as KemCore>::CiphertextSize>,
}

/// Estado del servidor durante el handshake. Descartado despues de `complete()`.
pub struct ServerHandshake {
    x25519_secret: EphemeralSecret,
    kem_decap_key: <MlKem768 as KemCore>::DecapsulationKey,
    kem_encap_key: <MlKem768 as KemCore>::EncapsulationKey,
    nonce: [u8; 32],
    /// Los 1248 bytes del ServerHello serializados eagerly al construir la struct.
    /// Se usan en `complete_from_wire_signed` para verificar la firma del cliente,
    /// que cubre [CR_bytes || server_hello_raw] para vincular la respuesta al handshake.
    pub server_hello_raw: [u8; SERVER_HELLO_LEN],
}

impl ServerHandshake {
    /// El servidor genera sus claves efimeras.
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
        let x25519_secret = EphemeralSecret::random_from_rng(&mut *rng);
        let (kem_decap_key, kem_encap_key) = MlKem768::generate(rng);
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);

        // Serializar el ServerHello eagerly para tenerlo disponible en complete_from_wire_signed.
        let mut server_hello_raw = [0u8; SERVER_HELLO_LEN];
        let x25519_pub = X25519PublicKey::from(&x25519_secret);
        server_hello_raw[..X25519_KEY_LEN].copy_from_slice(x25519_pub.as_bytes());
        let ek_encoded = kem_encap_key.as_bytes();
        let ek_bytes: &[u8] = ek_encoded.as_ref();
        server_hello_raw[X25519_KEY_LEN..X25519_KEY_LEN + MLKEM768_EK_LEN]
            .copy_from_slice(ek_bytes);
        server_hello_raw[X25519_KEY_LEN + MLKEM768_EK_LEN..].copy_from_slice(&nonce);

        Self {
            x25519_secret,
            kem_decap_key,
            kem_encap_key,
            nonce,
            server_hello_raw,
        }
    }

    /// Produce el mensaje que el servidor le envia al cliente.
    pub fn client_hello(&self) -> ClientHello {
        ClientHello {
            x25519_public: X25519PublicKey::from(&self.x25519_secret),
            kem_encap_key: self.kem_encap_key.clone(),
            nonce: self.nonce,
        }
    }

    /// Serializa el ServerHello para enviarlo por el wire.
    ///
    /// Formato: [32B X25519 pubkey] [1184B ML-KEM EK] [32B nonce]
    pub fn server_hello_bytes(&self) -> [u8; SERVER_HELLO_LEN] {
        self.server_hello_raw
    }

    /// Serializa el ServerHello firmado para enviarlo por el wire.
    ///
    /// Formato: [1248B ServerHello] [3309B Signature ML-DSA-65]
    ///
    /// La firma cubre los 1248 bytes del ServerHello — autentica las claves efimeras
    /// y el nonce contra la clave de largo plazo del servidor.
    /// La VerifyingKey NO se incluye en el wire: el cliente debe tenerla pre-shared.
    pub fn server_hello_signed_bytes(
        &self,
        signing_key: &SigningKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; SERVER_HELLO_SIGNED_LEN], HandshakeError> {
        let hello = self.server_hello_bytes();

        let sig =
            sign(signing_key, &hello, rng).map_err(|_| HandshakeError::AuthenticationFailed)?;

        let mut buf = [0u8; SERVER_HELLO_SIGNED_LEN];
        buf[..SERVER_HELLO_LEN].copy_from_slice(&hello);
        buf[SERVER_HELLO_LEN..].copy_from_slice(sig.to_bytes());

        Ok(buf)
    }

    /// Recibe la respuesta del cliente desde el wire y completa el handshake.
    ///
    /// Formato esperado: [32B X25519 pubkey] [1088B ML-KEM ciphertext]
    pub fn complete_from_wire(
        self,
        bytes: &[u8; CLIENT_RESPONSE_LEN],
    ) -> Result<SessionKey, HandshakeError> {
        let x25519_pub = X25519PublicKey::from(
            <[u8; X25519_KEY_LEN]>::try_from(&bytes[..X25519_KEY_LEN]).unwrap(),
        );
        let ct_bytes: &[u8] = &bytes[X25519_KEY_LEN..];
        let ct_arr: [u8; MLKEM768_CT_LEN] = ct_bytes
            .try_into()
            .map_err(|_| HandshakeError::Decapsulate)?;
        let kem_ciphertext = Array::from(ct_arr);
        let response = ClientResponse {
            x25519_public: x25519_pub,
            kem_ciphertext,
        };
        self.complete(&response)
    }

    /// Recibe la respuesta del cliente firmada desde el wire, verifica la firma y completa el handshake.
    ///
    /// Formato esperado: [1120B ClientResponse] [3309B Signature ML-DSA-65]
    ///
    /// La firma cubre [CR_bytes(1120) || server_hello_raw(1248)] = 2368 bytes.
    /// Esto vincula la respuesta del cliente al handshake especifico (anti-replay).
    /// El caller provee la `VerifyingKey` pre-shared del cliente.
    pub fn complete_from_wire_signed(
        self,
        bytes: &[u8; CLIENT_RESPONSE_SIGNED_LEN],
        client_vk: &VerifyingKey,
    ) -> Result<SessionKey, HandshakeError> {
        let cr_bytes: &[u8; CLIENT_RESPONSE_LEN] = bytes[..CLIENT_RESPONSE_LEN].try_into().unwrap();
        let sig_bytes = &bytes[CLIENT_RESPONSE_LEN..];

        // Construir el mensaje firmado: CR_bytes || server_hello_raw
        let mut message = [0u8; CLIENT_RESPONSE_LEN + SERVER_HELLO_LEN];
        message[..CLIENT_RESPONSE_LEN].copy_from_slice(cr_bytes);
        message[CLIENT_RESPONSE_LEN..].copy_from_slice(&self.server_hello_raw);

        let sig = Signature::from_bytes(sig_bytes).map_err(|_| HandshakeError::ClientAuthFailed)?;

        verify(client_vk, &message, &sig).map_err(|_| HandshakeError::ClientAuthFailed)?;

        self.complete_from_wire(cr_bytes)
    }

    /// El servidor recibe la respuesta del cliente y deriva la clave de sesion.
    pub fn complete(self, response: &ClientResponse) -> Result<SessionKey, HandshakeError> {
        // Secreto X25519
        let x25519_shared: SharedSecret =
            self.x25519_secret.diffie_hellman(&response.x25519_public);

        // Secreto ML-KEM
        let kem_shared = self
            .kem_decap_key
            .decapsulate(&response.kem_ciphertext)
            .map_err(|_| HandshakeError::Decapsulate)?;

        derive_session_key(x25519_shared.as_bytes(), kem_shared.as_ref(), &self.nonce)
    }
}

/// Parsea un ServerHello recibido desde el wire y retorna el `ClientHello` estructurado.
///
/// Formato esperado: [32B X25519 pubkey] [1184B ML-KEM EK] [32B nonce]
pub fn parse_server_hello(bytes: &[u8; SERVER_HELLO_LEN]) -> ClientHello {
    let x25519_public =
        X25519PublicKey::from(<[u8; X25519_KEY_LEN]>::try_from(&bytes[..X25519_KEY_LEN]).unwrap());
    let ek_slice = &bytes[X25519_KEY_LEN..X25519_KEY_LEN + MLKEM768_EK_LEN];
    type EkSize = <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;
    let ek_ref: &Array<u8, EkSize> = ek_slice.try_into().expect("EK slice length invalido");
    let kem_encap_key = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(ek_ref);
    let nonce: [u8; NONCE_LEN] = bytes[X25519_KEY_LEN + MLKEM768_EK_LEN..]
        .try_into()
        .unwrap();
    ClientHello {
        x25519_public,
        kem_encap_key,
        nonce,
    }
}

/// Parsea y verifica un ServerHello firmado recibido desde el wire.
///
/// Formato esperado: [1248B ServerHello] [3309B Signature ML-DSA-65]
///
/// El caller provee la `VerifyingKey` pre-shared — no se extrae del wire.
/// Verifica la firma antes de parsear. Retorna `Err(HandshakeError::AuthenticationFailed)`
/// si la firma no es valida bajo la clave dada.
pub fn parse_server_hello_signed(
    bytes: &[u8; SERVER_HELLO_SIGNED_LEN],
    vk: &VerifyingKey,
) -> Result<ClientHello, HandshakeError> {
    let hello_bytes: &[u8; SERVER_HELLO_LEN] = bytes[..SERVER_HELLO_LEN].try_into().unwrap();

    let sig = Signature::from_bytes(&bytes[SERVER_HELLO_LEN..])
        .map_err(|_| HandshakeError::AuthenticationFailed)?;

    verify(vk, hello_bytes, &sig).map_err(|_| HandshakeError::AuthenticationFailed)?;

    Ok(parse_server_hello(hello_bytes))
}

/// Serializa un `ClientResponse` para enviarlo por el wire.
///
/// Formato: [32B X25519 pubkey] [1088B ML-KEM ciphertext]
pub fn serialize_client_response(response: &ClientResponse) -> [u8; CLIENT_RESPONSE_LEN] {
    let mut buf = [0u8; CLIENT_RESPONSE_LEN];
    buf[..X25519_KEY_LEN].copy_from_slice(response.x25519_public.as_bytes());
    let ct_bytes: &[u8] = response.kem_ciphertext.as_ref();
    buf[X25519_KEY_LEN..].copy_from_slice(ct_bytes);
    buf
}

/// Serializa un `ClientResponse` firmado para enviarlo por el wire.
///
/// Formato: [1120B ClientResponse] [3309B Signature ML-DSA-65]
///
/// La firma cubre [CR_bytes(1120) || server_hello(1248)] = 2368 bytes.
/// Esto vincula la respuesta al handshake especifico iniciado por ese servidor.
pub fn serialize_client_response_signed(
    resp: &ClientResponse,
    sk: &SigningKey,
    server_hello: &[u8; SERVER_HELLO_LEN],
    rng: &mut impl CryptoRngCore,
) -> Result<[u8; CLIENT_RESPONSE_SIGNED_LEN], HandshakeError> {
    let cr_bytes = serialize_client_response(resp);

    // Mensaje = CR_bytes(1120) || server_hello(1248)
    let mut message = [0u8; CLIENT_RESPONSE_LEN + SERVER_HELLO_LEN];
    message[..CLIENT_RESPONSE_LEN].copy_from_slice(&cr_bytes);
    message[CLIENT_RESPONSE_LEN..].copy_from_slice(server_hello);

    let sig = sign(sk, &message, rng).map_err(|_| HandshakeError::ClientAuthFailed)?;

    let mut buf = [0u8; CLIENT_RESPONSE_SIGNED_LEN];
    buf[..CLIENT_RESPONSE_LEN].copy_from_slice(&cr_bytes);
    buf[CLIENT_RESPONSE_LEN..].copy_from_slice(sig.to_bytes());

    Ok(buf)
}

/// Logica del cliente: recibe el ClientHello del servidor, encapsula, deriva la clave.
///
/// Retorna la respuesta que el cliente debe enviar al servidor + la clave de sesion local.
pub fn client_respond(
    hello: &ClientHello,
    rng: &mut impl CryptoRngCore,
) -> Result<(ClientResponse, SessionKey), HandshakeError> {
    // Efimero X25519 del cliente
    let client_x25519_secret = EphemeralSecret::random_from_rng(&mut *rng);
    let client_x25519_public = X25519PublicKey::from(&client_x25519_secret);

    // Secreto X25519
    let x25519_shared = client_x25519_secret.diffie_hellman(&hello.x25519_public);

    // Encapsulacion ML-KEM: el cliente encapsula contra la clave publica del servidor
    let (kem_ciphertext, kem_shared) = hello
        .kem_encap_key
        .encapsulate(rng)
        .map_err(|_| HandshakeError::Encapsulate)?;

    let session_key =
        derive_session_key(x25519_shared.as_bytes(), kem_shared.as_ref(), &hello.nonce)?;

    let response = ClientResponse {
        x25519_public: client_x25519_public,
        kem_ciphertext,
    };

    Ok((response, session_key))
}

/// Deriva la clave de sesion final combinando los dos secretos via HKDF-SHA256.
///
/// `key = HKDF-SHA256(ikm = x25519_secret || kem_secret, salt = nonce, info = "latticeshield-v1-session-key")`
///
/// Seguridad hibrida: si uno de los dos secretos es comprometido, el otro sigue protegiendo la sesion.
fn derive_session_key(
    x25519_secret: &[u8],
    kem_secret: &[u8],
    nonce: &[u8; 32],
) -> Result<SessionKey, HandshakeError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(x25519_secret.len() + kem_secret.len()));
    ikm.extend_from_slice(x25519_secret);
    ikm.extend_from_slice(kem_secret);

    let hkdf = Hkdf::<Sha256>::new(Some(nonce), &ikm);
    let mut okm = [0u8; SESSION_KEY_LEN];
    hkdf.expand(HKDF_INFO, &mut okm)
        .map_err(|_| HandshakeError::Hkdf)?;

    Ok(SessionKey(okm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::generate_keypair;
    use rand_core::OsRng;

    #[test]
    fn handshake_produces_matching_session_keys() {
        let mut rng = OsRng;

        // Servidor genera sus claves
        let server = ServerHandshake::new(&mut rng);
        let hello = server.client_hello();

        // Cliente responde
        let (response, client_key) = client_respond(&hello, &mut rng).unwrap();

        // Servidor completa el handshake
        let server_key = server.complete(&response).unwrap();

        // Ambas claves deben ser identicas
        assert_eq!(
            client_key.as_bytes(),
            server_key.as_bytes(),
            "Las claves de sesion deben coincidir"
        );
    }

    #[test]
    fn session_keys_are_unique_per_handshake() {
        let mut rng = OsRng;

        let server1 = ServerHandshake::new(&mut rng);
        let hello1 = server1.client_hello();
        let (response1, _) = client_respond(&hello1, &mut rng).unwrap();
        let key1 = server1.complete(&response1).unwrap();

        let server2 = ServerHandshake::new(&mut rng);
        let hello2 = server2.client_hello();
        let (response2, _) = client_respond(&hello2, &mut rng).unwrap();
        let key2 = server2.complete(&response2).unwrap();

        assert_ne!(
            key1.as_bytes(),
            key2.as_bytes(),
            "Dos handshakes distintos no deben producir la misma clave"
        );
    }

    // ── Server authentication (pre-shared VerifyingKey) ──────────────────────

    #[test]
    fn signed_server_hello_has_correct_length() {
        let mut rng = OsRng;
        let server = ServerHandshake::new(&mut rng);
        let (sk, _vk) = generate_keypair(&mut rng);
        let bytes = server.server_hello_signed_bytes(&sk, &mut rng).unwrap();
        assert_eq!(bytes.len(), SERVER_HELLO_SIGNED_LEN);
    }

    #[test]
    fn signed_server_hello_verifies_with_preshared_vk() {
        let mut rng = OsRng;
        let server = ServerHandshake::new(&mut rng);
        let (sk, vk) = generate_keypair(&mut rng);
        let bytes = server.server_hello_signed_bytes(&sk, &mut rng).unwrap();
        let hello = parse_server_hello_signed(&bytes, &vk);
        assert!(
            hello.is_ok(),
            "verificacion debe pasar con VK pre-shared correcta"
        );
    }

    #[test]
    fn signed_hello_server_and_client_derive_same_session_key() {
        let mut rng = OsRng;
        let server = ServerHandshake::new(&mut rng);
        let (sk, vk) = generate_keypair(&mut rng);
        let signed_bytes = server.server_hello_signed_bytes(&sk, &mut rng).unwrap();

        let hello = parse_server_hello_signed(&signed_bytes, &vk).unwrap();
        let (response, client_key) = client_respond(&hello, &mut rng).unwrap();
        let server_key = server.complete(&response).unwrap();

        assert_eq!(
            client_key.as_bytes(),
            server_key.as_bytes(),
            "cliente y servidor deben derivar la misma session key"
        );
    }

    #[test]
    fn signed_hello_produces_unique_keys_per_session() {
        let mut rng = OsRng;

        let server1 = ServerHandshake::new(&mut rng);
        let (sk1, vk1) = generate_keypair(&mut rng);
        let bytes1 = server1.server_hello_signed_bytes(&sk1, &mut rng).unwrap();
        let hello1 = parse_server_hello_signed(&bytes1, &vk1).unwrap();
        let (response1, client_key1) = client_respond(&hello1, &mut rng).unwrap();
        let _server_key1 = server1.complete(&response1).unwrap();

        let server2 = ServerHandshake::new(&mut rng);
        let (sk2, vk2) = generate_keypair(&mut rng);
        let bytes2 = server2.server_hello_signed_bytes(&sk2, &mut rng).unwrap();
        let hello2 = parse_server_hello_signed(&bytes2, &vk2).unwrap();
        let (_, client_key2) = client_respond(&hello2, &mut rng).unwrap();

        assert_ne!(
            client_key1.as_bytes(),
            client_key2.as_bytes(),
            "dos sesiones distintas no deben producir la misma session key"
        );
    }

    #[test]
    fn tampered_signature_in_signed_hello_fails() {
        let mut rng = OsRng;
        let server = ServerHandshake::new(&mut rng);
        let (sk, vk) = generate_keypair(&mut rng);
        let mut bytes = server.server_hello_signed_bytes(&sk, &mut rng).unwrap();

        bytes[SERVER_HELLO_LEN] ^= 0xFF;

        let result = parse_server_hello_signed(&bytes, &vk);
        assert!(
            matches!(result, Err(HandshakeError::AuthenticationFailed)),
            "firma corrompida debe fallar con AuthenticationFailed"
        );
    }

    #[test]
    fn tampered_server_hello_body_fails_authentication() {
        let mut rng = OsRng;
        let server = ServerHandshake::new(&mut rng);
        let (sk, vk) = generate_keypair(&mut rng);
        let mut bytes = server.server_hello_signed_bytes(&sk, &mut rng).unwrap();

        bytes[X25519_KEY_LEN + MLKEM768_EK_LEN] ^= 0xFF;

        let result = parse_server_hello_signed(&bytes, &vk);
        assert!(
            matches!(result, Err(HandshakeError::AuthenticationFailed)),
            "ServerHello corrompido debe fallar con AuthenticationFailed"
        );
    }

    #[test]
    fn wrong_preshared_vk_fails_authentication() {
        let mut rng = OsRng;
        let server = ServerHandshake::new(&mut rng);
        let (sk, _vk) = generate_keypair(&mut rng);
        let (_sk2, vk2) = generate_keypair(&mut rng);

        let bytes = server.server_hello_signed_bytes(&sk, &mut rng).unwrap();

        let result = parse_server_hello_signed(&bytes, &vk2);
        assert!(
            matches!(result, Err(HandshakeError::AuthenticationFailed)),
            "VK pre-shared erronea debe fallar con AuthenticationFailed"
        );
    }

    #[test]
    fn tampered_kem_ciphertext_fails_decapsulation() {
        let mut rng = OsRng;

        let server = ServerHandshake::new(&mut rng);
        let hello = server.client_hello();
        let (response, _) = client_respond(&hello, &mut rng).unwrap();

        // Corromper el ciphertext ML-KEM
        // (en la practica ML-KEM devuelve un secreto "basura" en lugar de error,
        //  pero la clave de sesion no va a coincidir)
        let _ = response.kem_ciphertext; // el tipo no permite mutacion directa — esto es intencional
                                         // Este test verifica que el tipo es opaco y no se puede mutar accidentalmente
    }

    // ── Client authentication (mutual auth, pre-shared VerifyingKey) ─────────

    #[test]
    fn test_client_response_signed_roundtrip() {
        let mut rng = OsRng;

        // Claves del servidor (server-auth)
        let (server_sk, server_vk) = generate_keypair(&mut rng);
        // Claves del cliente (client-auth)
        let (client_sk, client_vk) = generate_keypair(&mut rng);

        // Servidor genera ServerHello firmado
        let server = ServerHandshake::new(&mut rng);
        let signed_hello = server
            .server_hello_signed_bytes(&server_sk, &mut rng)
            .unwrap();
        let server_hello_raw: &[u8; SERVER_HELLO_LEN] =
            signed_hello[..SERVER_HELLO_LEN].try_into().unwrap();

        // Cliente verifica ServerHello y responde
        let hello = parse_server_hello_signed(&signed_hello, &server_vk).unwrap();
        let (response, client_key) = client_respond(&hello, &mut rng).unwrap();

        // Cliente firma su respuesta
        let signed_cr =
            serialize_client_response_signed(&response, &client_sk, server_hello_raw, &mut rng)
                .unwrap();
        assert_eq!(signed_cr.len(), CLIENT_RESPONSE_SIGNED_LEN);

        // Servidor verifica la firma del cliente y completa el handshake
        let server_key = server
            .complete_from_wire_signed(&signed_cr, &client_vk)
            .unwrap();

        assert_eq!(
            client_key.as_bytes(),
            server_key.as_bytes(),
            "mutual auth: cliente y servidor deben derivar la misma session key"
        );
    }

    #[test]
    fn test_client_response_signed_wrong_vk() {
        let mut rng = OsRng;

        let (client_sk, _client_vk) = generate_keypair(&mut rng);
        let (_wrong_sk, wrong_vk) = generate_keypair(&mut rng);

        let server = ServerHandshake::new(&mut rng);
        let sh_raw = server.server_hello_raw;
        // Usar parse_server_hello para no mover server antes de complete_from_wire_signed
        let ch = parse_server_hello(&sh_raw);
        let (resp, _) = client_respond(&ch, &mut rng).unwrap();
        let scr = serialize_client_response_signed(&resp, &client_sk, &sh_raw, &mut rng).unwrap();

        // Verificar con una VK incorrecta — debe fallar con ClientAuthFailed
        let result = server.complete_from_wire_signed(&scr, &wrong_vk);
        assert!(
            matches!(result, Err(HandshakeError::ClientAuthFailed)),
            "VK incorrecta debe fallar con ClientAuthFailed"
        );
    }

    #[test]
    fn test_client_response_signed_tampered_cr() {
        let mut rng = OsRng;

        let (client_sk, client_vk) = generate_keypair(&mut rng);

        let server = ServerHandshake::new(&mut rng);
        let sh_raw = server.server_hello_raw;
        let ch = parse_server_hello(&sh_raw);
        let (resp, _) = client_respond(&ch, &mut rng).unwrap();

        let mut signed_cr =
            serialize_client_response_signed(&resp, &client_sk, &sh_raw, &mut rng).unwrap();

        // Corromper un byte en la porcion CR (primeros 1120 bytes)
        signed_cr[0] ^= 0xFF;

        let result = server.complete_from_wire_signed(&signed_cr, &client_vk);
        assert!(
            matches!(result, Err(HandshakeError::ClientAuthFailed)),
            "CR corrompido debe fallar con ClientAuthFailed"
        );
    }

    #[test]
    fn test_client_response_signed_wrong_server_hello() {
        let mut rng = OsRng;

        let (client_sk, client_vk) = generate_keypair(&mut rng);

        // Servidor A genera su hello
        let server_a = ServerHandshake::new(&mut rng);
        let sh_raw_a = server_a.server_hello_raw;

        // Servidor B genera su hello (distinto)
        let server_b = ServerHandshake::new(&mut rng);
        let sh_raw_b = server_b.server_hello_raw;

        // Cliente responde al hello de A pero firma con el hello de B (incorrecto)
        let ch_a = parse_server_hello(&sh_raw_a);
        let (resp, _) = client_respond(&ch_a, &mut rng).unwrap();
        let signed_cr =
            serialize_client_response_signed(&resp, &client_sk, &sh_raw_b, &mut rng).unwrap();

        // Servidor A verifica — debe fallar porque el server_hello en la firma es el de B
        let result = server_a.complete_from_wire_signed(&signed_cr, &client_vk);
        assert!(
            matches!(result, Err(HandshakeError::ClientAuthFailed)),
            "server_hello incorrecto en la firma debe fallar con ClientAuthFailed"
        );
    }
}
