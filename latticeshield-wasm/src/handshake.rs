//! Handshake hibrido — lado cliente (WASM).
//!
//! Implementa solo la logica del cliente: parsear el ServerHello firmado,
//! encapsular contra ML-KEM-768, realizar X25519, derivar la session key.
//!
//! NO incluye logica del servidor (ServerHandshake), EncryptedChannel ni tokio.
//! Wire-compatible con `latticeshield-crypto/src/handshake.rs`.

use hkdf::Hkdf;
use hybrid_array::Array;
use ml_kem::{kem::Encapsulate, EncodedSizeUser, KemCore, MlKem768};
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::{Zeroize, Zeroizing};

use crate::error::WasmError;
use crate::signing::{Signature, VerifyingKey, SIGNATURE_LEN, VERIFYING_KEY_LEN};
use libcrux_ml_dsa::ml_dsa_65;

// ── Constantes wire (identicas a latticeshield-crypto) ────────────────────────

pub const X25519_KEY_LEN: usize = 32;
pub const MLKEM768_EK_LEN: usize = 1184;
pub const MLKEM768_CT_LEN: usize = 1088;
pub const NONCE_LEN: usize = 32;
pub const SERVER_HELLO_LEN: usize = X25519_KEY_LEN + MLKEM768_EK_LEN + NONCE_LEN; // 1248
pub const SERVER_HELLO_SIGNED_LEN: usize = SERVER_HELLO_LEN + SIGNATURE_LEN; // 4557
pub const CLIENT_RESPONSE_LEN: usize = X25519_KEY_LEN + MLKEM768_CT_LEN; // 1120
pub const SESSION_KEY_LEN: usize = 32;

const HKDF_INFO: &[u8] = b"latticeshield-v1-session-key";
const EMPTY_CONTEXT: &[u8] = b"";

// ── Structs internos ──────────────────────────────────────────────────────────

struct ClientHello {
    x25519_public: X25519PublicKey,
    kem_encap_key: <MlKem768 as KemCore>::EncapsulationKey,
    nonce: [u8; NONCE_LEN],
}

// ── API publica (usada desde lib.rs) ──────────────────────────────────────────

/// Dado un `server_hello_signed` (4557B) y la `VerifyingKey` pre-shared del servidor (1952B),
/// parsea y verifica el ServerHello, ejecuta el lado cliente del handshake hibrido y retorna:
/// - `client_response` (1120B): lo que el cliente envia al servidor
/// - `session_key` (32B): clave de sesion derivada
pub fn generate_client_response(
    server_hello_signed: &[u8],
    server_vk_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), WasmError> {
    // Validar longitudes de entrada
    if server_hello_signed.len() != SERVER_HELLO_SIGNED_LEN {
        return Err(WasmError::HandshakeError(format!(
            "server_hello_signed must be {} bytes, got {}",
            SERVER_HELLO_SIGNED_LEN,
            server_hello_signed.len()
        )));
    }
    if server_vk_bytes.len() != VERIFYING_KEY_LEN {
        return Err(WasmError::InvalidKeyLength {
            expected: VERIFYING_KEY_LEN,
            got: server_vk_bytes.len(),
        });
    }

    let signed_arr: &[u8; SERVER_HELLO_SIGNED_LEN] =
        server_hello_signed.try_into().map_err(|_| {
            WasmError::HandshakeError("server_hello_signed slice conversion failed".to_string())
        })?;

    // Verificar firma ML-DSA-65 antes de parsear
    let hello = parse_server_hello_signed(signed_arr, server_vk_bytes)?;

    // Ejecutar lado cliente del handshake
    let (cr_bytes, session_key_bytes) = client_respond(&hello)?;

    Ok((cr_bytes.to_vec(), session_key_bytes.to_vec()))
}

// ── Implementacion interna ────────────────────────────────────────────────────

fn parse_server_hello_signed(
    bytes: &[u8; SERVER_HELLO_SIGNED_LEN],
    vk_bytes: &[u8],
) -> Result<ClientHello, WasmError> {
    let hello_bytes: &[u8; SERVER_HELLO_LEN] = bytes[..SERVER_HELLO_LEN].try_into().unwrap();

    // Verificar firma ML-DSA-65
    let sig = Signature::from_bytes(&bytes[SERVER_HELLO_LEN..])?;
    let vk = VerifyingKey::from_bytes(vk_bytes)?;

    let vk_inner = ml_dsa_65::MLDSA65VerificationKey::new(*vk.to_bytes());
    let sig_inner = ml_dsa_65::MLDSA65Signature::new(*sig.to_bytes());

    ml_dsa_65::portable::verify(&vk_inner, hello_bytes, EMPTY_CONTEXT, &sig_inner)
        .map_err(|_| WasmError::HandshakeError("server authentication failed".to_string()))?;

    parse_server_hello(hello_bytes)
}

fn parse_server_hello(bytes: &[u8; SERVER_HELLO_LEN]) -> Result<ClientHello, WasmError> {
    let x25519_public = X25519PublicKey::from(
        <[u8; X25519_KEY_LEN]>::try_from(&bytes[..X25519_KEY_LEN])
            .map_err(|_| WasmError::HandshakeError("X25519 key parse failed".to_string()))?,
    );

    let ek_slice = &bytes[X25519_KEY_LEN..X25519_KEY_LEN + MLKEM768_EK_LEN];
    type EkSize = <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;
    let ek_ref: &Array<u8, EkSize> = ek_slice
        .try_into()
        .map_err(|_| WasmError::HandshakeError("ML-KEM EK parse failed".to_string()))?;
    let kem_encap_key = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(ek_ref);

    let nonce: [u8; NONCE_LEN] = bytes[X25519_KEY_LEN + MLKEM768_EK_LEN..]
        .try_into()
        .map_err(|_| WasmError::HandshakeError("nonce parse failed".to_string()))?;

    Ok(ClientHello {
        x25519_public,
        kem_encap_key,
        nonce,
    })
}

fn client_respond(
    hello: &ClientHello,
) -> Result<([u8; CLIENT_RESPONSE_LEN], [u8; SESSION_KEY_LEN]), WasmError> {
    let mut rng = OsRng;

    // Efimero X25519 del cliente
    let client_x25519_secret = EphemeralSecret::random_from_rng(rng);
    let client_x25519_public = X25519PublicKey::from(&client_x25519_secret);

    // Secreto X25519
    let x25519_shared = client_x25519_secret.diffie_hellman(&hello.x25519_public);

    // Encapsulacion ML-KEM: el cliente encapsula contra la EK del servidor
    let (kem_ciphertext, kem_shared) = hello
        .kem_encap_key
        .encapsulate(&mut rng)
        .map_err(|_| WasmError::HandshakeError("ML-KEM encapsulation failed".to_string()))?;

    // Derivar session key via HKDF-SHA256
    let session_key =
        derive_session_key(x25519_shared.as_bytes(), kem_shared.as_ref(), &hello.nonce)?;

    // Serializar ClientResponse: [32B X25519 pubkey][1088B ML-KEM ciphertext]
    let mut cr = [0u8; CLIENT_RESPONSE_LEN];
    cr[..X25519_KEY_LEN].copy_from_slice(client_x25519_public.as_bytes());
    let ct_bytes: &[u8] = kem_ciphertext.as_ref();
    cr[X25519_KEY_LEN..].copy_from_slice(ct_bytes);

    Ok((cr, session_key))
}

fn derive_session_key(
    x25519_secret: &[u8],
    kem_secret: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<[u8; SESSION_KEY_LEN], WasmError> {
    let mut ikm = Vec::with_capacity(x25519_secret.len() + kem_secret.len());
    ikm.extend_from_slice(x25519_secret);
    ikm.extend_from_slice(kem_secret);

    let hkdf = Hkdf::<Sha256>::new(Some(nonce), &ikm);
    let mut okm = Zeroizing::new([0u8; SESSION_KEY_LEN]);
    hkdf.expand(HKDF_INFO, okm.as_mut())
        .map_err(|_| WasmError::HandshakeError("HKDF expansion failed".to_string()))?;

    ikm.zeroize();

    let result = *okm; // copia los bytes; okm (Zeroizing) se dropea aqui y zeroza el original
    Ok(result)
}
