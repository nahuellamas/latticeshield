//! Firmas post-cuanticas ML-DSA-65 (FIPS 204) — variante WASM.
//!
//! Identico a `latticeshield-crypto/src/signing.rs` EXCEPTO:
//! - `SigningKey::new()` NO llama `libc::mlock` (browser no tiene swap; `Zeroize` es suficiente)
//! - `Drop` NO llama `libc::munlock`
//! - No depende de `libc` — compatible con `wasm32-unknown-unknown`
//!
//! Los constantes, wire format y tipos son identicos a `latticeshield-crypto` para
//! garantizar wire-compatibility con el bridge existente.

use libcrux_ml_dsa::ml_dsa_65;
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::error::WasmError;

/// Tamanio de la clave de firma serializada (ML-DSA-65).
pub const SIGNING_KEY_LEN: usize = 4032;
/// Tamanio de la clave de verificacion serializada (ML-DSA-65).
pub const VERIFYING_KEY_LEN: usize = 1952;
/// Tamanio de una firma serializada (ML-DSA-65).
pub const SIGNATURE_LEN: usize = 3309;

/// Separador de dominio ML-DSA-65 per FIPS 204 §5.2.
///
/// Identico al valor de `latticeshield-crypto` — garantiza wire-compatibility
/// y aísla el dominio criptografico de otras implementaciones que usen `b""`.
const SIGNING_CONTEXT: &[u8] = b"latticeshield-v1";

// ── Newtypes ──────────────────────────────────────────────────────────────────

/// Clave de firma ML-DSA-65 — variante WASM (sin mlock).
///
/// Se zeroiza automaticamente al salir del scope via `Zeroize` + `Drop`.
/// No llama `libc::mlock` porque el browser no tiene swap y `libc` no es
/// disponible en `wasm32-unknown-unknown`.
#[derive(Zeroize)]
pub struct SigningKey(Box<[u8; SIGNING_KEY_LEN]>);

impl SigningKey {
    /// Construye una `SigningKey` desde un slice de bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WasmError> {
        let arr: [u8; SIGNING_KEY_LEN] =
            bytes.try_into().map_err(|_| WasmError::InvalidKeyLength {
                expected: SIGNING_KEY_LEN,
                got: bytes.len(),
            })?;
        Ok(Self(Box::new(arr)))
    }

    /// Retorna los bytes de la clave.
    pub fn to_bytes(&self) -> &[u8; SIGNING_KEY_LEN] {
        &self.0
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        // Zeroizar sin munlock — browser no tiene swap.
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey([REDACTED])")
    }
}

/// Clave de verificacion ML-DSA-65. Publica — no requiere zeroize.
pub struct VerifyingKey([u8; VERIFYING_KEY_LEN]);

impl VerifyingKey {
    /// Construye una `VerifyingKey` desde un slice de bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WasmError> {
        let arr: [u8; VERIFYING_KEY_LEN] =
            bytes.try_into().map_err(|_| WasmError::InvalidKeyLength {
                expected: VERIFYING_KEY_LEN,
                got: bytes.len(),
            })?;
        Ok(Self(arr))
    }

    /// Retorna los bytes de la clave.
    pub fn to_bytes(&self) -> &[u8; VERIFYING_KEY_LEN] {
        &self.0
    }
}

/// Firma ML-DSA-65 serializada.
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Construye una `Signature` desde un slice de bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WasmError> {
        let arr: [u8; SIGNATURE_LEN] =
            bytes
                .try_into()
                .map_err(|_| WasmError::InvalidSignatureLength {
                    expected: SIGNATURE_LEN,
                    got: bytes.len(),
                })?;
        Ok(Self(arr))
    }

    /// Retorna los bytes de la firma.
    pub fn to_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

// ── Funciones publicas ────────────────────────────────────────────────────────

/// Genera un par de claves ML-DSA-65 usando `OsRng` (getrandom/js en WASM).
pub fn generate_keypair(rng: &mut impl rand_core::CryptoRngCore) -> (SigningKey, VerifyingKey) {
    let mut seed = Zeroizing::new([0u8; libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE]);
    rng.fill_bytes(seed.as_mut());

    let kp = ml_dsa_65::portable::generate_key_pair(*seed);

    let sk_bytes: &[u8; SIGNING_KEY_LEN] = kp.signing_key.as_ref();
    let vk_bytes: &[u8; VERIFYING_KEY_LEN] = kp.verification_key.as_ref();

    (SigningKey(Box::new(*sk_bytes)), VerifyingKey(*vk_bytes))
}

/// Firma `msg` con los bytes de la clave de firma. Usa `OsRng` interno.
///
/// Retorna los bytes de la firma (3309 bytes) o `WasmError`.
pub fn sign_msg(sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, WasmError> {
    let sk = SigningKey::from_bytes(sk_bytes)?;
    let mut rng = OsRng;
    let mut randomness = [0u8; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE];
    rng.fill_bytes(&mut randomness);

    let sk_inner = ml_dsa_65::MLDSA65SigningKey::new(*sk.0);
    let sig = ml_dsa_65::portable::sign(&sk_inner, msg, SIGNING_CONTEXT, randomness)
        .map_err(|_| WasmError::SignError)?;

    let sig_bytes: &[u8; SIGNATURE_LEN] = sig.as_ref();
    Ok(sig_bytes.to_vec())
}

/// Verifica `sig_bytes` sobre `msg` usando la clave de verificacion dada.
///
/// Retorna `Ok(())` si valida, `Err(WasmError::VerifyError)` si no.
pub fn verify_msg(vk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), WasmError> {
    let vk = VerifyingKey::from_bytes(vk_bytes)?;
    let sig = Signature::from_bytes(sig_bytes)?;

    let vk_inner = ml_dsa_65::MLDSA65VerificationKey::new(vk.0);
    let sig_inner = ml_dsa_65::MLDSA65Signature::new(sig.0);

    ml_dsa_65::portable::verify(&vk_inner, msg, SIGNING_CONTEXT, &sig_inner)
        .map_err(|_| WasmError::VerifyError)
}

// ── Tests (native — cargo test) ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── domain-separation regression ─────────────────────────────────────────

    #[test]
    fn signing_context_mismatch_is_rejected() {
        // A signature produced with b"latticeshield-v1" MUST NOT verify with b""
        // and vice-versa.  This mirrors the test in latticeshield-crypto and
        // guards the WASM path against silent context drift.
        let mut rng = rand_core::OsRng;
        let (sk, vk) = generate_keypair(&mut rng);
        let msg = b"test message for context mismatch";

        // Sign via the public API (uses SIGNING_CONTEXT = b"latticeshield-v1")
        let sig_bytes = sign_msg(sk.to_bytes(), msg).expect("sign must succeed");

        // Verify with b"" via libcrux directly — must fail
        let raw_vk = ml_dsa_65::MLDSA65VerificationKey::new(*vk.to_bytes());
        let raw_sig = ml_dsa_65::MLDSA65Signature::new(
            sig_bytes
                .as_slice()
                .try_into()
                .expect("sig bytes must be SIGNATURE_LEN"),
        );
        let result = ml_dsa_65::portable::verify(&raw_vk, msg, b"", &raw_sig);
        assert!(
            result.is_err(),
            "old-context verify (b\"\") must fail against new-context signature (b\"latticeshield-v1\")"
        );
    }
}
