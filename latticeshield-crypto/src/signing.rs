//! Firmas post-cuanticas ML-DSA-65 (FIPS 204).
//!
//! Expone una API opaca sobre `libcrux-ml-dsa 0.0.7` usando el backend portable
//! (sin AVX2 — las pruebas del backend AVX2 tienen problemas de soundness per
//! IACR eprint 2026/192 en libcrux 0.0.7).
//!
//! Tamanos wire (ML-DSA-65, FIPS 204 §Table 2):
//!   - Clave de firma:      4032 bytes
//!   - Clave de verificacion: 1952 bytes
//!   - Firma:               3309 bytes

use libcrux_ml_dsa::ml_dsa_65;
use rand_core::CryptoRngCore;
use thiserror::Error;
use zeroize::Zeroize;

/// Tamanio de la clave de firma serializada.
pub const SIGNING_KEY_LEN: usize = 4032;
/// Tamanio de la clave de verificacion serializada.
pub const VERIFYING_KEY_LEN: usize = 1952;
/// Tamanio de una firma serializada.
pub const SIGNATURE_LEN: usize = 3309;

/// Contexto vacio — no requerido por el protocolo OTA de LatticeShield.
const EMPTY_CONTEXT: &[u8] = b"";

// ── Errores ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("ML-DSA-65 signing operation failed")]
    Signing,
    #[error("ML-DSA-65 signature verification failed")]
    Verification,
    #[error("invalid key or signature byte length")]
    InvalidLength,
}

// ── Newtypes opacos ───────────────────────────────────────────────────────────

/// Clave de firma ML-DSA-65. Material secreto — se zeroiza y se hace munlock al salir del scope.
///
/// El material de clave se almacena en el heap (`Box`) para que la direccion sea estable
/// ante moves. Esto permite que `mlock(2)` funcione correctamente: el SO no paginara
/// estos bytes al swap durante toda la vida del objeto.
///
/// En plataformas no-Unix el tipo funciona igual pero sin mlock.
#[derive(Zeroize)]
pub struct SigningKey(Box<[u8; SIGNING_KEY_LEN]>);

impl SigningKey {
    /// Construye una `SigningKey` desde un slice de bytes y bloquea la pagina en memoria.
    ///
    /// Retorna `SigningError::InvalidLength` si `bytes` no tiene exactamente
    /// `SIGNING_KEY_LEN` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SigningError> {
        let arr: [u8; SIGNING_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| SigningError::InvalidLength)?;
        Ok(Self::new(arr))
    }

    /// Retorna los bytes de la clave de firma.
    pub fn to_bytes(&self) -> &[u8; SIGNING_KEY_LEN] {
        &self.0
    }

    /// Constructor interno: boxea los bytes y llama mlock sobre el heap.
    fn new(bytes: [u8; SIGNING_KEY_LEN]) -> Self {
        let boxed = Box::new(bytes);
        #[cfg(unix)]
        unsafe {
            // Non-fatal: si mlock falla (p.ej. RLIMIT_MEMLOCK bajo) la clave sigue
            // funcionando — solo pierde la garantia anti-swap.
            libc::mlock(boxed.as_ptr() as *const libc::c_void, SIGNING_KEY_LEN);
        }
        Self(boxed)
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        // Zeroizar primero: limpia los bytes mientras la pagina sigue bloqueada.
        self.0.zeroize();
        // Desbloquear despues: la pagina puede volver a ser candidata a swap,
        // pero ya no contiene material sensible.
        #[cfg(unix)]
        unsafe {
            libc::munlock(self.0.as_ptr() as *const libc::c_void, SIGNING_KEY_LEN);
        }
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
    ///
    /// Retorna `SigningError::InvalidLength` si `bytes` no tiene exactamente
    /// `VERIFYING_KEY_LEN` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SigningError> {
        let arr: [u8; VERIFYING_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| SigningError::InvalidLength)?;
        Ok(Self(arr))
    }

    /// Retorna los bytes de la clave de verificacion.
    pub fn to_bytes(&self) -> &[u8; VERIFYING_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Muestra los primeros 4 bytes como fingerprint — no expone material sensible.
        write!(
            f,
            "VerifyingKey({:02x}{:02x}{:02x}{:02x}...)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// Firma ML-DSA-65 serializada.
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Construye una `Signature` desde un slice de bytes.
    ///
    /// Retorna `SigningError::InvalidLength` si `bytes` no tiene exactamente
    /// `SIGNATURE_LEN` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SigningError> {
        let arr: [u8; SIGNATURE_LEN] = bytes
            .try_into()
            .map_err(|_| SigningError::InvalidLength)?;
        Ok(Self(arr))
    }

    /// Retorna los bytes de la firma.
    pub fn to_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Signature({:02x}{:02x}{:02x}{:02x}...)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

// ── Funciones publicas ────────────────────────────────────────────────────────

/// Genera un par de claves ML-DSA-65 usando la fuente de aleatoriedad dada.
///
/// La clave de firma se zeroiza automaticamente al salir del scope.
pub fn generate_keypair(
    rng: &mut impl CryptoRngCore,
) -> (SigningKey, VerifyingKey) {
    let mut seed = [0u8; libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE];
    rng.fill_bytes(&mut seed);

    let kp = ml_dsa_65::portable::generate_key_pair(seed);

    let sk_bytes: &[u8; SIGNING_KEY_LEN] = kp.signing_key.as_ref();
    let vk_bytes: &[u8; VERIFYING_KEY_LEN] = kp.verification_key.as_ref();

    (SigningKey::new(*sk_bytes), VerifyingKey(*vk_bytes))
}

/// Firma `msg` con la `SigningKey` dada.
///
/// Usa aleatoriedad hedged (randomizada): combina entropia del RNG con el
/// mensaje para resistir ataques de fault y side-channel.
pub fn sign(
    key: &SigningKey,
    msg: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<Signature, SigningError> {
    let mut randomness = [0u8; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE];
    rng.fill_bytes(&mut randomness);

    let sk = ml_dsa_65::MLDSA65SigningKey::new(*key.0);
    let sig = ml_dsa_65::portable::sign(&sk, msg, EMPTY_CONTEXT, randomness)
        .map_err(|_| SigningError::Signing)?;

    let sig_bytes: &[u8; SIGNATURE_LEN] = sig.as_ref();
    Ok(Signature(*sig_bytes))
}

/// Verifica que `sig` es una firma valida de `msg` bajo `key`.
///
/// Retorna `Ok(())` si la firma es valida, `Err(SigningError::Verification)` en caso contrario.
pub fn verify(key: &VerifyingKey, msg: &[u8], sig: &Signature) -> Result<(), SigningError> {
    let vk = ml_dsa_65::MLDSA65VerificationKey::new(key.0);
    let s = ml_dsa_65::MLDSA65Signature::new(sig.0);

    ml_dsa_65::portable::verify(&vk, msg, EMPTY_CONTEXT, &s)
        .map_err(|_| SigningError::Verification)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    // ── Task 4.1 — generate_keypair ───────────────────────────────────────────

    #[test]
    fn generate_keypair_produces_correct_key_sizes() {
        let (sk, vk) = generate_keypair(&mut OsRng);
        assert_eq!(sk.to_bytes().len(), SIGNING_KEY_LEN);
        assert_eq!(vk.to_bytes().len(), VERIFYING_KEY_LEN);
    }

    #[test]
    fn two_keypairs_are_distinct() {
        let (sk1, vk1) = generate_keypair(&mut OsRng);
        let (sk2, vk2) = generate_keypair(&mut OsRng);
        assert_ne!(sk1.to_bytes(), sk2.to_bytes());
        assert_ne!(vk1.to_bytes(), vk2.to_bytes());
    }

    // ── Task 4.2 — sign ──────────────────────────────────────────────────────

    #[test]
    fn sign_produces_correct_signature_size() {
        let (sk, _vk) = generate_keypair(&mut OsRng);
        let msg = b"latticeshield firmware v1.0";
        let sig = sign(&sk, msg, &mut OsRng).unwrap();
        assert_eq!(sig.to_bytes().len(), SIGNATURE_LEN);
    }

    #[test]
    fn sign_is_hedged_two_signatures_of_same_msg_differ() {
        let (sk, _vk) = generate_keypair(&mut OsRng);
        let msg = b"latticeshield firmware v1.0";
        let sig1 = sign(&sk, msg, &mut OsRng).unwrap();
        let sig2 = sign(&sk, msg, &mut OsRng).unwrap();
        // ML-DSA-65 hedged: cada llamada usa entropia distinta → firmas distintas.
        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    // ── Task 4.3 — verify ────────────────────────────────────────────────────

    #[test]
    fn valid_signature_verifies_correctly() {
        let (sk, vk) = generate_keypair(&mut OsRng);
        let msg = b"latticeshield firmware v1.0";
        let sig = sign(&sk, msg, &mut OsRng).unwrap();
        assert!(verify(&vk, msg, &sig).is_ok());
    }

    #[test]
    fn tampered_message_fails_verification() {
        let (sk, vk) = generate_keypair(&mut OsRng);
        let msg = b"latticeshield firmware v1.0";
        let sig = sign(&sk, msg, &mut OsRng).unwrap();
        let tampered = b"latticeshield firmware v2.0";
        assert!(verify(&vk, tampered, &sig).is_err());
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let (sk, vk) = generate_keypair(&mut OsRng);
        let msg = b"latticeshield firmware v1.0";
        let sig = sign(&sk, msg, &mut OsRng).unwrap();

        let mut corrupted_bytes = *sig.to_bytes();
        corrupted_bytes[0] ^= 0xFF;
        let corrupted_sig = Signature::from_bytes(&corrupted_bytes).unwrap();

        assert!(verify(&vk, msg, &corrupted_sig).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (sk, _vk) = generate_keypair(&mut OsRng);
        let (_sk2, vk2) = generate_keypair(&mut OsRng);
        let msg = b"latticeshield firmware v1.0";
        let sig = sign(&sk, msg, &mut OsRng).unwrap();
        assert!(verify(&vk2, msg, &sig).is_err());
    }

    // ── Task 4.4 — serialization round-trip ──────────────────────────────────

    #[test]
    fn sign_accepts_empty_message() {
        let (sk, vk) = generate_keypair(&mut OsRng);
        let sig = sign(&sk, &[], &mut OsRng).unwrap();
        assert!(verify(&vk, &[], &sig).is_ok());
    }

    #[test]
    fn signing_key_serialization_round_trip() {
        let (sk, vk) = generate_keypair(&mut OsRng);
        let bytes = sk.to_bytes().to_vec();
        let sk2 = SigningKey::from_bytes(&bytes).unwrap();
        // Equivalencia funcional: la clave reconstruida produce firmas validas.
        let msg = b"latticeshield firmware v1.0";
        let sig = sign(&sk2, msg, &mut OsRng).unwrap();
        assert!(verify(&vk, msg, &sig).is_ok());
    }

    #[test]
    fn verifying_key_serialization_round_trip() {
        let (sk, vk) = generate_keypair(&mut OsRng);
        let msg = b"latticeshield firmware v1.0";
        let sig = sign(&sk, msg, &mut OsRng).unwrap();
        let bytes = vk.to_bytes().to_vec();
        let vk2 = VerifyingKey::from_bytes(&bytes).unwrap();
        // Equivalencia funcional: la clave reconstruida verifica firmas del sk original.
        assert!(verify(&vk2, msg, &sig).is_ok());
    }

    #[test]
    fn signature_serialization_round_trip() {
        let (sk, vk) = generate_keypair(&mut OsRng);
        let msg = b"latticeshield firmware v1.0";
        let sig = sign(&sk, msg, &mut OsRng).unwrap();
        let bytes = sig.to_bytes().to_vec();
        let sig2 = Signature::from_bytes(&bytes).unwrap();
        // La firma round-tripeada debe verificar igual que la original.
        assert!(verify(&vk, msg, &sig2).is_ok());
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(SigningKey::from_bytes(&[0u8; 10]).is_err());
        assert!(VerifyingKey::from_bytes(&[0u8; 10]).is_err());
        assert!(Signature::from_bytes(&[0u8; 10]).is_err());
    }
}
