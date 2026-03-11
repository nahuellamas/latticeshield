//! Carga y fingerprint de la VerifyingKey del servidor (pre-shared).

use std::path::Path;

use anyhow::Context;
use sha2::{Digest, Sha256};

use latticeshield_crypto::{VerifyingKey, VERIFYING_KEY_LEN};

/// Carga la VerifyingKey del servidor desde un archivo binario.
///
/// Retorna error si el archivo no existe o tiene longitud incorrecta.
pub fn load_verifying_key(path: &Path) -> anyhow::Result<VerifyingKey> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("loading server VK from {}", path.display()))?;

    if bytes.len() != VERIFYING_KEY_LEN {
        anyhow::bail!(
            "invalid key length: expected {}, got {}",
            VERIFYING_KEY_LEN,
            bytes.len()
        );
    }

    let vk = VerifyingKey::from_bytes(&bytes[..VERIFYING_KEY_LEN])
        .map_err(|e| anyhow::anyhow!("failed to parse VerifyingKey: {e}"))?;

    Ok(vk)
}

/// Calcula el fingerprint SHA-256 de la VerifyingKey.
///
/// Retorna una cadena hexadecimal en minusculas de 64 caracteres.
pub fn fingerprint(vk: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(vk.to_bytes());
    let digest = hasher.finalize();
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use latticeshield_crypto::generate_keypair;
    use rand_core::OsRng;
    use tempfile::NamedTempFile;

    #[test]
    fn load_roundtrip_ok() {
        let mut rng = OsRng;
        let (_sk, vk) = generate_keypair(&mut rng);
        let vk_bytes = vk.to_bytes().to_vec();

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&vk_bytes).unwrap();

        let loaded = load_verifying_key(f.path()).unwrap();
        assert_eq!(loaded.to_bytes(), vk.to_bytes());
    }

    #[test]
    fn load_wrong_size_file_error() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&[0u8; 100]).unwrap();

        let err = load_verifying_key(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("invalid key length"),
            "error should reference 'invalid key length', got: {err}"
        );
    }

    #[test]
    fn load_nonexistent_file_error() {
        let path = Path::new("/nonexistent/server.vk");
        let err = load_verifying_key(path).unwrap_err().to_string();
        assert!(
            err.contains("/nonexistent/server.vk"),
            "error should contain path, got: {err}"
        );
    }

    #[test]
    fn fingerprint_is_64_hex_chars() {
        let mut rng = OsRng;
        let (_sk, vk) = generate_keypair(&mut rng);
        let fp = fingerprint(&vk);
        assert_eq!(fp.len(), 64, "fingerprint must be 64 hex chars, got len {}", fp.len());
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let mut rng = OsRng;
        let (_sk, vk) = generate_keypair(&mut rng);
        let fp1 = fingerprint(&vk);
        let fp2 = fingerprint(&vk);
        assert_eq!(fp1, fp2, "fingerprint must be deterministic");
    }
}
