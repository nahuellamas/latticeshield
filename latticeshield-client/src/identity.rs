//! Carga y fingerprint de la VerifyingKey del servidor (pre-shared).
//! Tambien maneja el par de claves de largo plazo del cliente (ClientIdentity).

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use latticeshield_crypto::{
    generate_keypair, SigningKey, VerifyingKey, SIGNING_KEY_LEN, VERIFYING_KEY_LEN,
};

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

fn vk_path_from(sk_path: &Path) -> PathBuf {
    sk_path.with_extension("vk")
}

// ── ClientIdentity ─────────────────────────────────────────────────────────────

/// Par de claves de largo plazo del cliente para autenticacion mutua ML-DSA-65.
///
/// Se carga una vez al arrancar via `ClientIdentity::load()` y se comparte
/// entre sesiones via `Arc<ClientIdentity>`. La `SigningKey` se zeroiza del
/// buffer de lectura inmediatamente despues de deserializar.
///
/// Convencion de archivos:
///   - `client.sk` — clave de firma    (0o600, secreta)
///   - `client.vk` — clave de verificacion (0o644, publica — distribuir al bridge)
pub struct ClientIdentity {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl ClientIdentity {
    /// Carga el par de claves desde disco.
    ///
    /// - `sk_path`: ruta al archivo `client.sk`
    /// - La `VerifyingKey` se carga desde el mismo directorio con extension `.vk`
    ///
    /// Falla si:
    ///   - El archivo `.sk` no existe o no es legible
    ///   - Los permisos del `.sk` no son exactamente `0o600`
    ///   - Los bytes no tienen el tamano correcto
    pub fn load(sk_path: &Path) -> anyhow::Result<Self> {
        // Verificar permisos del archivo de clave privada
        let metadata = std::fs::metadata(sk_path)
            .with_context(|| format!("no se puede acceder a {}", sk_path.display()))?;

        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            anyhow::bail!(
                "permisos inseguros en {}: {:o} (debe ser 0600 — ejecuta: chmod 600 {})",
                sk_path.display(),
                mode,
                sk_path.display()
            );
        }

        // Cargar signing key — zeroizar el buffer de lectura despues de deserializar
        let mut sk_buf = [0u8; SIGNING_KEY_LEN];
        std::fs::File::open(sk_path)
            .with_context(|| format!("abriendo {}", sk_path.display()))?
            .read_exact(&mut sk_buf)
            .context("leyendo signing key — archivo truncado?")?;

        let signing_key = SigningKey::from_bytes(&sk_buf)
            .map_err(|e| anyhow::anyhow!("signing key invalida en {}: {e}", sk_path.display()))?;

        sk_buf.zeroize();

        // Cargar verifying key
        let vk_path = vk_path_from(sk_path);
        let mut vk_buf = [0u8; VERIFYING_KEY_LEN];
        std::fs::File::open(&vk_path)
            .with_context(|| {
                format!(
                    "abriendo {} — existe client.vk junto a client.sk?",
                    vk_path.display()
                )
            })?
            .read_exact(&mut vk_buf)
            .context("leyendo verifying key — archivo truncado?")?;

        let verifying_key = VerifyingKey::from_bytes(&vk_buf)
            .map_err(|e| anyhow::anyhow!("verifying key invalida en {}: {e}", vk_path.display()))?;

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Genera un par de claves nuevo y los guarda en `dir/client.sk` y `dir/client.vk`.
    ///
    /// - `client.sk` se crea con permisos `0o600` desde el momento de creacion
    /// - `client.vk` se crea con permisos `0o644`
    ///
    /// Distribuir `client.vk` al bridge antes de arrancar el cliente.
    pub fn generate_and_save(dir: &Path) -> anyhow::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;

        std::fs::create_dir_all(dir)
            .with_context(|| format!("creando directorio {}", dir.display()))?;

        let (sk, vk) = generate_keypair(&mut rand_core::OsRng);

        let sk_path = dir.join("client.sk");
        let vk_path = dir.join("client.vk");

        // Escribir signing key con permisos 0o600 desde creacion (sin race window)
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&sk_path)
            .with_context(|| format!("creando {}", sk_path.display()))?
            .write_all(sk.to_bytes())
            .context("escribiendo signing key")?;

        // Escribir verifying key con permisos 0o644
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&vk_path)
            .with_context(|| format!("creando {}", vk_path.display()))?
            .write_all(vk.to_bytes())
            .context("escribiendo verifying key")?;

        println!("Keypair de cliente generado exitosamente:");
        println!(
            "  Signing key:    {} (0600 — mantener SECRETO)",
            sk_path.display()
        );
        println!(
            "  Verifying key:  {} (0644 — distribuir al bridge out-of-band)",
            vk_path.display()
        );

        Ok(())
    }
}

impl Drop for ClientIdentity {
    fn drop(&mut self) {
        // SigningKey implementa Zeroize — se zeroiza al hacer drop
        self.signing_key.zeroize();
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use latticeshield_crypto::generate_keypair;
    use rand_core::OsRng;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
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
        assert_eq!(
            fp.len(),
            64,
            "fingerprint must be 64 hex chars, got len {}",
            fp.len()
        );
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let mut rng = OsRng;
        let (_sk, vk) = generate_keypair(&mut rng);
        let fp1 = fingerprint(&vk);
        let fp2 = fingerprint(&vk);
        assert_eq!(fp1, fp2, "fingerprint must be deterministic");
    }

    // ── ClientIdentity tests ──────────────────────────────────────────────────

    #[test]
    fn client_generate_creates_both_files() {
        let dir = tempfile::tempdir().unwrap();
        ClientIdentity::generate_and_save(dir.path()).unwrap();
        assert!(dir.path().join("client.sk").exists());
        assert!(dir.path().join("client.vk").exists());
    }

    #[test]
    fn client_generate_sk_has_correct_permissions() {
        let dir = tempfile::tempdir().unwrap();
        ClientIdentity::generate_and_save(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join("client.sk"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "client.sk debe ser 0600, es {:o}", mode);
    }

    #[test]
    fn client_generate_vk_has_correct_permissions() {
        let dir = tempfile::tempdir().unwrap();
        ClientIdentity::generate_and_save(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join("client.vk"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644, "client.vk debe ser 0644, es {:o}", mode);
    }

    #[test]
    fn client_load_roundtrip_ok() {
        let dir = tempfile::tempdir().unwrap();
        ClientIdentity::generate_and_save(dir.path()).unwrap();
        ClientIdentity::load(&dir.path().join("client.sk")).unwrap();
    }

    #[test]
    fn client_load_fails_on_wrong_sk_permissions() {
        let dir = tempfile::tempdir().unwrap();
        ClientIdentity::generate_and_save(dir.path()).unwrap();
        let sk_path = dir.path().join("client.sk");
        std::fs::set_permissions(&sk_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = ClientIdentity::load(&sk_path)
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(err.contains("permisos inseguros"), "{err}");
    }

    #[test]
    fn client_load_fails_on_wrong_size() {
        let dir = tempfile::tempdir().unwrap();
        let sk_path = dir.path().join("client.sk");
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&sk_path)
            .unwrap()
            .write_all(&[0u8; 16])
            .unwrap();
        let err = ClientIdentity::load(&sk_path)
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("truncado") || err.contains("failed to fill"),
            "{err}"
        );
    }
}
