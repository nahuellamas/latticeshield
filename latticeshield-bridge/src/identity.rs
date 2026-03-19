//! Par de claves de largo plazo del servidor para autenticacion ML-DSA-65.
//!
//! El `ServerIdentity` se carga una vez al arrancar el bridge y se comparte
//! entre sesiones via `Arc`. La `SigningKey` se zeroiza del buffer de lectura
//! inmediatamente despues de deserializar.
//!
//! Convencion de archivos:
//!   - `server.sk` — clave de firma    (0o600, secreta)
//!   - `server.vk` — clave de verificacion (0o644, publica — distribuir a clientes)

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use latticeshield_crypto::{
    generate_keypair, SigningKey, VerifyingKey, SIGNING_KEY_LEN, VERIFYING_KEY_LEN,
};
use zeroize::Zeroize;

/// Par de claves de largo plazo del servidor.
///
/// Se crea una vez al arrancar via `ServerIdentity::load()` y se comparte
/// entre tareas de sesion como `Arc<ServerIdentity>`.
pub struct ServerIdentity {
    pub signing_key: SigningKey,
    /// Clave de verificacion publica. Se expone via vk-share y en el payload
    /// de registro del control plane. Se distribuye out-of-band a los clientes.
    pub verifying_key: VerifyingKey,
}

impl ServerIdentity {
    /// Carga el par de claves desde disco.
    ///
    /// - `sk_path`: ruta al archivo `server.sk`
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
            .with_context(|| format!("abriendo {} — existe server.vk junto a server.sk?", vk_path.display()))?
            .read_exact(&mut vk_buf)
            .context("leyendo verifying key — archivo truncado?")?;

        let verifying_key = VerifyingKey::from_bytes(&vk_buf)
            .map_err(|e| anyhow::anyhow!("verifying key invalida en {}: {e}", vk_path.display()))?;

        Ok(Self { signing_key, verifying_key })
    }

    /// Genera un par de claves nuevo y los guarda en `dir/server.sk` y `dir/server.vk`.
    ///
    /// - `server.sk` se crea con permisos `0o600` desde el momento de creacion
    /// - `server.vk` se crea con permisos `0o644`
    ///
    /// Distribuir `server.vk` a todos los clientes antes de arrancar el bridge.
    pub fn generate_and_save(dir: &Path) -> anyhow::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;

        std::fs::create_dir_all(dir)
            .with_context(|| format!("creando directorio {}", dir.display()))?;

        let (sk, vk) = generate_keypair(&mut rand_core::OsRng);

        let sk_path = dir.join("server.sk");
        let vk_path = dir.join("server.vk");

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

        println!("Keypair generado exitosamente:");
        println!("  Signing key:    {} (0600 — mantener SECRETO)", sk_path.display());
        println!("  Verifying key:  {} (0644 — distribuir a clientes out-of-band)", vk_path.display());

        Ok(())
    }
}

fn vk_path_from(sk_path: &Path) -> PathBuf {
    sk_path.with_extension("vk")
}

/// Error al cargar una identidad de cliente.
#[derive(Debug)]
pub enum IdentityError {
    Io(std::io::Error),
    InvalidSize { expected: usize, found: usize },
    InvalidKey(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::Io(e) => write!(f, "archivo no encontrado o no legible: {e}"),
            IdentityError::InvalidSize { expected, found } => {
                write!(f, "tamano de archivo invalido: esperado {expected} bytes, encontrado {found}")
            }
            IdentityError::InvalidKey(msg) => write!(f, "clave de verificacion invalida: {msg}"),
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IdentityError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for IdentityError {
    fn from(e: std::io::Error) -> Self {
        IdentityError::Io(e)
    }
}

/// Clave de verificacion publica de un cliente para autenticacion mutua.
///
/// Se carga una vez al arrancar via `ClientVerifyingIdentity::load()` y se
/// comparte entre tareas de sesion como `Arc<ClientVerifyingIdentity>`.
///
/// No requiere chequeo de permisos — la VK es material publico.
#[derive(Debug)]
pub struct ClientVerifyingIdentity {
    pub verifying_key: VerifyingKey,
}

impl ClientVerifyingIdentity {
    /// Carga la clave de verificacion del cliente desde disco.
    ///
    /// Falla si:
    ///   - El archivo no existe o no es legible
    ///   - El archivo no tiene exactamente `VERIFYING_KEY_LEN` bytes
    ///   - Los bytes no representan una VK valida
    pub fn load(vk_path: &Path) -> Result<Self, IdentityError> {
        let data = std::fs::read(vk_path)?;

        if data.len() != VERIFYING_KEY_LEN {
            return Err(IdentityError::InvalidSize {
                expected: VERIFYING_KEY_LEN,
                found: data.len(),
            });
        }

        let buf: &[u8; VERIFYING_KEY_LEN] = data.as_slice().try_into().expect("len ya validado");
        let verifying_key = VerifyingKey::from_bytes(buf)
            .map_err(|e| IdentityError::InvalidKey(e.to_string()))?;

        Ok(Self { verifying_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // -------------------------------------------------------------------------
    // generate_and_save
    // -------------------------------------------------------------------------

    #[test]
    fn generate_creates_both_files() {
        let dir = tempfile::tempdir().unwrap();
        ServerIdentity::generate_and_save(dir.path()).unwrap();
        assert!(dir.path().join("server.sk").exists());
        assert!(dir.path().join("server.vk").exists());
    }

    #[test]
    fn generate_sk_has_correct_permissions() {
        let dir = tempfile::tempdir().unwrap();
        ServerIdentity::generate_and_save(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join("server.sk"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "server.sk debe ser 0600, es {:o}", mode);
    }

    #[test]
    fn generate_vk_has_correct_permissions() {
        let dir = tempfile::tempdir().unwrap();
        ServerIdentity::generate_and_save(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join("server.vk"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644, "server.vk debe ser 0644, es {:o}", mode);
    }

    #[test]
    fn generate_files_have_correct_size() {
        let dir = tempfile::tempdir().unwrap();
        ServerIdentity::generate_and_save(dir.path()).unwrap();
        assert_eq!(
            std::fs::metadata(dir.path().join("server.sk")).unwrap().len(),
            SIGNING_KEY_LEN as u64
        );
        assert_eq!(
            std::fs::metadata(dir.path().join("server.vk")).unwrap().len(),
            VERIFYING_KEY_LEN as u64
        );
    }

    // -------------------------------------------------------------------------
    // load
    // -------------------------------------------------------------------------

    #[test]
    fn load_roundtrip_ok() {
        let dir = tempfile::tempdir().unwrap();
        ServerIdentity::generate_and_save(dir.path()).unwrap();
        ServerIdentity::load(&dir.path().join("server.sk")).unwrap();
    }

    #[test]
    fn load_fails_on_wrong_sk_permissions() {
        let dir = tempfile::tempdir().unwrap();
        ServerIdentity::generate_and_save(dir.path()).unwrap();
        let sk_path = dir.path().join("server.sk");
        std::fs::set_permissions(&sk_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = ServerIdentity::load(&sk_path)
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(err.contains("permisos inseguros"), "{err}");
    }

    #[test]
    fn load_fails_when_sk_missing() {
        let dir = tempfile::tempdir().unwrap();
        let err = ServerIdentity::load(&dir.path().join("server.sk"))
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(err.contains("no se puede acceder"), "{err}");
    }

    #[test]
    fn load_fails_when_vk_missing() {
        let dir = tempfile::tempdir().unwrap();
        ServerIdentity::generate_and_save(dir.path()).unwrap();
        std::fs::remove_file(dir.path().join("server.vk")).unwrap();
        let err = ServerIdentity::load(&dir.path().join("server.sk"))
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(err.contains("server.vk"), "{err}");
    }

    #[test]
    fn load_fails_on_truncated_sk() {
        let dir = tempfile::tempdir().unwrap();
        let sk_path = dir.path().join("server.sk");
        // Crear un .sk con datos basura de tamaño incorrecto (permisos 0o600)
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&sk_path)
            .unwrap()
            .write_all(&[0u8; 16])
            .unwrap();
        let err = ServerIdentity::load(&sk_path)
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("truncado") || err.contains("failed to fill"),
            "{err}"
        );
    }

    // -------------------------------------------------------------------------
    // ClientVerifyingIdentity
    // -------------------------------------------------------------------------

    #[test]
    fn client_vk_load_roundtrip_ok() {
        let dir = tempfile::tempdir().unwrap();
        // Generar un keypair de servidor y reusar la VK como VK de cliente
        ServerIdentity::generate_and_save(dir.path()).unwrap();
        let vk_path = dir.path().join("server.vk");
        // Cargar como ClientVerifyingIdentity
        ClientVerifyingIdentity::load(&vk_path).unwrap();
    }

    #[test]
    fn client_vk_load_wrong_size_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vk_path = dir.path().join("client.vk");
        // Escribir un archivo con tamano incorrecto
        std::fs::write(&vk_path, &[0u8; 16]).unwrap();
        let err = ClientVerifyingIdentity::load(&vk_path).unwrap_err();
        assert!(
            matches!(err, IdentityError::InvalidSize { expected: VERIFYING_KEY_LEN, .. }),
            "error inesperado: {err}"
        );
    }

    #[test]
    fn client_vk_load_missing_file_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vk_path = dir.path().join("nonexistent.vk");
        let err = ClientVerifyingIdentity::load(&vk_path).unwrap_err();
        assert!(matches!(err, IdentityError::Io(_)), "error inesperado: {err}");
    }
}
