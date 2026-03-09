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
    /// Clave de verificacion publica. No se usa en el hot path del servidor —
    /// se distribuye out-of-band a los clientes para que puedan verificar firmas.
    #[allow(dead_code)]
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
