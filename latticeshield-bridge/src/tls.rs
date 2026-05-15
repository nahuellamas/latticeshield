//! TLS acceptor setup — loads PEM cert+key and builds a tokio_rustls TlsAcceptor.
//! Optional `generate_self_signed` is feature-gated behind `tls-keygen`.

use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// Load a PEM-encoded certificate chain from `path`.
fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let f = std::fs::File::open(path)
        .with_context(|| format!("cannot open cert file: {}", path.display()))?;
    let mut reader = BufReader::new(f);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .with_context(|| format!("failed to parse certs from: {}", path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in: {}", path.display());
    }
    Ok(certs)
}

/// Load the first private key (PKCS#8 or RSA) from a PEM file at `path`.
fn load_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let f = std::fs::File::open(path)
        .with_context(|| format!("cannot open key file: {}", path.display()))?;
    let mut reader = BufReader::new(f);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("failed to parse private key from: {}", path.display()))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in: {}", path.display()))
}

/// Build a rustls ServerConfig from PEM cert+key files.
/// Returns Arc<ServerConfig> — consumed by both TlsAcceptor (TLS) and quinn Endpoint (QUIC).
pub fn build_server_config(cert_path: &Path, key_path: &Path) -> anyhow::Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| {
            format!(
                "invalid cert/key pair — cert: {}, key: {}\n\
             Hint: run `latticeshield-bridge tls-keygen ./keys` to generate a self-signed cert",
                cert_path.display(),
                key_path.display()
            )
        })?;
    Ok(Arc::new(config))
}

/// Load cert + key from PEM files and build a TlsAcceptor.
/// Returns Err with an actionable message if files are missing or malformed.
pub fn build_acceptor(cert_path: &Path, key_path: &Path) -> anyhow::Result<TlsAcceptor> {
    let config = build_server_config(cert_path, key_path)?;
    Ok(TlsAcceptor::from(config))
}

/// Generate a self-signed TLS cert+key for development use.
/// Writes tls.crt (0o644) and tls.key (0o600) to `dir`.
/// Only available with the `tls-keygen` feature flag.
#[cfg(feature = "tls-keygen")]
pub fn generate_self_signed(dir: &Path) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::create_dir_all(dir)
        .with_context(|| format!("cannot create dir: {}", dir.display()))?;

    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("rcgen failed to generate self-signed cert")?;

    let cert_pem = certified_key.cert.pem();
    let key_pem = certified_key.key_pair.serialize_pem();

    let cert_path = dir.join("tls.crt");
    let key_path = dir.join("tls.key");

    // Write cert — world readable
    std::fs::write(&cert_path, cert_pem.as_bytes())
        .with_context(|| format!("cannot write cert: {}", cert_path.display()))?;
    #[allow(clippy::permissions_set_readonly_false)]
    std::fs::set_permissions(
        &cert_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    )
    .with_context(|| format!("cannot set perms on: {}", cert_path.display()))?;

    // Write key — owner-only (0o600)
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&key_path)
        .with_context(|| format!("cannot open for write: {}", key_path.display()))?
        .write_all(key_pem.as_bytes())
        .with_context(|| format!("cannot write key: {}", key_path.display()))?;

    println!("Generated:");
    println!("  cert: {} (0644)", cert_path.display());
    println!("  key:  {} (0600)", key_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn init_crypto() {
        static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        INIT.get_or_init(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    /// Helper: generate a self-signed cert/key using rcgen (from dev-deps).
    /// Returns (cert_file, key_file) as NamedTempFile so they stay on disk during test.
    fn make_self_signed_files() -> (NamedTempFile, NamedTempFile) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen failed");
        let mut cert_f = NamedTempFile::new().unwrap();
        let mut key_f = NamedTempFile::new().unwrap();
        cert_f.write_all(certified.cert.pem().as_bytes()).unwrap();
        key_f
            .write_all(certified.key_pair.serialize_pem().as_bytes())
            .unwrap();
        (cert_f, key_f)
    }

    #[test]
    fn build_acceptor_valid_self_signed_ok() {
        init_crypto();
        let (cert_f, key_f) = make_self_signed_files();
        build_acceptor(cert_f.path(), key_f.path()).unwrap();
    }

    #[test]
    fn build_acceptor_missing_cert_file_err() {
        let key_f = NamedTempFile::new().unwrap();
        let err = build_acceptor(Path::new("/nonexistent/tls.crt"), key_f.path())
            .err()
            .expect("should be Err")
            .to_string();
        assert!(err.contains("cert"), "expected 'cert' in error, got: {err}");
    }

    #[test]
    fn build_acceptor_missing_key_file_err() {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let mut cert_f = NamedTempFile::new().unwrap();
        cert_f.write_all(certified.cert.pem().as_bytes()).unwrap();
        let err = build_acceptor(cert_f.path(), Path::new("/nonexistent/tls.key"))
            .err()
            .expect("should be Err")
            .to_string();
        assert!(err.contains("key"), "expected 'key' in error, got: {err}");
    }

    #[test]
    fn build_acceptor_malformed_pem_err() {
        let mut cert_f = NamedTempFile::new().unwrap();
        let key_f = NamedTempFile::new().unwrap();
        cert_f.write_all(b"this is not valid PEM data").unwrap();
        let err = build_acceptor(cert_f.path(), key_f.path())
            .err()
            .expect("should be Err")
            .to_string();
        assert!(!err.is_empty());
    }

    #[test]
    fn build_server_config_valid_cert_ok() {
        init_crypto();
        let (cert_f, key_f) = make_self_signed_files();
        let result = build_server_config(cert_f.path(), key_f.path());
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
    }

    #[test]
    fn build_server_config_missing_cert_err() {
        let key_f = NamedTempFile::new().unwrap();
        let err = build_server_config(Path::new("/nonexistent/tls.crt"), key_f.path())
            .err()
            .expect("should be Err")
            .to_string();
        assert!(err.contains("cert"), "expected 'cert' in error, got: {err}");
    }

    #[test]
    fn build_server_config_missing_key_err() {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let mut cert_f = NamedTempFile::new().unwrap();
        cert_f.write_all(certified.cert.pem().as_bytes()).unwrap();
        let err = build_server_config(cert_f.path(), Path::new("/nonexistent/tls.key"))
            .err()
            .expect("should be Err")
            .to_string();
        assert!(err.contains("key"), "expected 'key' in error, got: {err}");
    }

    #[cfg(feature = "tls-keygen")]
    #[test]
    fn generate_self_signed_creates_files_with_correct_perms() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        generate_self_signed(dir.path()).unwrap();

        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");

        assert!(cert_path.exists(), "tls.crt missing");
        assert!(key_path.exists(), "tls.key missing");

        let key_mode = std::fs::metadata(&key_path).unwrap().mode() & 0o777;
        assert_eq!(key_mode, 0o600, "tls.key must be 0600, got {key_mode:o}");
    }

    #[cfg(feature = "tls-keygen")]
    #[test]
    fn generate_self_signed_cert_is_valid_pem_for_acceptor() {
        init_crypto();
        let dir = tempfile::tempdir().unwrap();
        generate_self_signed(dir.path()).unwrap();
        build_acceptor(&dir.path().join("tls.crt"), &dir.path().join("tls.key")).unwrap();
    }

    #[cfg(feature = "tls-keygen")]
    #[test]
    fn generate_self_signed_unwritable_path_error() {
        let err = generate_self_signed(Path::new("/proc/nonexistent/tls"))
            .unwrap_err()
            .to_string();
        assert!(!err.is_empty());
    }
}
