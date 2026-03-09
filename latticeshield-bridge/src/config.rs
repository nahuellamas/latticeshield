//! Configuracion del proxy. Se carga desde un archivo TOML via `Config::load(path)`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

// ── Default fns (required by #[serde(default = "...")] on fields) ─────────────

fn default_listen_addr() -> String {
    "0.0.0.0:8443".to_string()
}

fn default_backend_addr() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_max_frame_size() -> usize {
    64 * 1024
}

fn default_signing_key_path() -> PathBuf {
    PathBuf::from("./keys/server.sk")
}

fn default_metrics_addr() -> String {
    "0.0.0.0:8444".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

// ── Sub-structs ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_backend_addr")]
    pub backend_addr: String,
    #[serde(default = "default_max_frame_size")]
    pub max_frame_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            backend_addr: default_backend_addr(),
            max_frame_size: default_max_frame_size(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CryptoConfig {
    #[serde(default = "default_signing_key_path")]
    pub signing_key_path: PathBuf,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            signing_key_path: default_signing_key_path(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_addr")]
    pub listen_addr: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_metrics_addr(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

// ── Root Config ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub crypto: CryptoConfig,
    pub metrics: MetricsConfig,
    pub logging: LoggingConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            crypto: CryptoConfig::default(),
            metrics: MetricsConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

// ── ValidConfig — post-validation, what server::run() receives ─────────────────

#[derive(Debug, Clone)]
pub struct ValidConfig {
    pub listen_addr: SocketAddr,
    pub backend_addr: SocketAddr,
    pub metrics_addr: SocketAddr,
    pub max_frame_size: usize,
    pub signing_key_path: PathBuf,
    pub log_level: String,
}

// ── Config::load + validate ────────────────────────────────────────────────────

impl Config {
    /// Carga la configuracion desde un archivo TOML en `path`.
    ///
    /// Lee el archivo, lo parsea como TOML y aplica validacion semantica.
    /// Retorna `ValidConfig` con todos los campos listos para usar.
    pub fn load(path: &Path) -> anyhow::Result<ValidConfig> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file: {}", path.display()))?;
        let config: Config = toml::from_str(&contents)
            .with_context(|| format!("invalid TOML in {}", path.display()))?;
        config.validate()
    }

    fn validate(self) -> anyhow::Result<ValidConfig> {
        let listen_addr: SocketAddr = self
            .server
            .listen_addr
            .parse()
            .context("invalid server.listen_addr")?;

        let backend_addr: SocketAddr = self
            .server
            .backend_addr
            .parse()
            .context("invalid server.backend_addr")?;

        let metrics_addr: SocketAddr = self
            .metrics
            .listen_addr
            .parse()
            .context("invalid metrics.listen_addr")?;

        if self.server.max_frame_size < 1024 || self.server.max_frame_size > 16 * 1024 * 1024 {
            anyhow::bail!(
                "server.max_frame_size must be between 1024 and 16777216 (16 MiB), got {}",
                self.server.max_frame_size
            );
        }

        if self.crypto.signing_key_path.as_os_str().is_empty() {
            anyhow::bail!("crypto.signing_key_path must not be empty");
        }

        Ok(ValidConfig {
            listen_addr,
            backend_addr,
            metrics_addr,
            max_frame_size: self.server.max_frame_size,
            signing_key_path: self.crypto.signing_key_path,
            log_level: self.logging.level,
        })
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_toml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn load_valid_config_ok() {
        let f = write_toml(
            r#"
[server]
listen_addr    = "127.0.0.1:9443"
backend_addr   = "127.0.0.1:9080"
max_frame_size = 32768

[crypto]
signing_key_path = "/etc/latticeshield/server.sk"

[metrics]
listen_addr = "127.0.0.1:9444"

[logging]
level = "debug"
"#,
        );

        let cfg = Config::load(f.path()).unwrap();

        assert_eq!(cfg.listen_addr.to_string(), "127.0.0.1:9443");
        assert_eq!(cfg.backend_addr.to_string(), "127.0.0.1:9080");
        assert_eq!(cfg.max_frame_size, 32768);
        assert_eq!(cfg.signing_key_path, PathBuf::from("/etc/latticeshield/server.sk"));
        assert_eq!(cfg.metrics_addr.to_string(), "127.0.0.1:9444");
        assert_eq!(cfg.log_level, "debug");
    }

    #[test]
    fn load_missing_file_error() {
        let err = Config::load(Path::new("/nonexistent/path/config.toml"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cannot read"),
            "error should contain 'cannot read', got: {err}"
        );
    }

    #[test]
    fn load_bad_toml_error() {
        let f = write_toml("[invalid toml {");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("invalid TOML"),
            "error should contain 'invalid TOML', got: {err}"
        );
    }

    #[test]
    fn load_wrong_type_error() {
        let f = write_toml(
            r#"
[server]
max_frame_size = "not_a_number"
"#,
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("invalid TOML"),
            "error should contain 'invalid TOML' with file path, got: {err}"
        );
    }

    #[test]
    fn validation_rejects_empty_signing_key_path() {
        let f = write_toml(
            r#"
[crypto]
signing_key_path = ""
"#,
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("signing_key_path"),
            "error should reference signing_key_path, got: {err}"
        );
    }

    #[test]
    fn load_defaults_when_sections_absent() {
        let f = write_toml("");
        let cfg = Config::load(f.path()).unwrap();

        assert_eq!(cfg.listen_addr.to_string(), "0.0.0.0:8443");
        assert_eq!(cfg.backend_addr.to_string(), "127.0.0.1:8080");
        assert_eq!(cfg.max_frame_size, 65536);
        assert_eq!(cfg.signing_key_path, PathBuf::from("./keys/server.sk"));
        assert_eq!(cfg.metrics_addr.to_string(), "0.0.0.0:8444");
        assert_eq!(cfg.log_level, "info");
    }

    #[test]
    fn load_defaults_when_fields_absent() {
        let f = write_toml("[server]\n");
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.max_frame_size, 65536);
    }

    #[test]
    fn validation_rejects_zero_frame_size() {
        let f = write_toml(
            r#"
[server]
max_frame_size = 0
"#,
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("max_frame_size"),
            "error should reference max_frame_size, got: {err}"
        );
    }

    #[test]
    fn validation_rejects_frame_size_too_large() {
        let f = write_toml(
            r#"
[server]
max_frame_size = 33554432
"#,
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("max_frame_size"),
            "error should reference max_frame_size, got: {err}"
        );
    }

    #[test]
    fn validation_rejects_bad_socket_addr() {
        let f = write_toml(
            r#"
[server]
listen_addr = "not_an_addr"
"#,
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("listen_addr"),
            "error should reference listen_addr, got: {err}"
        );
    }
}
