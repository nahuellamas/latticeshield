//! Configuracion del cliente proxy. Se carga desde un archivo TOML via `ClientConfig::load(path)`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

// ── Default fns ────────────────────────────────────────────────────────────────

fn default_listen_addr() -> String {
    "127.0.0.1:9090".to_string()
}

fn default_bridge_addr() -> String {
    "127.0.0.1:8443".to_string()
}

fn default_server_vk_path() -> PathBuf {
    PathBuf::from("./keys/server.vk")
}

fn default_max_frame_size() -> usize {
    65536
}

fn default_log_level() -> String {
    "info".to_string()
}

// ── Sub-structs ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ClientSection {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_bridge_addr")]
    pub bridge_addr: String,
    #[serde(default = "default_server_vk_path")]
    pub server_vk_path: PathBuf,
    #[serde(default = "default_max_frame_size")]
    pub max_frame_size: usize,
}

impl Default for ClientSection {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            bridge_addr: default_bridge_addr(),
            server_vk_path: default_server_vk_path(),
            max_frame_size: default_max_frame_size(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggingSection {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

// ── Root Config ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ClientConfig {
    pub client: ClientSection,
    pub logging: LoggingSection,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            client: ClientSection::default(),
            logging: LoggingSection::default(),
        }
    }
}

// ── ValidClientConfig — post-validation ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ValidClientConfig {
    pub listen_addr: SocketAddr,
    pub bridge_addr: SocketAddr,
    pub server_vk_path: PathBuf,
    pub max_frame_size: usize,
    pub log_level: String,
}

// ── ClientConfig::load + validate ─────────────────────────────────────────────

impl ClientConfig {
    /// Carga la configuracion desde un archivo TOML en `path`.
    pub fn load(path: &Path) -> anyhow::Result<ValidClientConfig> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file: {}", path.display()))?;
        let config: ClientConfig = toml::from_str(&contents)
            .with_context(|| format!("invalid TOML in {}", path.display()))?;
        config.validate()
    }

    pub fn validate(self) -> anyhow::Result<ValidClientConfig> {
        let listen_addr: SocketAddr = self
            .client
            .listen_addr
            .parse()
            .context("invalid client.listen_addr")?;

        let bridge_addr: SocketAddr = self
            .client
            .bridge_addr
            .parse()
            .context("invalid client.bridge_addr")?;

        if self.client.max_frame_size < 1024 || self.client.max_frame_size > 16 * 1024 * 1024 {
            anyhow::bail!(
                "max_frame_size must be between 1024 and 16777216, got {}",
                self.client.max_frame_size
            );
        }

        if self.client.server_vk_path.as_os_str().is_empty() {
            anyhow::bail!("crypto.server_vk_path must not be empty");
        }

        Ok(ValidClientConfig {
            listen_addr,
            bridge_addr,
            server_vk_path: self.client.server_vk_path,
            max_frame_size: self.client.max_frame_size,
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
    fn defaults_when_empty_file() {
        let f = write_toml("");
        let cfg = ClientConfig::load(f.path()).unwrap();
        assert_eq!(cfg.listen_addr.to_string(), "127.0.0.1:9090");
        assert_eq!(cfg.bridge_addr.to_string(), "127.0.0.1:8443");
        assert_eq!(cfg.max_frame_size, 65536);
        assert_eq!(cfg.server_vk_path, PathBuf::from("./keys/server.vk"));
    }

    #[test]
    fn custom_values_parsed() {
        let f = write_toml(
            r#"
[client]
listen_addr = "127.0.0.1:19090"
bridge_addr = "10.0.0.1:8443"
"#,
        );
        let cfg = ClientConfig::load(f.path()).unwrap();
        assert_eq!(cfg.listen_addr.to_string(), "127.0.0.1:19090");
        assert_eq!(cfg.bridge_addr.to_string(), "10.0.0.1:8443");
    }

    #[test]
    fn missing_file_error() {
        let err = ClientConfig::load(Path::new("/nonexistent/path/config.toml"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cannot read"),
            "error should contain 'cannot read', got: {err}"
        );
    }

    #[test]
    fn bad_toml_error() {
        let f = write_toml("[invalid toml {");
        let err = ClientConfig::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("invalid TOML"),
            "error should contain 'invalid TOML', got: {err}"
        );
    }

    #[test]
    fn invalid_listen_addr_rejected() {
        let f = write_toml("[client]\nlisten_addr = \"not_an_addr\"\n");
        let err = ClientConfig::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("client.listen_addr"),
            "error should reference client.listen_addr, got: {err}"
        );
    }

    #[test]
    fn invalid_bridge_addr_rejected() {
        let f = write_toml("[client]\nbridge_addr = \"bad_addr\"\n");
        let err = ClientConfig::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("client.bridge_addr"),
            "error should reference client.bridge_addr, got: {err}"
        );
    }

    #[test]
    fn max_frame_size_zero_rejected() {
        let f = write_toml("[client]\nmax_frame_size = 0\n");
        let err = ClientConfig::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("max_frame_size"),
            "error should reference max_frame_size, got: {err}"
        );
    }

    #[test]
    fn max_frame_size_too_large_rejected() {
        let f = write_toml("[client]\nmax_frame_size = 33554432\n");
        let err = ClientConfig::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("max_frame_size"),
            "error should reference max_frame_size, got: {err}"
        );
    }

    #[test]
    fn empty_server_vk_path_rejected() {
        let f = write_toml("[client]\nserver_vk_path = \"\"\n");
        let err = ClientConfig::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("crypto.server_vk_path"),
            "error should reference crypto.server_vk_path, got: {err}"
        );
    }
}
