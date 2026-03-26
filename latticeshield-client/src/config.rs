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

fn default_pool_max_size() -> usize {
    4
}
fn default_pool_idle_timeout_secs() -> u64 {
    30
}
fn default_pool_warm_size() -> usize {
    2
}
fn default_pool_warm_interval_secs() -> u64 {
    5
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
    pub client_sk_path: Option<PathBuf>,
}

impl Default for ClientSection {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            bridge_addr: default_bridge_addr(),
            server_vk_path: default_server_vk_path(),
            max_frame_size: default_max_frame_size(),
            client_sk_path: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PoolConfig {
    #[serde(default = "default_pool_max_size")]
    pub max_size: usize,
    #[serde(default = "default_pool_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_pool_warm_size")]
    pub warm_size: usize,
    #[serde(default = "default_pool_warm_interval_secs")]
    pub warm_interval_secs: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_size: default_pool_max_size(),
            idle_timeout_secs: default_pool_idle_timeout_secs(),
            warm_size: default_pool_warm_size(),
            warm_interval_secs: default_pool_warm_interval_secs(),
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
    #[serde(default)]
    pub pool: PoolConfig,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            client: ClientSection::default(),
            logging: LoggingSection::default(),
            pool: PoolConfig::default(),
        }
    }
}

// ── ValidClientConfig — post-validation ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ValidClientConfig {
    pub listen_addr: SocketAddr,
    pub bridge_addr: SocketAddr,
    pub server_vk_path: PathBuf,
    pub client_sk_path: Option<PathBuf>,
    pub max_frame_size: usize,
    pub log_level: String,
    pub pool: PoolConfig,
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

        if self.pool.max_size < 1 {
            anyhow::bail!("pool.max_size must be >= 1");
        }
        if self.pool.warm_size > self.pool.max_size {
            anyhow::bail!("pool.warm_size must be <= pool.max_size");
        }
        if self.pool.idle_timeout_secs < 1 {
            anyhow::bail!("pool.idle_timeout_secs must be >= 1");
        }
        if self.pool.warm_interval_secs < 1 {
            anyhow::bail!("pool.warm_interval_secs must be >= 1");
        }

        Ok(ValidClientConfig {
            listen_addr,
            bridge_addr,
            server_vk_path: self.client.server_vk_path,
            client_sk_path: self.client.client_sk_path,
            max_frame_size: self.client.max_frame_size,
            log_level: self.logging.level,
            pool: self.pool,
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

    #[test]
    fn client_sk_path_parsed() {
        let f = write_toml(
            r#"
[client]
client_sk_path = "./keys/client.sk"
"#,
        );
        let cfg = ClientConfig::load(f.path()).unwrap();
        assert_eq!(cfg.client_sk_path, Some(PathBuf::from("./keys/client.sk")));
    }

    #[test]
    fn client_sk_path_absent_is_none() {
        let f = write_toml("");
        let cfg = ClientConfig::load(f.path()).unwrap();
        assert!(cfg.client_sk_path.is_none());
    }

    #[test]
    fn pool_defaults_when_section_absent() {
        let f = write_toml("");
        let cfg = ClientConfig::load(f.path()).unwrap();
        assert_eq!(cfg.pool.max_size, 4);
        assert_eq!(cfg.pool.idle_timeout_secs, 30);
        assert_eq!(cfg.pool.warm_size, 2);
        assert_eq!(cfg.pool.warm_interval_secs, 5);
    }

    #[test]
    fn pool_explicit_values_parsed() {
        let f = write_toml(
            r#"
[pool]
max_size = 8
warm_size = 4
"#,
        );
        let cfg = ClientConfig::load(f.path()).unwrap();
        assert_eq!(cfg.pool.max_size, 8);
        assert_eq!(cfg.pool.warm_size, 4);
    }

    #[test]
    fn pool_warm_size_gt_max_size_rejected() {
        let f = write_toml("[pool]\nmax_size = 2\nwarm_size = 5\n");
        let err = ClientConfig::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("pool.warm_size"),
            "error should reference pool.warm_size, got: {err}"
        );
    }

    #[test]
    fn pool_max_size_zero_rejected() {
        let f = write_toml("[pool]\nmax_size = 0\n");
        let err = ClientConfig::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("pool.max_size"),
            "error should reference pool.max_size, got: {err}"
        );
    }

    #[test]
    fn pool_idle_timeout_zero_rejected() {
        let f = write_toml("[pool]\nidle_timeout_secs = 0\n");
        let err = ClientConfig::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("pool.idle_timeout_secs"),
            "error should reference pool.idle_timeout_secs, got: {err}"
        );
    }

    #[test]
    fn pool_warm_size_zero_accepted() {
        let f = write_toml("[pool]\nwarm_size = 0\n");
        let cfg = ClientConfig::load(f.path()).unwrap();
        assert_eq!(cfg.pool.warm_size, 0);
    }

    #[test]
    fn pool_warm_interval_zero_rejected() {
        let f = write_toml("[pool]\nwarm_interval_secs = 0\n");
        let err = ClientConfig::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("pool.warm_interval_secs"),
            "error should reference pool.warm_interval_secs, got: {err}"
        );
    }
}
