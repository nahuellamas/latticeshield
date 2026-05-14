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
    /// Maximum seconds to wait for the PQC TCP handshake to complete.
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    /// Maximum concurrent PQC TCP connections per source IP.
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            backend_addr: default_backend_addr(),
            max_frame_size: default_max_frame_size(),
            handshake_timeout_secs: default_handshake_timeout_secs(),
            max_connections_per_ip: default_max_connections_per_ip(),
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

fn default_cp_enabled() -> bool {
    false
}
fn default_cp_endpoint() -> String {
    String::new()
}
fn default_cp_agent_name() -> String {
    String::new()
}
fn default_cp_interval() -> u64 {
    30
}

fn default_kr_enabled() -> bool {
    false
}
fn default_kr_max_bytes() -> u64 {
    10_737_418_240
} // 10 GB
fn default_kr_max_seconds() -> u64 {
    86_400
} // 24 hours

fn default_tls_enabled() -> bool {
    false
}
fn default_tls_listen_addr() -> String {
    "0.0.0.0:8440".to_string()
}
fn default_tls_cert_path() -> PathBuf {
    PathBuf::from("./keys/tls.crt")
}
fn default_tls_key_path() -> PathBuf {
    PathBuf::from("./keys/tls.key")
}

fn default_quic_enabled() -> bool {
    false
}
fn default_quic_listen_addr() -> String {
    "0.0.0.0:8441".to_string()
}

fn default_admin_enabled() -> bool {
    false
}
fn default_admin_listen_addr() -> String {
    "0.0.0.0:8445".to_string()
}
fn default_admin_rate_limit() -> u32 {
    5
}
fn default_admin_handshake_timeout() -> u64 {
    10
}

fn default_require_client_auth() -> bool {
    true
}

fn default_ws_enabled() -> bool {
    false
}
fn default_ws_listen_addr() -> String {
    "0.0.0.0:8446".to_string()
}
fn default_ws_handshake_timeout_secs() -> u64 {
    10
}
fn default_ws_max_connections_per_ip() -> u32 {
    100
}

fn default_handshake_timeout_secs() -> u64 {
    10
}
fn default_max_connections_per_ip() -> u32 {
    50
}

// ── AdminConfig ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AdminConfig {
    #[serde(default = "default_admin_enabled")]
    pub enabled: bool,
    #[serde(default = "default_admin_listen_addr")]
    pub listen_addr: String,
    /// Ruta a la clave de verificacion publica del control plane (material publico).
    /// Requerida cuando enabled = true.
    pub control_plane_vk_path: Option<PathBuf>,
    #[serde(default = "default_admin_rate_limit")]
    pub rate_limit_per_second: u32,
    #[serde(default = "default_admin_handshake_timeout")]
    pub handshake_timeout_secs: u64,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: default_admin_enabled(),
            listen_addr: default_admin_listen_addr(),
            control_plane_vk_path: None,
            rate_limit_per_second: default_admin_rate_limit(),
            handshake_timeout_secs: default_admin_handshake_timeout(),
        }
    }
}

// ── AuthConfig ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Ruta a la clave de verificacion publica del cliente (material publico).
    /// Requerida cuando require_client_auth = true.
    pub client_vk_path: Option<PathBuf>,
    /// Si true (default), el bridge falla al arrancar si no hay client_vk_path configurado.
    /// Set to false para permitir conexiones sin autenticacion del cliente.
    #[serde(default = "default_require_client_auth")]
    pub require_client_auth: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            client_vk_path: None,
            require_client_auth: default_require_client_auth(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ControlPlaneConfig {
    #[serde(default = "default_cp_enabled")]
    pub enabled: bool,
    #[serde(default = "default_cp_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_cp_agent_name")]
    pub agent_name: String,
    #[serde(default = "default_cp_interval")]
    pub heartbeat_interval_secs: u64,
    pub install_token: Option<String>,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            enabled: default_cp_enabled(),
            endpoint: default_cp_endpoint(),
            agent_name: default_cp_agent_name(),
            heartbeat_interval_secs: default_cp_interval(),
            install_token: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct KeyRotationConfig {
    #[serde(default = "default_kr_enabled")]
    pub enabled: bool,
    #[serde(default = "default_kr_max_bytes")]
    pub max_bytes_per_key: u64,
    #[serde(default = "default_kr_max_seconds")]
    pub max_seconds_per_key: u64,
}

impl Default for KeyRotationConfig {
    fn default() -> Self {
        Self {
            enabled: default_kr_enabled(),
            max_bytes_per_key: default_kr_max_bytes(),
            max_seconds_per_key: default_kr_max_seconds(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    #[serde(default = "default_tls_enabled")]
    pub enabled: bool,
    #[serde(default = "default_tls_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_tls_cert_path")]
    pub cert_path: PathBuf,
    #[serde(default = "default_tls_key_path")]
    pub key_path: PathBuf,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: default_tls_enabled(),
            listen_addr: default_tls_listen_addr(),
            cert_path: default_tls_cert_path(),
            key_path: default_tls_key_path(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct QuicConfig {
    #[serde(default = "default_quic_enabled")]
    pub enabled: bool,
    #[serde(default = "default_quic_listen_addr")]
    pub listen_addr: String,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            enabled: default_quic_enabled(),
            listen_addr: default_quic_listen_addr(),
            cert_path: None,
            key_path: None,
        }
    }
}

// ── WsConfig ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WsConfig {
    #[serde(default = "default_ws_enabled")]
    pub enabled: bool,
    #[serde(default = "default_ws_listen_addr")]
    pub listen_addr: String,
    /// TLS cert path — required when enabled = true (WS runs over WSS only in production)
    pub cert_path: Option<PathBuf>,
    /// TLS key path — required when enabled = true
    pub key_path: Option<PathBuf>,
    /// Allowed Origin headers. Empty = accept all origins (development mode — emits WARN at startup).
    pub allowed_origins: Vec<String>,
    /// Maximum seconds to wait for the PQC handshake to complete after WS upgrade.
    #[serde(default = "default_ws_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    /// Maximum concurrent WebSocket connections per source IP.
    #[serde(default = "default_ws_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            enabled: default_ws_enabled(),
            listen_addr: default_ws_listen_addr(),
            cert_path: None,
            key_path: None,
            allowed_origins: Vec::new(),
            handshake_timeout_secs: default_ws_handshake_timeout_secs(),
            max_connections_per_ip: default_ws_max_connections_per_ip(),
        }
    }
}

// ── Root Config ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub crypto: CryptoConfig,
    pub metrics: MetricsConfig,
    pub logging: LoggingConfig,
    pub control_plane: ControlPlaneConfig,
    pub key_rotation: KeyRotationConfig,
    pub tls: TlsConfig,
    pub quic: QuicConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub websocket: WsConfig,
}

// ── ValidConfig — post-validation, what server::run() receives ─────────────────

#[derive(Clone)]
pub struct ValidConfig {
    pub listen_addr: SocketAddr,
    pub backend_addr: SocketAddr,
    pub metrics_addr: SocketAddr,
    pub max_frame_size: usize,
    pub handshake_timeout_secs: u64,
    pub max_connections_per_ip: u32,
    pub signing_key_path: PathBuf,
    pub log_level: String,
    pub control_plane_enabled: bool,
    pub control_plane_endpoint: String,
    pub control_plane_agent_name: String,
    pub heartbeat_interval: std::time::Duration,
    pub key_rotation_enabled: bool,
    pub max_bytes_per_key: u64,
    pub key_rotation_interval: std::time::Duration,
    pub tls_enabled: bool,
    pub tls_listen_addr: SocketAddr,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub quic_enabled: bool,
    pub quic_listen_addr: SocketAddr,
    pub quic_cert_path: PathBuf, // only meaningful when quic_enabled = true
    pub quic_key_path: PathBuf,  // only meaningful when quic_enabled = true
    /// true si se configuro [auth].client_vk_path — el bridge exigira autenticacion del cliente.
    pub client_auth_enabled: bool,
    /// Ruta a la VK del cliente (solo significativa cuando client_auth_enabled = true).
    pub client_vk_path: Option<PathBuf>,
    // ── Admin PQC listener (:8445) ──────────────────────────────────────────────
    pub admin_enabled: bool,
    pub admin_listen_addr: SocketAddr,
    /// Ruta a la VK del control plane (requerida cuando admin_enabled = true).
    pub admin_control_plane_vk_path: Option<PathBuf>,
    pub admin_rate_limit_per_second: u32,
    pub admin_handshake_timeout_secs: u64,
    pub control_plane_install_token: Option<String>,
    /// Graceful shutdown drain timeout. Sessions still active after this duration are forced.
    pub shutdown_timeout: std::time::Duration,
    // ── WebSocket listener (:8446) ───────────────────────────────────────────────
    pub ws_enabled: bool,
    pub ws_listen_addr: SocketAddr,
    pub ws_cert_path: PathBuf, // only meaningful when ws_enabled = true
    pub ws_key_path: PathBuf,  // only meaningful when ws_enabled = true
    pub ws_allowed_origins: Vec<crate::ws::NormalizedOrigin>,
    pub ws_handshake_timeout_secs: u64,
    pub ws_max_connections_per_ip: u32,
    /// Maximum number of active VK-share tokens in the in-memory store.
    /// Controlled by env var `LATTICE_VK_TOKEN_MAX` (default 1000).
    pub vk_share_max_tokens: usize,
}

impl std::fmt::Debug for ValidConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidConfig")
            .field("listen_addr", &self.listen_addr)
            .field("backend_addr", &self.backend_addr)
            .field("metrics_addr", &self.metrics_addr)
            .field("max_frame_size", &self.max_frame_size)
            .field("handshake_timeout_secs", &self.handshake_timeout_secs)
            .field("max_connections_per_ip", &self.max_connections_per_ip)
            .field("signing_key_path", &self.signing_key_path)
            .field("log_level", &self.log_level)
            .field("control_plane_enabled", &self.control_plane_enabled)
            .field("control_plane_endpoint", &self.control_plane_endpoint)
            .field("control_plane_agent_name", &self.control_plane_agent_name)
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("key_rotation_enabled", &self.key_rotation_enabled)
            .field("max_bytes_per_key", &self.max_bytes_per_key)
            .field("key_rotation_interval", &self.key_rotation_interval)
            .field("tls_enabled", &self.tls_enabled)
            .field("tls_listen_addr", &self.tls_listen_addr)
            .field("tls_cert_path", &self.tls_cert_path)
            .field("tls_key_path", &self.tls_key_path)
            .field("quic_enabled", &self.quic_enabled)
            .field("quic_listen_addr", &self.quic_listen_addr)
            .field("quic_cert_path", &self.quic_cert_path)
            .field("quic_key_path", &self.quic_key_path)
            .field("client_auth_enabled", &self.client_auth_enabled)
            .field("client_vk_path", &self.client_vk_path)
            .field("admin_enabled", &self.admin_enabled)
            .field("admin_listen_addr", &self.admin_listen_addr)
            .field(
                "admin_control_plane_vk_path",
                &self.admin_control_plane_vk_path,
            )
            .field(
                "admin_rate_limit_per_second",
                &self.admin_rate_limit_per_second,
            )
            .field(
                "admin_handshake_timeout_secs",
                &self.admin_handshake_timeout_secs,
            )
            .field(
                "control_plane_install_token",
                &self
                    .control_plane_install_token
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field("ws_enabled", &self.ws_enabled)
            .field("ws_listen_addr", &self.ws_listen_addr)
            .field("ws_cert_path", &self.ws_cert_path)
            .field("ws_key_path", &self.ws_key_path)
            .field(
                "ws_allowed_origins",
                &self
                    .ws_allowed_origins
                    .iter()
                    .map(|o| o.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("ws_handshake_timeout_secs", &self.ws_handshake_timeout_secs)
            .field("ws_max_connections_per_ip", &self.ws_max_connections_per_ip)
            .field("vk_share_max_tokens", &self.vk_share_max_tokens)
            .finish()
    }
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

        if self.server.handshake_timeout_secs < 1 {
            anyhow::bail!(
                "server.handshake_timeout_secs must be at least 1, got {}",
                self.server.handshake_timeout_secs
            );
        }

        if self.server.max_connections_per_ip == 0 {
            anyhow::bail!("server.max_connections_per_ip must be at least 1");
        }

        if self.crypto.signing_key_path.as_os_str().is_empty() {
            anyhow::bail!("crypto.signing_key_path must not be empty");
        }

        // ── Control plane validation ────────────────────────────────────────
        let control_plane_enabled = self.control_plane.enabled;
        let control_plane_endpoint = self.control_plane.endpoint.clone();

        if control_plane_enabled && control_plane_endpoint.is_empty() {
            anyhow::bail!("control_plane.endpoint must be set when control_plane.enabled = true");
        }

        if control_plane_enabled && !control_plane_endpoint.is_empty() {
            url::Url::parse(&control_plane_endpoint)
                .with_context(|| "control_plane.endpoint is not a valid URL")?;
        }

        let control_plane_agent_name = if self.control_plane.agent_name.is_empty() {
            std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
        } else {
            self.control_plane.agent_name.clone()
        };

        let heartbeat_interval =
            std::time::Duration::from_secs(self.control_plane.heartbeat_interval_secs.max(5));

        // ── install_token resolution (env var takes precedence over TOML) ───
        let control_plane_install_token = match std::env::var("INSTALL_TOKEN") {
            Ok(val) if !val.is_empty() => Some(val),
            _ => self.control_plane.install_token.clone(),
        };

        if control_plane_enabled && control_plane_install_token.is_none() {
            tracing::warn!(
                "control_plane.install_token is not set — the cloud cannot authenticate this bridge on registration"
            );
        }

        // ── Key rotation validation ─────────────────────────────────────────
        if self.key_rotation.max_bytes_per_key < 1_048_576 {
            anyhow::bail!(
                "key_rotation.max_bytes_per_key must be at least 1048576 (1 MiB), got {}",
                self.key_rotation.max_bytes_per_key
            );
        }

        if self.key_rotation.max_seconds_per_key < 60 {
            anyhow::bail!(
                "key_rotation.max_seconds_per_key must be at least 60, got {}",
                self.key_rotation.max_seconds_per_key
            );
        }

        // ── TLS listener validation ──────────────────────────────────────────
        let tls_listen_addr: SocketAddr = self
            .tls
            .listen_addr
            .parse()
            .context("invalid tls.listen_addr")?;

        if self.tls.enabled {
            if self.tls.cert_path.as_os_str().is_empty() {
                anyhow::bail!("tls.cert_path must be set when tls.enabled = true");
            }
            if self.tls.key_path.as_os_str().is_empty() {
                anyhow::bail!("tls.key_path must be set when tls.enabled = true");
            }
            if tls_listen_addr == listen_addr {
                anyhow::bail!(
                    "tls.listen_addr ({}) conflicts with server.listen_addr — they must be different ports",
                    tls_listen_addr
                );
            }
            if tls_listen_addr == metrics_addr {
                anyhow::bail!(
                    "tls.listen_addr ({}) conflicts with metrics.listen_addr — they must be different ports",
                    tls_listen_addr
                );
            }
        }

        // ── QUIC listener validation ─────────────────────────────────────────
        let quic_listen_addr: SocketAddr = self
            .quic
            .listen_addr
            .parse()
            .context("invalid quic.listen_addr")?;

        if self.quic.enabled {
            if self.quic.cert_path.is_none() {
                anyhow::bail!("quic.cert_path must be set when quic.enabled = true");
            }
            if self.quic.key_path.is_none() {
                anyhow::bail!("quic.key_path must be set when quic.enabled = true");
            }
            if quic_listen_addr == listen_addr {
                anyhow::bail!(
                    "quic.listen_addr ({}) conflicts with server.listen_addr — they must be different ports",
                    quic_listen_addr
                );
            }
            if self.tls.enabled && quic_listen_addr == tls_listen_addr {
                anyhow::bail!(
                    "quic.listen_addr ({}) conflicts with tls.listen_addr — same addr/port on UDP vs TCP is confusing, use different ports",
                    quic_listen_addr
                );
            }
            if quic_listen_addr == metrics_addr {
                anyhow::bail!(
                    "quic.listen_addr ({}) conflicts with metrics.listen_addr — they must be different ports",
                    quic_listen_addr
                );
            }
        }

        // ── Auth validation ──────────────────────────────────────────────────
        let require_client_auth = self.auth.require_client_auth;
        if require_client_auth && self.auth.client_vk_path.is_none() {
            anyhow::bail!(
                "[auth] require_client_auth = true but client_vk_path is not set. \
                 Configure [auth].client_vk_path or set require_client_auth = false to opt out."
            );
        }
        let client_auth_enabled = require_client_auth && self.auth.client_vk_path.is_some();
        if !client_auth_enabled {
            tracing::warn!(
                "client_auth_enabled=false: mutual authentication is disabled; \
                 any client can connect without a verifying key"
            );
        }
        let client_vk_path = self.auth.client_vk_path;

        // ── Admin PQC listener validation ────────────────────────────────────
        let admin_listen_addr: SocketAddr = self
            .admin
            .listen_addr
            .parse()
            .context("invalid admin.listen_addr")?;

        if self.admin.enabled {
            if self.admin.control_plane_vk_path.is_none() {
                anyhow::bail!(
                    "admin.control_plane_vk_path must be set when admin.enabled = true\n\
                     Hint: ejecuta `latticeshield-bridge admin-keygen ./keys` para generar las claves."
                );
            }
            if self.admin.rate_limit_per_second < 1 {
                anyhow::bail!(
                    "admin.rate_limit_per_second must be at least 1, got {}",
                    self.admin.rate_limit_per_second
                );
            }
            if self.admin.handshake_timeout_secs < 1 {
                anyhow::bail!(
                    "admin.handshake_timeout_secs must be at least 1, got {}",
                    self.admin.handshake_timeout_secs
                );
            }
            if admin_listen_addr == listen_addr {
                anyhow::bail!(
                    "admin.listen_addr ({}) conflicts with server.listen_addr — they must be different ports",
                    admin_listen_addr
                );
            }
            if admin_listen_addr == metrics_addr {
                anyhow::bail!(
                    "admin.listen_addr ({}) conflicts with metrics.listen_addr — they must be different ports",
                    admin_listen_addr
                );
            }
            if self.tls.enabled && admin_listen_addr == tls_listen_addr {
                anyhow::bail!(
                    "admin.listen_addr ({}) conflicts with tls.listen_addr — they must be different ports",
                    admin_listen_addr
                );
            }
            if self.quic.enabled && admin_listen_addr == quic_listen_addr {
                anyhow::bail!(
                    "admin.listen_addr ({}) conflicts with quic.listen_addr — they must be different ports",
                    admin_listen_addr
                );
            }
        }

        // ── WebSocket listener validation ────────────────────────────────────
        let ws_listen_addr: SocketAddr = self
            .websocket
            .listen_addr
            .parse()
            .context("invalid websocket.listen_addr")?;

        if self.websocket.enabled {
            if self.websocket.cert_path.is_none() {
                anyhow::bail!("websocket.cert_path must be set when websocket.enabled = true");
            }
            if self.websocket.key_path.is_none() {
                anyhow::bail!("websocket.key_path must be set when websocket.enabled = true");
            }
            if ws_listen_addr == listen_addr {
                anyhow::bail!(
                    "websocket.listen_addr ({}) conflicts with server.listen_addr — they must be different ports",
                    ws_listen_addr
                );
            }
            if ws_listen_addr == metrics_addr {
                anyhow::bail!(
                    "websocket.listen_addr ({}) conflicts with metrics.listen_addr — they must be different ports",
                    ws_listen_addr
                );
            }
            if self.tls.enabled && ws_listen_addr == tls_listen_addr {
                anyhow::bail!(
                    "websocket.listen_addr ({}) conflicts with tls.listen_addr — they must be different ports",
                    ws_listen_addr
                );
            }
            if self.quic.enabled && ws_listen_addr == quic_listen_addr {
                anyhow::bail!(
                    "websocket.listen_addr ({}) conflicts with quic.listen_addr — they must be different ports",
                    ws_listen_addr
                );
            }
            if self.admin.enabled && ws_listen_addr == admin_listen_addr {
                anyhow::bail!(
                    "websocket.listen_addr ({}) conflicts with admin.listen_addr — they must be different ports",
                    ws_listen_addr
                );
            }
            if self.websocket.allowed_origins.is_empty() {
                tracing::warn!(
                    "websocket.allowed_origins is empty — origin validation is disabled (development mode)"
                );
            }
        }

        // ── Parse ws_allowed_origins into NormalizedOrigin ───────────────────
        let ws_allowed_origins: Vec<crate::ws::NormalizedOrigin> = self
            .websocket
            .allowed_origins
            .iter()
            .map(|s| {
                crate::ws::NormalizedOrigin::parse(s).map_err(|e| {
                    anyhow::anyhow!("invalid websocket.allowed_origins entry {:?}: {}", s, e)
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        // ── VK-share token cap (SEC-H10-1c) ──────────────────────────────────
        let vk_share_max_tokens = match std::env::var("LATTICE_VK_TOKEN_MAX") {
            Ok(val) if !val.is_empty() => match val.parse::<usize>() {
                Ok(n) if n > 0 => n,
                Ok(_) => {
                    tracing::warn!(
                        "LATTICE_VK_TOKEN_MAX=0 is invalid — using default {}",
                        crate::vk_share::DEFAULT_TOKEN_MAX
                    );
                    crate::vk_share::DEFAULT_TOKEN_MAX
                }
                Err(_) => {
                    tracing::warn!(
                        "LATTICE_VK_TOKEN_MAX={:?} is not a valid usize — using default {}",
                        val,
                        crate::vk_share::DEFAULT_TOKEN_MAX
                    );
                    crate::vk_share::DEFAULT_TOKEN_MAX
                }
            },
            _ => crate::vk_share::DEFAULT_TOKEN_MAX,
        };

        // ── Graceful shutdown timeout ────────────────────────────────────────
        let shutdown_timeout_secs = std::env::var("SHUTDOWN_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);
        let shutdown_timeout = std::time::Duration::from_secs(shutdown_timeout_secs);

        Ok(ValidConfig {
            listen_addr,
            backend_addr,
            metrics_addr,
            max_frame_size: self.server.max_frame_size,
            handshake_timeout_secs: self.server.handshake_timeout_secs,
            max_connections_per_ip: self.server.max_connections_per_ip,
            signing_key_path: self.crypto.signing_key_path,
            log_level: self.logging.level,
            control_plane_enabled,
            control_plane_endpoint,
            control_plane_agent_name,
            heartbeat_interval,
            key_rotation_enabled: self.key_rotation.enabled,
            max_bytes_per_key: self.key_rotation.max_bytes_per_key,
            key_rotation_interval: std::time::Duration::from_secs(
                self.key_rotation.max_seconds_per_key,
            ),
            tls_enabled: self.tls.enabled,
            tls_listen_addr,
            tls_cert_path: self.tls.cert_path,
            tls_key_path: self.tls.key_path,
            quic_enabled: self.quic.enabled,
            quic_listen_addr,
            quic_cert_path: self.quic.cert_path.unwrap_or_default(),
            quic_key_path: self.quic.key_path.unwrap_or_default(),
            client_auth_enabled,
            client_vk_path,
            admin_enabled: self.admin.enabled,
            admin_listen_addr,
            admin_control_plane_vk_path: self.admin.control_plane_vk_path,
            admin_rate_limit_per_second: self.admin.rate_limit_per_second,
            admin_handshake_timeout_secs: self.admin.handshake_timeout_secs,
            control_plane_install_token,
            shutdown_timeout,
            ws_enabled: self.websocket.enabled,
            ws_listen_addr,
            ws_cert_path: self.websocket.cert_path.unwrap_or_default(),
            ws_key_path: self.websocket.key_path.unwrap_or_default(),
            ws_allowed_origins,
            ws_handshake_timeout_secs: self.websocket.handshake_timeout_secs,
            ws_max_connections_per_ip: self.websocket.max_connections_per_ip,
            vk_share_max_tokens,
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
        // Tests that don't set [auth] get require_client_auth = false automatically
        // so non-auth tests don't break due to the secure-by-default requirement.
        if !content.contains("[auth]") {
            f.write_all(b"[auth]\nrequire_client_auth = false\n\n")
                .unwrap();
        }
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
        assert_eq!(
            cfg.signing_key_path,
            PathBuf::from("/etc/latticeshield/server.sk")
        );
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

    // ── ControlPlane config tests ─────────────────────────────────────────────

    #[test]
    fn control_plane_defaults_when_section_absent() {
        let f = write_toml("");
        let cfg = Config::load(f.path()).unwrap();
        assert!(!cfg.control_plane_enabled);
        assert_eq!(cfg.control_plane_endpoint, "");
        assert_eq!(cfg.heartbeat_interval, std::time::Duration::from_secs(30));
    }

    #[test]
    fn control_plane_full_section_accepted() {
        let f = write_toml(
            "[control_plane]\nenabled = true\nendpoint = \"http://cp.example.com:9000\"\nagent_name = \"edge-01\"\nheartbeat_interval_secs = 60\n",
        );
        let cfg = Config::load(f.path()).unwrap();
        assert!(cfg.control_plane_enabled);
        assert_eq!(cfg.control_plane_endpoint, "http://cp.example.com:9000");
        assert_eq!(cfg.control_plane_agent_name, "edge-01");
        assert_eq!(cfg.heartbeat_interval, std::time::Duration::from_secs(60));
    }

    #[test]
    fn control_plane_enabled_empty_endpoint_rejected() {
        let f = write_toml("[control_plane]\nenabled = true\n");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("control_plane.endpoint"),
            "error should reference control_plane.endpoint, got: {err}"
        );
    }

    #[test]
    fn control_plane_enabled_malformed_url_rejected() {
        let f = write_toml("[control_plane]\nenabled = true\nendpoint = \"not a url\"\n");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("control_plane.endpoint"),
            "error should reference control_plane.endpoint, got: {err}"
        );
    }

    #[test]
    fn control_plane_disabled_non_empty_endpoint_accepted() {
        let f = write_toml("[control_plane]\nenabled = false\nendpoint = \"garbage string\"\n");
        // should NOT error even with garbage endpoint when disabled
        Config::load(f.path()).unwrap();
    }

    #[test]
    fn control_plane_heartbeat_interval_floored_at_5s() {
        let f = write_toml(
            "[control_plane]\nenabled = true\nendpoint = \"http://localhost:9000\"\nheartbeat_interval_secs = 2\n",
        );
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.heartbeat_interval, std::time::Duration::from_secs(5));
    }

    // ── KeyRotation config tests ──────────────────────────────────────────────

    #[test]
    fn key_rotation_defaults_when_section_absent() {
        let f = write_toml("");
        let cfg = Config::load(f.path()).unwrap();
        assert!(!cfg.key_rotation_enabled);
        assert_eq!(cfg.max_bytes_per_key, 10_737_418_240);
        assert_eq!(
            cfg.key_rotation_interval,
            std::time::Duration::from_secs(86_400)
        );
    }

    #[test]
    fn key_rotation_custom_values_accepted() {
        let f = write_toml(
            "[key_rotation]\nenabled = true\nmax_bytes_per_key = 1048576\nmax_seconds_per_key = 60\n",
        );
        let cfg = Config::load(f.path()).unwrap();
        assert!(cfg.key_rotation_enabled);
        assert_eq!(cfg.max_bytes_per_key, 1_048_576);
        assert_eq!(
            cfg.key_rotation_interval,
            std::time::Duration::from_secs(60)
        );
    }

    #[test]
    fn key_rotation_max_bytes_below_minimum_rejected() {
        let f = write_toml("[key_rotation]\nmax_bytes_per_key = 1000\n");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("max_bytes_per_key"),
            "error should reference max_bytes_per_key, got: {err}"
        );
    }

    #[test]
    fn key_rotation_max_seconds_below_minimum_rejected() {
        let f = write_toml("[key_rotation]\nmax_seconds_per_key = 30\n");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("max_seconds_per_key"),
            "error should reference max_seconds_per_key, got: {err}"
        );
    }

    // ── TlsConfig tests ──────────────────────────────────────────────────

    #[test]
    fn tls_disabled_by_default() {
        let f = write_toml("");
        let cfg = Config::load(f.path()).unwrap();
        assert!(!cfg.tls_enabled);
    }

    #[test]
    fn tls_enabled_empty_cert_path_rejected() {
        let f =
            write_toml("[tls]\nenabled = true\ncert_path = \"\"\nkey_path = \"./keys/tls.key\"\n");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("cert_path"), "got: {err}");
    }

    #[test]
    fn tls_enabled_empty_key_path_rejected() {
        let f =
            write_toml("[tls]\nenabled = true\ncert_path = \"./keys/tls.crt\"\nkey_path = \"\"\n");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("key_path"), "got: {err}");
    }

    #[test]
    fn tls_enabled_bad_listen_addr_rejected() {
        let f = write_toml("[tls]\nenabled = true\nlisten_addr = \"not_an_addr\"\n");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("tls.listen_addr"), "got: {err}");
    }

    #[test]
    fn tls_listen_addr_collides_with_pqc_rejected() {
        // default PQC is 0.0.0.0:8443; set TLS to the same
        let f = write_toml(
            "[tls]\nenabled = true\nlisten_addr = \"0.0.0.0:8443\"\ncert_path = \"./keys/tls.crt\"\nkey_path = \"./keys/tls.key\"\n"
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("conflicts"), "got: {err}");
    }

    #[test]
    fn tls_listen_addr_collides_with_metrics_rejected() {
        // default metrics is 0.0.0.0:8444; set TLS to the same
        let f = write_toml(
            "[tls]\nenabled = true\nlisten_addr = \"0.0.0.0:8444\"\ncert_path = \"./keys/tls.crt\"\nkey_path = \"./keys/tls.key\"\n"
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("conflicts"), "got: {err}");
    }

    #[test]
    fn tls_disabled_skips_path_and_cert_validation() {
        // cert/key paths are empty and files don't exist, but enabled = false → no error
        let f = write_toml("[tls]\nenabled = false\n");
        Config::load(f.path()).unwrap();
    }

    // ── QuicConfig tests ──────────────────────────────────────────────────

    #[test]
    fn quic_disabled_by_default() {
        let f = write_toml("");
        let cfg = Config::load(f.path()).unwrap();
        assert!(!cfg.quic_enabled);
        assert_eq!(cfg.quic_listen_addr.to_string(), "0.0.0.0:8441");
    }

    #[test]
    fn quic_section_parsed_from_toml() {
        let f = write_toml(
            "[quic]\nenabled = true\nlisten_addr = \"127.0.0.1:8441\"\ncert_path = \"./keys/tls.crt\"\nkey_path = \"./keys/tls.key\"\n"
        );
        let cfg = Config::load(f.path()).unwrap();
        assert!(cfg.quic_enabled);
        assert_eq!(cfg.quic_listen_addr.to_string(), "127.0.0.1:8441");
        assert_eq!(cfg.quic_cert_path, PathBuf::from("./keys/tls.crt"));
        assert_eq!(cfg.quic_key_path, PathBuf::from("./keys/tls.key"));
    }

    #[test]
    fn quic_enabled_missing_cert_path_rejected() {
        let f = write_toml("[quic]\nenabled = true\n");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("cert_path"),
            "expected cert_path in error, got: {err}"
        );
    }

    #[test]
    fn quic_enabled_missing_key_path_rejected() {
        let f = write_toml("[quic]\nenabled = true\ncert_path = \"./keys/tls.crt\"\n");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("key_path"),
            "expected key_path in error, got: {err}"
        );
    }

    #[test]
    fn quic_listen_addr_collides_with_pqc_rejected() {
        // default server.listen_addr is 0.0.0.0:8443
        let f = write_toml(
            "[quic]\nenabled = true\nlisten_addr = \"0.0.0.0:8443\"\ncert_path = \"./keys/tls.crt\"\nkey_path = \"./keys/tls.key\"\n"
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("conflicts"),
            "expected conflicts in error, got: {err}"
        );
    }

    #[test]
    fn quic_listen_addr_collides_with_tls_rejected() {
        // tls.listen_addr = 0.0.0.0:8440, quic.listen_addr = 0.0.0.0:8440
        let f = write_toml(
            "[tls]\nenabled = true\nlisten_addr = \"0.0.0.0:8440\"\ncert_path = \"./keys/tls.crt\"\nkey_path = \"./keys/tls.key\"\n\
             [quic]\nenabled = true\nlisten_addr = \"0.0.0.0:8440\"\ncert_path = \"./keys/tls.crt\"\nkey_path = \"./keys/tls.key\"\n"
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("conflicts"),
            "expected conflicts in error, got: {err}"
        );
    }

    #[test]
    fn quic_listen_addr_collides_with_metrics_rejected() {
        // default metrics is 0.0.0.0:8444
        let f = write_toml(
            "[quic]\nenabled = true\nlisten_addr = \"0.0.0.0:8444\"\ncert_path = \"./keys/tls.crt\"\nkey_path = \"./keys/tls.key\"\n"
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("conflicts"),
            "expected conflicts in error, got: {err}"
        );
    }

    #[test]
    fn quic_disabled_skips_cert_and_collision_validation() {
        // enabled=false, no cert_path, colliding addr → no error
        let f = write_toml("[quic]\nenabled = false\nlisten_addr = \"0.0.0.0:8443\"\n");
        Config::load(f.path()).unwrap();
    }

    // ── AuthConfig tests ──────────────────────────────────────────────────────

    #[test]
    fn auth_section_absent_errors_by_default() {
        // Bypass the write_toml helper (which disables auth) — write raw TOML to test
        // that a real deployment without any [auth] section errors on startup.
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"").unwrap();
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("require_client_auth"), "got: {err}");
        assert!(err.contains("client_vk_path"), "got: {err}");
    }

    #[test]
    fn auth_section_with_client_vk_path_enables_client_auth() {
        let f = write_toml("[auth]\nclient_vk_path = \"./keys/client.vk\"\n");
        let cfg = Config::load(f.path()).unwrap();
        assert!(cfg.client_auth_enabled);
        assert_eq!(cfg.client_vk_path, Some(PathBuf::from("./keys/client.vk")));
    }

    #[test]
    fn auth_opt_out_without_vk_path_gives_client_auth_disabled() {
        // Explicit require_client_auth = false → no error, auth disabled
        let f = write_toml("[auth]\nrequire_client_auth = false\n");
        let cfg = Config::load(f.path()).unwrap();
        assert!(!cfg.client_auth_enabled);
        assert!(cfg.client_vk_path.is_none());
    }

    #[test]
    fn auth_required_true_without_vk_path_errors() {
        let f = write_toml("[auth]\nrequire_client_auth = true\n");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("require_client_auth"), "got: {err}");
        assert!(err.contains("client_vk_path"), "got: {err}");
    }

    #[test]
    fn auth_required_false_with_vk_path_enables_auth() {
        // require_client_auth = false but VK provided — VK is ignored, auth disabled
        // (require_client_auth drives the outcome)
        let f = write_toml(
            "[auth]\nrequire_client_auth = false\nclient_vk_path = \"./keys/client.vk\"\n",
        );
        let cfg = Config::load(f.path()).unwrap();
        assert!(!cfg.client_auth_enabled);
    }

    // ── AdminConfig tests ─────────────────────────────────────────────────────

    #[test]
    fn admin_disabled_by_default() {
        let f = write_toml("");
        let cfg = Config::load(f.path()).unwrap();
        assert!(!cfg.admin_enabled);
        assert_eq!(cfg.admin_listen_addr.to_string(), "0.0.0.0:8445");
        assert_eq!(cfg.admin_rate_limit_per_second, 5);
        assert_eq!(cfg.admin_handshake_timeout_secs, 10);
        assert!(cfg.admin_control_plane_vk_path.is_none());
    }

    #[test]
    fn admin_enabled_all_fields_accepted() {
        let f = write_toml(
            r#"
[admin]
enabled = true
listen_addr = "0.0.0.0:8445"
control_plane_vk_path = "./keys/cp.vk"
rate_limit_per_second = 10
handshake_timeout_secs = 30
"#,
        );
        let cfg = Config::load(f.path()).unwrap();
        assert!(cfg.admin_enabled);
        assert_eq!(cfg.admin_listen_addr.to_string(), "0.0.0.0:8445");
        assert_eq!(
            cfg.admin_control_plane_vk_path,
            Some(PathBuf::from("./keys/cp.vk"))
        );
        assert_eq!(cfg.admin_rate_limit_per_second, 10);
        assert_eq!(cfg.admin_handshake_timeout_secs, 30);
    }

    #[test]
    fn admin_enabled_missing_vk_path_rejected() {
        let f = write_toml("[admin]\nenabled = true\n");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("control_plane_vk_path"), "got: {err}");
    }

    #[test]
    fn admin_listen_addr_collides_with_pqc_rejected() {
        let f = write_toml(
            "[admin]\nenabled = true\nlisten_addr = \"0.0.0.0:8443\"\ncontrol_plane_vk_path = \"./keys/cp.vk\"\n",
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("conflicts"), "got: {err}");
    }

    #[test]
    fn admin_listen_addr_collides_with_metrics_rejected() {
        let f = write_toml(
            "[admin]\nenabled = true\nlisten_addr = \"0.0.0.0:8444\"\ncontrol_plane_vk_path = \"./keys/cp.vk\"\n",
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("conflicts"), "got: {err}");
    }

    #[test]
    fn admin_handshake_timeout_zero_rejected() {
        let f = write_toml(
            "[admin]\nenabled = true\ncontrol_plane_vk_path = \"./keys/cp.vk\"\nhandshake_timeout_secs = 0\n",
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("handshake_timeout_secs"), "got: {err}");
    }

    #[test]
    fn admin_rate_limit_zero_rejected() {
        let f = write_toml(
            "[admin]\nenabled = true\ncontrol_plane_vk_path = \"./keys/cp.vk\"\nrate_limit_per_second = 0\n",
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("rate_limit_per_second"), "got: {err}");
    }

    // ── install_token tests ───────────────────────────────────────────────────
    // All env-var resolution cases are combined into one test to guarantee
    // sequential execution. std::env is process-global; parallel tests that
    // set/unset INSTALL_TOKEN race even with a mutex in some test harness
    // configurations.

    #[test]
    fn install_token_env_var_resolution() {
        // Case 1: TOML field accepted when env var absent
        std::env::remove_var("INSTALL_TOKEN");
        let f = write_toml("[control_plane]\ninstall_token = \"toml-token\"\n");
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(
            cfg.control_plane_install_token,
            Some("toml-token".to_string()),
            "TOML install_token should be loaded into ValidConfig"
        );

        // Case 2: env var takes precedence over TOML
        std::env::set_var("INSTALL_TOKEN", "env-token");
        let f = write_toml("[control_plane]\ninstall_token = \"toml-token\"\n");
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(
            cfg.control_plane_install_token,
            Some("env-token".to_string()),
            "env var INSTALL_TOKEN must take precedence over TOML install_token"
        );

        // Case 3: empty env var treated as absent — TOML value used
        std::env::set_var("INSTALL_TOKEN", "");
        let f = write_toml("[control_plane]\ninstall_token = \"toml-token\"\n");
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(
            cfg.control_plane_install_token,
            Some("toml-token".to_string()),
            "empty INSTALL_TOKEN env var should fall back to TOML value"
        );

        // Case 4: None when neither TOML nor env var is set
        std::env::remove_var("INSTALL_TOKEN");
        let f = write_toml("[control_plane]\n");
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(
            cfg.control_plane_install_token, None,
            "control_plane_install_token should be None when neither TOML nor env var is set"
        );

        // Case 5: control_plane.enabled = true with no install_token is non-fatal (warn only)
        std::env::remove_var("INSTALL_TOKEN");
        let f =
            write_toml("[control_plane]\nenabled = true\nendpoint = \"http://localhost:9000\"\n");
        let cfg = Config::load(f.path()).unwrap();
        assert!(cfg.control_plane_enabled);
        assert_eq!(cfg.control_plane_install_token, None);

        // Cleanup
        std::env::remove_var("INSTALL_TOKEN");
    }

    #[test]
    fn valid_config_debug_redacts_install_token() {
        // Build a minimal ValidConfig with a known token value
        let cfg = ValidConfig {
            listen_addr: "127.0.0.1:8443".parse().unwrap(),
            backend_addr: "127.0.0.1:8080".parse().unwrap(),
            metrics_addr: "127.0.0.1:8444".parse().unwrap(),
            max_frame_size: 65536,
            handshake_timeout_secs: 10,
            max_connections_per_ip: 50,
            signing_key_path: PathBuf::from("./keys/server.sk"),
            log_level: "info".to_string(),
            control_plane_enabled: false,
            control_plane_endpoint: String::new(),
            control_plane_agent_name: String::new(),
            heartbeat_interval: std::time::Duration::from_secs(30),
            key_rotation_enabled: false,
            max_bytes_per_key: 10_737_418_240,
            key_rotation_interval: std::time::Duration::from_secs(86_400),
            tls_enabled: false,
            tls_listen_addr: "127.0.0.1:8440".parse().unwrap(),
            tls_cert_path: PathBuf::from("./keys/tls.crt"),
            tls_key_path: PathBuf::from("./keys/tls.key"),
            quic_enabled: false,
            quic_listen_addr: "127.0.0.1:8441".parse().unwrap(),
            quic_cert_path: PathBuf::from("./keys/tls.crt"),
            quic_key_path: PathBuf::from("./keys/tls.key"),
            client_auth_enabled: false,
            client_vk_path: None,
            admin_enabled: false,
            admin_listen_addr: "127.0.0.1:8445".parse().unwrap(),
            admin_control_plane_vk_path: None,
            admin_rate_limit_per_second: 5,
            admin_handshake_timeout_secs: 10,
            control_plane_install_token: Some("super-secret-value".to_string()),
            shutdown_timeout: std::time::Duration::from_secs(30),
            ws_enabled: false,
            ws_listen_addr: "127.0.0.1:8446".parse().unwrap(),
            ws_cert_path: PathBuf::from("./keys/ws.crt"),
            ws_key_path: PathBuf::from("./keys/ws.key"),
            ws_allowed_origins: Vec::new(),
            ws_handshake_timeout_secs: 10,
            ws_max_connections_per_ip: 100,
            vk_share_max_tokens: 1000,
        };

        let debug_str = format!("{cfg:?}");
        assert!(
            !debug_str.contains("super-secret-value"),
            "Debug output must NOT contain the raw token value, got: {debug_str}"
        );
        assert!(
            debug_str.contains("[REDACTED]"),
            "Debug output must contain '[REDACTED]', got: {debug_str}"
        );
    }

    // ── WsConfig tests ────────────────────────────────────────────────────────

    #[test]
    fn ws_disabled_by_default() {
        let f = write_toml("");
        let cfg = Config::load(f.path()).unwrap();
        assert!(!cfg.ws_enabled);
        assert_eq!(cfg.ws_listen_addr.to_string(), "0.0.0.0:8446");
        assert_eq!(cfg.ws_handshake_timeout_secs, 10);
        assert_eq!(cfg.ws_max_connections_per_ip, 100);
        assert!(cfg.ws_allowed_origins.is_empty());
    }

    #[test]
    fn ws_section_parsed_from_toml() {
        let f = write_toml(
            r#"
[websocket]
enabled = true
listen_addr = "127.0.0.1:8446"
cert_path = "./keys/ws.crt"
key_path = "./keys/ws.key"
allowed_origins = ["https://app.example.com"]
handshake_timeout_secs = 20
max_connections_per_ip = 50
"#,
        );
        let cfg = Config::load(f.path()).unwrap();
        assert!(cfg.ws_enabled);
        assert_eq!(cfg.ws_listen_addr.to_string(), "127.0.0.1:8446");
        assert_eq!(cfg.ws_cert_path, PathBuf::from("./keys/ws.crt"));
        assert_eq!(cfg.ws_key_path, PathBuf::from("./keys/ws.key"));
        assert_eq!(cfg.ws_allowed_origins.len(), 1);
        assert_eq!(
            cfg.ws_allowed_origins[0].as_str(),
            "https://app.example.com:443"
        );
        assert_eq!(cfg.ws_handshake_timeout_secs, 20);
        assert_eq!(cfg.ws_max_connections_per_ip, 50);
    }

    #[test]
    fn ws_enabled_missing_cert_path_rejected() {
        let f = write_toml("[websocket]\nenabled = true\nkey_path = \"./keys/ws.key\"\n");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("cert_path"),
            "expected cert_path in error, got: {err}"
        );
    }

    #[test]
    fn ws_enabled_missing_key_path_rejected() {
        let f = write_toml("[websocket]\nenabled = true\ncert_path = \"./keys/ws.crt\"\n");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("key_path"),
            "expected key_path in error, got: {err}"
        );
    }

    #[test]
    fn ws_listen_addr_collides_with_pqc_rejected() {
        // default server.listen_addr is 0.0.0.0:8443
        let f = write_toml(
            "[websocket]\nenabled = true\nlisten_addr = \"0.0.0.0:8443\"\ncert_path = \"./keys/ws.crt\"\nkey_path = \"./keys/ws.key\"\n",
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("conflicts"), "expected conflicts, got: {err}");
    }

    #[test]
    fn ws_listen_addr_collides_with_metrics_rejected() {
        // default metrics is 0.0.0.0:8444
        let f = write_toml(
            "[websocket]\nenabled = true\nlisten_addr = \"0.0.0.0:8444\"\ncert_path = \"./keys/ws.crt\"\nkey_path = \"./keys/ws.key\"\n",
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("conflicts"), "expected conflicts, got: {err}");
    }

    #[test]
    fn ws_listen_addr_collides_with_tls_rejected() {
        let f = write_toml(
            "[tls]\nenabled = true\nlisten_addr = \"0.0.0.0:8440\"\ncert_path = \"./keys/tls.crt\"\nkey_path = \"./keys/tls.key\"\n\
             [websocket]\nenabled = true\nlisten_addr = \"0.0.0.0:8440\"\ncert_path = \"./keys/ws.crt\"\nkey_path = \"./keys/ws.key\"\n",
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("conflicts"), "expected conflicts, got: {err}");
    }

    #[test]
    fn ws_listen_addr_collides_with_admin_rejected() {
        let f = write_toml(
            "[admin]\nenabled = true\nlisten_addr = \"0.0.0.0:8445\"\ncontrol_plane_vk_path = \"./keys/cp.vk\"\n\
             [websocket]\nenabled = true\nlisten_addr = \"0.0.0.0:8445\"\ncert_path = \"./keys/ws.crt\"\nkey_path = \"./keys/ws.key\"\n",
        );
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("conflicts"), "expected conflicts, got: {err}");
    }

    #[test]
    fn ws_disabled_skips_cert_and_collision_validation() {
        // enabled=false with colliding addr and no cert → no error
        let f = write_toml("[websocket]\nenabled = false\nlisten_addr = \"0.0.0.0:8443\"\n");
        Config::load(f.path()).unwrap();
    }

    // ── handshake_timeout_secs + max_connections_per_ip tests (SEC-OBS3/OBS4) ──

    #[test]
    fn tcp_handshake_timeout_default_is_10() {
        let f = write_toml("[server]\n");
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(
            cfg.handshake_timeout_secs, 10,
            "server.handshake_timeout_secs default must be 10"
        );
    }

    #[test]
    fn tcp_handshake_timeout_custom_accepted() {
        let f = write_toml("[server]\nhandshake_timeout_secs = 30\n");
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.handshake_timeout_secs, 30);
    }

    #[test]
    fn tcp_handshake_timeout_zero_rejected() {
        let f = write_toml("[server]\nhandshake_timeout_secs = 0\n");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("handshake_timeout_secs"),
            "error should reference handshake_timeout_secs, got: {err}"
        );
    }

    #[test]
    fn tcp_max_connections_per_ip_default_is_50() {
        let f = write_toml("[server]\n");
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(
            cfg.max_connections_per_ip, 50,
            "server.max_connections_per_ip default must be 50"
        );
    }

    #[test]
    fn tcp_max_connections_per_ip_zero_rejected() {
        let f = write_toml("[server]\nmax_connections_per_ip = 0\n");
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("max_connections_per_ip"),
            "error should reference max_connections_per_ip, got: {err}"
        );
    }

    // ── shutdown_timeout env-var tests ────────────────────────────────────────
    // Combined into one test to avoid parallel env-var race conditions.
    // std::env is process-global; parallel tests that set/unset SHUTDOWN_TIMEOUT_SECS
    // race even with a mutex in some test harness configurations.
    #[test]
    fn shutdown_timeout_env_var_resolution() {
        // Case 1: default is 30s when env var absent
        std::env::remove_var("SHUTDOWN_TIMEOUT_SECS");
        let f = write_toml("");
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(
            cfg.shutdown_timeout,
            std::time::Duration::from_secs(30),
            "shutdown_timeout default must be 30s"
        );

        // Case 2: env var overrides default
        std::env::set_var("SHUTDOWN_TIMEOUT_SECS", "60");
        let f = write_toml("");
        let cfg = Config::load(f.path()).unwrap();
        std::env::remove_var("SHUTDOWN_TIMEOUT_SECS");
        assert_eq!(
            cfg.shutdown_timeout,
            std::time::Duration::from_secs(60),
            "shutdown_timeout must be 60s when SHUTDOWN_TIMEOUT_SECS=60"
        );
    }
}
