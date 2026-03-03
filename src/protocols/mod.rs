use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;

pub mod wireguard;
pub mod hysteria2;
pub mod fluxtunnel;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("QUIC error: {0}")]
    QuicError(String),
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TunnelStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

/// Конфигурация для FluxTunnel — собственного протокола поверх QUIC
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FluxTunnelConfig {
    /// Адрес сервера FluxTunnel (ip:port)
    pub server_addr: String,
    /// Пароль / pre-shared key (будет использоваться в HKDF для генерации ключей)
    pub password: String,
    /// SNI для TLS
    pub sni: Option<String>,
    /// Пропускать проверку TLS сертификата (для self-signed)
    pub insecure: bool,
    /// Лимит пропускной способности вверх, Mbps (0 = без лимита, как в Hysteria2)
    pub up_mbps: u32,
    /// Лимит пропускной способности вниз, Mbps
    pub down_mbps: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WireGuardConfig {
    pub private_key: String,
    pub server_public_key: String,
    pub server_addr: String,
    pub local_ip: String,
    /// DNS для тоннеля
    pub dns: Option<Vec<String>>,
    /// MTU (по умолчанию 1420)
    pub mtu: Option<u16>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Hysteria2Config {
    pub server_addr: String,
    pub password: String,
    pub sni: Option<String>,
    pub insecure: bool,
    pub up_mbps: u32,
    pub down_mbps: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProtocolConfig {
    WireGuard(WireGuardConfig),
    Hysteria2(Hysteria2Config),
    FluxTunnel(FluxTunnelConfig),
}

#[async_trait]
pub trait Protocol: Send + Sync {
    fn name(&self) -> &str;
    async fn connect(&mut self) -> Result<()>;
    async fn send(&mut self, data: Bytes) -> Result<()>;
    async fn receive(&mut self) -> Result<Bytes>;
    async fn close(&mut self) -> Result<()>;
    fn stats(&self) -> TunnelStats;
    fn is_connected(&self) -> bool;
}

pub fn create_protocol(config: ProtocolConfig) -> Result<Box<dyn Protocol>> {
    match config {
        ProtocolConfig::WireGuard(cfg) => {
            Ok(Box::new(wireguard::WireGuardProtocol::new(cfg)?))
        }
        ProtocolConfig::Hysteria2(cfg) => {
            Ok(Box::new(hysteria2::Hysteria2Protocol::new(cfg)?))
        }
        ProtocolConfig::FluxTunnel(cfg) => {
            Ok(Box::new(fluxtunnel::FluxTunnelProtocol::new(cfg)?))
        }
    }
}
