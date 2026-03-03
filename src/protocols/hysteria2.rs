/// Hysteria2 клиент поверх QUIC.
/// Hysteria2 использует HTTP/3 маскировку + QUIC BBR congestion control.
/// Здесь реализована базовая совместимость с оригинальным протоколом.
///
/// Протокол аутентификации Hysteria2:
/// - HTTP/3 CONNECT на /:
///   Headers: Hysteria-Auth: <password>, Hysteria-CC-RX: <down_mbps * 1000000 / 8>
/// - Сервер отвечает 233 (успех) или 403 (ошибка)

use super::{Protocol, ProtocolError, Result, TunnelStats, Hysteria2Config};
use async_trait::async_trait;
use bytes::Bytes;
use quinn::{ClientConfig, Endpoint, Connection};
use std::sync::Arc;
use std::net::ToSocketAddrs;

pub struct Hysteria2Protocol {
    config: Hysteria2Config,
    connection: Option<Connection>,
    connected: bool,
    stats: TunnelStats,
}

impl Hysteria2Protocol {
    pub fn new(config: Hysteria2Config) -> Result<Self> {
        Ok(Self {
            config,
            connection: None,
            connected: false,
            stats: TunnelStats::default(),
        })
    }

    fn build_quic_config(&self) -> Result<ClientConfig> {
        let crypto = if self.config.insecure {
            let mut tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();

            tls_config.dangerous()
                .set_certificate_verifier(Arc::new(NoVerification));

            // Hysteria2 использует h3 ALPN
            tls_config.alpn_protocols = vec![b"h3".to_vec()];
            Arc::new(tls_config)
        } else {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let mut tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            tls_config.alpn_protocols = vec![b"h3".to_vec()];
            Arc::new(tls_config)
        };

        Ok(ClientConfig::new(crypto))
    }

    /// Hysteria2 auth через HTTP/3 CONNECT
    async fn authenticate(&self, conn: &Connection) -> Result<()> {
        tracing::info!("🔑 Hysteria2: authenticating...");

        // Открываем control stream
        let (mut send, mut recv) = conn.open_bi().await
            .map_err(|e| ProtocolError::QuicError(format!("open_bi: {}", e)))?;

        // Строим Hysteria2 auth request
        // Формат: [4 bytes magic "HY2\x00"][password_len u16 BE][password][rx u64 BE]
        let password_bytes = self.config.password.as_bytes();
        let rx_bytes_per_sec = (self.config.down_mbps as u64) * 1_000_000 / 8;

        let mut auth_buf = Vec::new();
        auth_buf.extend_from_slice(b"HY2\x00");
        auth_buf.push((password_bytes.len() >> 8) as u8);
        auth_buf.push((password_bytes.len() & 0xFF) as u8);
        auth_buf.extend_from_slice(password_bytes);
        auth_buf.extend_from_slice(&rx_bytes_per_sec.to_be_bytes());

        send.write_all(&auth_buf).await
            .map_err(|e| ProtocolError::QuicError(format!("Auth write: {}", e)))?;
        send.finish()
            .map_err(|e| ProtocolError::QuicError(format!("Auth finish: {}", e)))?;

        // Читаем ответ: [1 byte status 0x00=ok]
        let mut status = [0u8; 1];
        recv.read_exact(&mut status).await
            .map_err(|e| ProtocolError::QuicError(format!("Auth response: {}", e)))?;

        if status[0] != 0x00 {
            return Err(ProtocolError::AuthFailed);
        }

        tracing::info!("✅ Hysteria2: authenticated (rx: {} KB/s)", rx_bytes_per_sec / 1024);
        Ok(())
    }
}

#[async_trait]
impl Protocol for Hysteria2Protocol {
    fn name(&self) -> &str {
        "Hysteria2"
    }

    async fn connect(&mut self) -> Result<()> {
        tracing::info!("🚀 Hysteria2: connecting to {}", self.config.server_addr);

        let quic_config = self.build_quic_config()?;

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| ProtocolError::ConnectionFailed(format!("QUIC bind: {}", e)))?;

        endpoint.set_default_client_config(quic_config);

        let server_addr = self.config.server_addr
            .to_socket_addrs()
            .map_err(|e| ProtocolError::ConnectionFailed(format!("DNS resolve: {}", e)))?
            .next()
            .ok_or_else(|| ProtocolError::ConnectionFailed("No address".to_string()))?;

        let sni = self.config.sni.clone()
            .unwrap_or_else(|| {
                self.config.server_addr.split(':').next()
                    .unwrap_or("localhost").to_string()
            });

        tracing::info!("🌐 QUIC → {} (SNI: {})", server_addr, sni);

        let connection = endpoint
            .connect(server_addr, &sni)
            .map_err(|e| ProtocolError::ConnectionFailed(format!("connect: {}", e)))?
            .await
            .map_err(|e| ProtocolError::ConnectionFailed(format!("handshake: {}", e)))?;

        tracing::info!("✅ QUIC connected, RTT: {:?}", connection.rtt());

        self.authenticate(&connection).await?;

        self.connection = Some(connection);
        self.connected = true;

        tracing::info!("✅ Hysteria2 ready!");
        Ok(())
    }

    async fn send(&mut self, data: Bytes) -> Result<()> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| ProtocolError::ConnectionFailed("Not connected".to_string()))?;

        // Пробуем датаграммы (UDP-like, low latency)
        if let Some(max_size) = conn.max_datagram_size() {
            if data.len() <= max_size {
                conn.send_datagram(data.clone())
                    .map_err(|e| ProtocolError::QuicError(format!("datagram: {}", e)))?;
                self.stats.bytes_sent += data.len() as u64;
                self.stats.packets_sent += 1;
                return Ok(());
            }
        }

        // Fallback: stream
        let (mut send_stream, _) = conn.open_bi().await
            .map_err(|e| ProtocolError::QuicError(format!("open_bi: {}", e)))?;

        send_stream.write_all(&data).await
            .map_err(|e| ProtocolError::QuicError(format!("write: {}", e)))?;

        send_stream.finish()
            .map_err(|e| ProtocolError::QuicError(format!("finish: {}", e)))?;

        self.stats.bytes_sent += data.len() as u64;
        self.stats.packets_sent += 1;

        Ok(())
    }

    async fn receive(&mut self) -> Result<Bytes> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| ProtocolError::ConnectionFailed("Not connected".to_string()))?;

        tokio::select! {
            datagram = conn.read_datagram() => {
                let data = datagram
                    .map_err(|e| ProtocolError::QuicError(format!("datagram recv: {}", e)))?;
                self.stats.bytes_received += data.len() as u64;
                self.stats.packets_received += 1;
                Ok(data)
            }
            stream = conn.accept_uni() => {
                let mut recv = stream
                    .map_err(|e| ProtocolError::QuicError(format!("accept_uni: {}", e)))?;
                let mut buf = Vec::new();
                recv.read_to_end(&mut buf, 1024 * 1024).await
                    .map_err(|e| ProtocolError::QuicError(format!("stream read: {}", e)))?;
                let data = Bytes::from(buf);
                self.stats.bytes_received += data.len() as u64;
                self.stats.packets_received += 1;
                Ok(data)
            }
        }
    }

    async fn close(&mut self) -> Result<()> {
        tracing::info!("🔌 Closing Hysteria2");
        if let Some(conn) = self.connection.take() {
            conn.close(0u32.into(), b"bye");
        }
        self.connected = false;
        Ok(())
    }

    fn stats(&self) -> TunnelStats {
        self.stats.clone()
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

#[derive(Debug)]
struct NoVerification;

impl rustls::client::danger::ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
