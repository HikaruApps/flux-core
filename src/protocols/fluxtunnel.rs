/// FluxTunnel — собственный протокол поверх QUIC.
///
/// Архитектура:
/// - Транспорт: QUIC (quinn)
/// - Аутентификация: HKDF из пароля + случайный nonce (отправляется в первом стриме)
/// - Шифрование данных: обеспечивается TLS 1.3 самим QUIC, дополнительного слоя нет
/// - Мультиплексирование: каждый проксируемый поток = отдельный QUIC stream
/// - UDP: QUIC datagrams (unreliable, низкая латентность)
/// - Управление потоком: встроенное в QUIC
///
/// Формат AUTH фрейма (первый bidirectional stream):
///   [1 byte version=0x01][32 bytes nonce][32 bytes HMAC-SHA256(password, nonce)]
///
/// Формат PROXY REQUEST фрейма (каждый новый stream):
///   [1 byte cmd: 0x01=TCP 0x03=UDP][1 byte addr_type: 0x01=IPv4 0x03=IPv6 0x02=domain]
///   [addr bytes][2 bytes port BE]
///
/// Формат PROXY RESPONSE:
///   [1 byte status: 0x00=ok 0x01=err][1 byte msg_len][msg bytes]

use super::{Protocol, ProtocolError, Result, TunnelStats, FluxTunnelConfig};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut, BufMut};
use quinn::{ClientConfig, Endpoint, Connection};
use rustls::pki_types::ServerName;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use rand::RngCore;
use std::sync::Arc;
use std::net::ToSocketAddrs;

type HmacSha256 = Hmac<Sha256>;

// Версия протокола
const FLUX_VERSION: u8 = 0x01;

// Команды
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x03;

// Типы адресов
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

pub struct FluxTunnelProtocol {
    config: FluxTunnelConfig,
    connection: Option<Connection>,
    connected: bool,
    stats: TunnelStats,
    /// Производный ключ из пароля (используется для HMAC auth)
    derived_key: [u8; 32],
}

impl FluxTunnelProtocol {
    pub fn new(config: FluxTunnelConfig) -> Result<Self> {
        // Сразу дериворуем ключ из пароля через HKDF
        let hkdf = Hkdf::<Sha256>::new(
            Some(b"flux-tunnel-v1"),
            config.password.as_bytes(),
        );
        let mut derived_key = [0u8; 32];
        hkdf.expand(b"auth-key", &mut derived_key)
            .map_err(|_| ProtocolError::ProtocolError("HKDF expand failed".to_string()))?;

        Ok(Self {
            config,
            connection: None,
            connected: false,
            stats: TunnelStats::default(),
            derived_key,
        })
    }

    /// Строим QUIC ClientConfig
    fn build_quic_config(&self) -> Result<ClientConfig> {
        let crypto = if self.config.insecure {
            // Self-signed / любой сертификат
            let mut tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();

            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerification));

            // ALPN — идентификатор нашего протокола
            tls_config.alpn_protocols = vec![b"flux/1".to_vec()];

            Arc::new(tls_config)
        } else {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let mut tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            tls_config.alpn_protocols = vec![b"flux/1".to_vec()];

            Arc::new(tls_config)
        };

        Ok(ClientConfig::new(crypto))
    }

    /// Отправляем AUTH фрейм на отдельном stream
    async fn authenticate(&self, conn: &Connection) -> Result<()> {
        tracing::info!("🔑 FluxTunnel: authenticating...");

        let (mut send, mut recv) = conn.open_bi().await
            .map_err(|e| ProtocolError::QuicError(format!("open_bi failed: {}", e)))?;

        // Генерируем nonce
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        // HMAC-SHA256(derived_key, nonce)
        let mut mac = HmacSha256::new_from_slice(&self.derived_key)
            .map_err(|e| ProtocolError::ProtocolError(e.to_string()))?;
        mac.update(&nonce);
        let mac_bytes = mac.finalize().into_bytes();

        // Собираем AUTH фрейм: [version][nonce][hmac]
        let mut auth_frame = BytesMut::with_capacity(65);
        auth_frame.put_u8(FLUX_VERSION);
        auth_frame.put_slice(&nonce);
        auth_frame.put_slice(&mac_bytes);

        send.write_all(&auth_frame).await
            .map_err(|e| ProtocolError::QuicError(format!("Auth send failed: {}", e)))?;
        send.finish()
            .map_err(|e| ProtocolError::QuicError(format!("Auth finish failed: {}", e)))?;

        // Читаем ответ: [status][msg_len][msg]
        let mut status = [0u8; 1];
        recv.read_exact(&mut status).await
            .map_err(|e| ProtocolError::QuicError(format!("Auth response read failed: {}", e)))?;

        if status[0] != 0x00 {
            let mut msg_len = [0u8; 1];
            recv.read_exact(&mut msg_len).await.ok();
            let mut msg = vec![0u8; msg_len[0] as usize];
            recv.read_exact(&mut msg).await.ok();
            let msg_str = String::from_utf8_lossy(&msg).to_string();
            return Err(ProtocolError::AuthFailed);
        }

        tracing::info!("✅ FluxTunnel: authenticated!");
        Ok(())
    }

    /// Строим PROXY REQUEST фрейм
    fn build_proxy_request(cmd: u8, target_addr: &str, target_port: u16) -> Result<Bytes> {
        let mut frame = BytesMut::new();
        frame.put_u8(cmd);

        // Определяем тип адреса
        if let Ok(_) = target_addr.parse::<std::net::Ipv4Addr>() {
            frame.put_u8(ATYP_IPV4);
            let ip: std::net::Ipv4Addr = target_addr.parse().unwrap();
            frame.put_slice(&ip.octets());
        } else if let Ok(_) = target_addr.parse::<std::net::Ipv6Addr>() {
            frame.put_u8(ATYP_IPV6);
            let ip: std::net::Ipv6Addr = target_addr.parse().unwrap();
            frame.put_slice(&ip.octets());
        } else {
            // Доменное имя
            frame.put_u8(ATYP_DOMAIN);
            let domain_bytes = target_addr.as_bytes();
            if domain_bytes.len() > 255 {
                return Err(ProtocolError::ProtocolError("Domain too long".to_string()));
            }
            frame.put_u8(domain_bytes.len() as u8);
            frame.put_slice(domain_bytes);
        }

        frame.put_u16(target_port);
        Ok(frame.freeze())
    }
}

#[async_trait]
impl Protocol for FluxTunnelProtocol {
    fn name(&self) -> &str {
        "FluxTunnel"
    }

    async fn connect(&mut self) -> Result<()> {
        tracing::info!("⚡ FluxTunnel: connecting to {}", self.config.server_addr);

        let quic_config = self.build_quic_config()?;

        // Биндим локальный QUIC endpoint
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| ProtocolError::ConnectionFailed(format!("QUIC endpoint bind failed: {}", e)))?;

        endpoint.set_default_client_config(quic_config);

        // Резолвим адрес сервера
        let server_sockaddr = self.config.server_addr
            .to_socket_addrs()
            .map_err(|e| ProtocolError::ConnectionFailed(format!("DNS resolve failed: {}", e)))?
            .next()
            .ok_or_else(|| ProtocolError::ConnectionFailed("No address resolved".to_string()))?;

        let sni = self.config.sni.clone()
            .unwrap_or_else(|| {
                // Берём hostname из server_addr если SNI не задан
                self.config.server_addr
                    .split(':')
                    .next()
                    .unwrap_or("localhost")
                    .to_string()
            });

        tracing::info!("🌐 QUIC connecting to {} (SNI: {})", server_sockaddr, sni);

        let connection = endpoint
            .connect(server_sockaddr, &sni)
            .map_err(|e| ProtocolError::ConnectionFailed(format!("QUIC connect failed: {}", e)))?
            .await
            .map_err(|e| ProtocolError::ConnectionFailed(format!("QUIC handshake failed: {}", e)))?;

        tracing::info!("✅ QUIC connected! RTT: {:?}", connection.rtt());

        // Аутентификация
        self.authenticate(&connection).await?;

        self.connection = Some(connection);
        self.connected = true;

        tracing::info!("✅ FluxTunnel ready!");
        Ok(())
    }

    /// send() открывает новый QUIC stream для каждого запроса.
    /// Формат data: [proxy_request_frame][payload]
    /// Для реального использования нужен отдельный метод open_tcp_stream / open_udp_stream,
    /// но для совместимости с трейтом Protocol пакуем всё сюда.
    async fn send(&mut self, data: Bytes) -> Result<()> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| ProtocolError::ConnectionFailed("Not connected".to_string()))?;

        // Используем QUIC datagrams для максимальной скорости (UDP семантика)
        // Для надёжной доставки (TCP семантика) — открываем stream
        let max_datagram = conn.max_datagram_size();

        if let Some(max_size) = max_datagram {
            if data.len() <= max_size {
                conn.send_datagram(data.clone())
                    .map_err(|e| ProtocolError::QuicError(format!("Datagram send failed: {}", e)))?;
                self.stats.bytes_sent += data.len() as u64;
                self.stats.packets_sent += 1;
                tracing::debug!("📤 FluxTunnel datagram {} bytes", data.len());
                return Ok(());
            }
        }

        // Данные > max datagram size — используем stream
        let (mut send_stream, _recv_stream) = conn.open_bi().await
            .map_err(|e| ProtocolError::QuicError(format!("open_bi failed: {}", e)))?;

        send_stream.write_all(&data).await
            .map_err(|e| ProtocolError::QuicError(format!("Stream write failed: {}", e)))?;

        send_stream.finish()
            .map_err(|e| ProtocolError::QuicError(format!("Stream finish failed: {}", e)))?;

        self.stats.bytes_sent += data.len() as u64;
        self.stats.packets_sent += 1;
        tracing::debug!("📤 FluxTunnel stream {} bytes", data.len());

        Ok(())
    }

    async fn receive(&mut self) -> Result<Bytes> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| ProtocolError::ConnectionFailed("Not connected".to_string()))?;

        // Пробуем сначала получить datagram (UDP)
        tokio::select! {
            datagram = conn.read_datagram() => {
                match datagram {
                    Ok(data) => {
                        self.stats.bytes_received += data.len() as u64;
                        self.stats.packets_received += 1;
                        tracing::debug!("📥 FluxTunnel datagram {} bytes", data.len());
                        Ok(data)
                    }
                    Err(e) => Err(ProtocolError::QuicError(format!("Datagram recv failed: {}", e)))
                }
            }
            stream = conn.accept_uni() => {
                match stream {
                    Ok(mut recv_stream) => {
                        let mut buf = Vec::new();
                        recv_stream.read_to_end(&mut buf, 1024 * 1024).await // max 1MB
                            .map_err(|e| ProtocolError::QuicError(format!("Stream read failed: {}", e)))?;
                        let data = Bytes::from(buf);
                        self.stats.bytes_received += data.len() as u64;
                        self.stats.packets_received += 1;
                        tracing::debug!("📥 FluxTunnel stream {} bytes", data.len());
                        Ok(data)
                    }
                    Err(e) => Err(ProtocolError::QuicError(format!("accept_uni failed: {}", e)))
                }
            }
        }
    }

    async fn close(&mut self) -> Result<()> {
        tracing::info!("🔌 Closing FluxTunnel");
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

/// Вспомогательная функция для открытия проксируемого TCP стрима
/// (используется во внешнем прокси-сервере, не в трейте Protocol)
pub async fn open_tcp_proxy_stream(
    conn: &Connection,
    target_host: &str,
    target_port: u16,
) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, recv) = conn.open_bi().await
        .map_err(|e| ProtocolError::QuicError(format!("open_bi: {}", e)))?;

    let req = FluxTunnelProtocol::build_proxy_request(CMD_TCP, target_host, target_port)?;
    send.write_all(&req).await
        .map_err(|e| ProtocolError::QuicError(format!("proxy req write: {}", e)))?;

    Ok((send, recv))
}

/// Вспомогательная функция для проксирования UDP через QUIC datagrams
pub async fn send_udp_datagram(
    conn: &Connection,
    target_host: &str,
    target_port: u16,
    payload: Bytes,
) -> Result<()> {
    // Формат UDP датаграммы: [proxy_request_header][payload]
    let mut frame = BytesMut::new();
    let req = FluxTunnelProtocol::build_proxy_request(CMD_UDP, target_host, target_port)?;
    frame.extend_from_slice(&req);
    frame.extend_from_slice(&payload);

    conn.send_datagram(frame.freeze())
        .map_err(|e| ProtocolError::QuicError(format!("UDP datagram send: {}", e)))?;

    Ok(())
}

// --- TLS без верификации (для self-signed / dev) ---

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
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
