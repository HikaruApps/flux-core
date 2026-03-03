use super::{Protocol, ProtocolError, Result, TunnelStats, WireGuardConfig};
use async_trait::async_trait;
use bytes::Bytes;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use base64::{Engine as _, engine::general_purpose};

pub struct WireGuardProtocol {
    config: WireGuardConfig,
    tunnel: Option<Arc<Mutex<Box<Tunn>>>>,
    socket: Option<Arc<UdpSocket>>,
    connected: bool,
    stats: TunnelStats,
}

impl WireGuardProtocol {
    pub fn new(config: WireGuardConfig) -> Result<Self> {
        Ok(Self {
            config,
            tunnel: None,
            socket: None,
            connected: false,
            stats: TunnelStats::default(),
        })
    }

    fn decode_key(b64: &str) -> Result<[u8; 32]> {
        let bytes = general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| ProtocolError::ProtocolError(format!("Bad base64 key: {}", e)))?;
        if bytes.len() != 32 {
            return Err(ProtocolError::ProtocolError(
                format!("Key must be 32 bytes, got {}", bytes.len()),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[async_trait]
impl Protocol for WireGuardProtocol {
    fn name(&self) -> &str {
        "WireGuard"
    }

    async fn connect(&mut self) -> Result<()> {
        tracing::info!("🔗 Connecting WireGuard to {}", self.config.server_addr);

        // Декодируем ключи из base64
        let private_key_bytes = Self::decode_key(&self.config.private_key)?;
        let server_pub_bytes = Self::decode_key(&self.config.server_public_key)?;

        let static_private = StaticSecret::from(private_key_bytes);
        let server_public = PublicKey::from(server_pub_bytes);

        // Создаём boringtun тоннель
        let tun = Tunn::new(
            static_private,
            server_public,
            None,  // preshared key
            None,  // keepalive interval
            0,     // index
            None,  // rate limiter
        ).map_err(|e| ProtocolError::ProtocolError(format!("WireGuard init failed: {}", e)))?;

        // UDP сокет для общения с сервером
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| ProtocolError::ConnectionFailed(format!("UDP bind failed: {}", e)))?;

        socket.connect(&self.config.server_addr)
            .map_err(|e| ProtocolError::ConnectionFailed(format!("UDP connect failed: {}", e)))?;

        socket.set_nonblocking(true)
            .map_err(|e| ProtocolError::IoError(e))?;

        tracing::info!("✅ UDP socket bound, initiating WireGuard handshake...");

        // Инициируем handshake — формируем initiation пакет
        let mut dst = vec![0u8; 2048];
        let tun = Arc::new(Mutex::new(tun));
        
        {
            let mut tun_lock = tun.lock().unwrap();
            match tun_lock.format_handshake_initiation(&mut dst, false) {
                TunnResult::WriteToNetwork(packet) => {
                    socket.send(packet)
                        .map_err(|e| ProtocolError::ConnectionFailed(
                            format!("Handshake send failed: {}", e)
                        ))?;
                    tracing::info!("📤 WireGuard handshake initiation sent ({} bytes)", packet.len());
                }
                other => {
                    tracing::warn!("⚠️ Unexpected handshake result: {:?}", std::mem::discriminant(&other));
                }
            }
        }

        // Ждём handshake response — неблокирующий poll через tokio
        let socket_arc = Arc::new(socket);
        let socket_clone = Arc::clone(&socket_arc);
        let tun_clone = Arc::clone(&tun);

        // Токио таск для получения handshake response
        let handshake_done = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; 4096];
            let mut dst = vec![0u8; 4096];
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            
            loop {
                if std::time::Instant::now() > deadline {
                    return Err("Handshake timeout".to_string());
                }
                
                match socket_clone.recv(&mut buf) {
                    Ok(n) => {
                        let mut tun_lock = tun_clone.lock().unwrap();
                        match tun_lock.decapsulate(None, &buf[..n], &mut dst) {
                            TunnResult::WriteToNetwork(pkt) => {
                                // Надо отправить ответ (обычно это cookie reply)
                                let _ = socket_clone.send(pkt);
                                continue;
                            }
                            TunnResult::Done => {
                                // Handshake завершён
                                return Ok(());
                            }
                            TunnResult::Err(e) => {
                                return Err(format!("Handshake error: {:?}", e));
                            }
                            _ => continue,
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                    Err(e) => return Err(format!("Recv error: {}", e)),
                }
            }
        });

        match handshake_done.await {
            Ok(Ok(())) => {
                tracing::info!("✅ WireGuard handshake complete!");
            }
            Ok(Err(e)) => {
                return Err(ProtocolError::ConnectionFailed(
                    format!("Handshake failed: {}", e)
                ));
            }
            Err(e) => {
                return Err(ProtocolError::ConnectionFailed(
                    format!("Handshake task panic: {}", e)
                ));
            }
        }

        self.tunnel = Some(tun);
        self.socket = Some(socket_arc);
        self.connected = true;

        tracing::info!("✅ WireGuard connected to {}", self.config.server_addr);
        Ok(())
    }

    async fn send(&mut self, data: Bytes) -> Result<()> {
        let tun = self.tunnel.as_ref()
            .ok_or_else(|| ProtocolError::ConnectionFailed("Not connected".to_string()))?;
        let socket = self.socket.as_ref()
            .ok_or_else(|| ProtocolError::ConnectionFailed("No socket".to_string()))?;

        let mut dst = vec![0u8; data.len() + 64]; // +overhead для WG заголовка
        let mut tun_lock = tun.lock().unwrap();

        match tun_lock.encapsulate(&data, &mut dst) {
            TunnResult::WriteToNetwork(packet) => {
                let packet_len = packet.len();
                let socket_clone = Arc::clone(socket);
                let packet_owned = packet.to_vec();
                
                tokio::task::spawn_blocking(move || {
                    socket_clone.send(&packet_owned)
                }).await
                    .map_err(|e| ProtocolError::ProtocolError(e.to_string()))?
                    .map_err(|e| ProtocolError::IoError(e))?;

                self.stats.bytes_sent += data.len() as u64;
                self.stats.packets_sent += 1;
                tracing::debug!("📤 WireGuard sent {} bytes (encapsulated: {})", data.len(), packet_len);
            }
            TunnResult::Err(e) => {
                return Err(ProtocolError::ProtocolError(format!("Encapsulate error: {:?}", e)));
            }
            _ => {}
        }

        Ok(())
    }

    async fn receive(&mut self) -> Result<Bytes> {
        let tun = self.tunnel.as_ref()
            .ok_or_else(|| ProtocolError::ConnectionFailed("Not connected".to_string()))?;
        let socket = self.socket.as_ref()
            .ok_or_else(|| ProtocolError::ConnectionFailed("No socket".to_string()))?;

        let socket_clone = Arc::clone(socket);
        let tun_clone = Arc::clone(tun);

        let result = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; 65535];
            let mut dst = vec![0u8; 65535];

            loop {
                let n = socket_clone.recv(&mut buf)
                    .map_err(|e| ProtocolError::IoError(e))?;

                let mut tun_lock = tun_clone.lock().unwrap();
                match tun_lock.decapsulate(None, &buf[..n], &mut dst) {
                    TunnResult::WriteToTunnelV4(packet, _src) => {
                        return Ok(Bytes::copy_from_slice(packet));
                    }
                    TunnResult::WriteToTunnelV6(packet, _src) => {
                        return Ok(Bytes::copy_from_slice(packet));
                    }
                    TunnResult::WriteToNetwork(pkt) => {
                        // keepalive или handshake response — отправляем и ждём дальше
                        let _ = socket_clone.send(pkt);
                        continue;
                    }
                    TunnResult::Err(e) => {
                        return Err(ProtocolError::ProtocolError(
                            format!("Decapsulate error: {:?}", e)
                        ));
                    }
                    TunnResult::Done => continue,
                }
            }
        }).await
            .map_err(|e| ProtocolError::ProtocolError(e.to_string()))??;

        self.stats.bytes_received += result.len() as u64;
        self.stats.packets_received += 1;
        tracing::debug!("📥 WireGuard received {} bytes", result.len());

        Ok(result)
    }

    async fn close(&mut self) -> Result<()> {
        tracing::info!("🔌 Closing WireGuard connection");
        self.tunnel = None;
        self.socket = None;
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
