use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use quinn::{Endpoint, ServerConfig, Connection, RecvStream, SendStream};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

type HmacSha256 = Hmac<Sha256>;

const FLUX_VERSION: u8 = 0x01;
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;
const STATUS_OK: u8 = 0x00;
const STATUS_ERR: u8 = 0x01;

/// Один пользователь на сервере
#[derive(Clone, Debug)]
pub struct UserEntry {
    pub name: String,
    pub password: String,
}

impl UserEntry {
    /// Дериворуем ключ HKDF из пароля пользователя
    pub fn derive_key(&self) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(
            Some(b"flux-tunnel-v1"),
            self.password.as_bytes(),
        );
        let mut key = [0u8; 32];
        hkdf.expand(b"auth-key", &mut key).unwrap();
        key
    }
}

pub struct ServerOptions {
    pub listen_addr: SocketAddr,
    pub users: Vec<UserEntry>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub max_connections: usize,
    pub up_mbps: u64,
    pub down_mbps: u64,
}

pub struct FluxTunnelServer {
    opts: ServerOptions,
    /// Предвычисленные ключи для каждого пользователя
    user_keys: Arc<Vec<(UserEntry, [u8; 32])>>,
}

impl FluxTunnelServer {
    pub fn new(opts: ServerOptions) -> anyhow::Result<Self> {
        let user_keys: Vec<(UserEntry, [u8; 32])> = opts.users
            .iter()
            .map(|u| {
                let key = u.derive_key();
                tracing::debug!("🔑 User '{}' key derived", u.name);
                (u.clone(), key)
            })
            .collect();

        Ok(Self {
            opts,
            user_keys: Arc::new(user_keys),
        })
    }

    fn build_server_config(&self) -> anyhow::Result<ServerConfig> {
        let (cert_chain, private_key) = if let (Some(cert_path), Some(key_path)) =
            (&self.opts.cert_path, &self.opts.key_path)
        {
            let cert_pem = std::fs::read(cert_path)?;
            let key_pem = std::fs::read(key_path)?;
            let certs: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut cert_pem.as_slice())
                    .collect::<Result<_, _>>()?;
            let key = rustls_pemfile::private_key(&mut key_pem.as_slice())?
                .ok_or_else(|| anyhow::anyhow!("No private key in file"))?;
            (certs, key)
        } else {
            tracing::warn!("⚠️  No TLS cert — generating self-signed");
            let cert = generate_simple_self_signed(vec!["localhost".to_string()])?;
            let cert_der = CertificateDer::from(cert.cert.der().to_vec());
            let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der())
                .map_err(|e| anyhow::anyhow!("Key error: {}", e))?;
            (vec![cert_der], key_der)
        };

        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;
        tls.alpn_protocols = vec![b"flux/1".to_vec()];

        Ok(ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls)?
        )))
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let server_config = self.build_server_config()?;
        let endpoint = Endpoint::server(server_config, self.opts.listen_addr)?;
        let max_conn = self.opts.max_connections;

        tracing::info!("✅ FluxTunnel server ready on {}", self.opts.listen_addr);
        tracing::info!("👥 {} user(s) loaded", self.user_keys.len());

        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        while let Some(incoming) = endpoint.accept().await {
            let current = active.load(std::sync::atomic::Ordering::Relaxed);
            if max_conn > 0 && current >= max_conn {
                tracing::warn!("⚠️  Max connections ({}) reached, rejecting", max_conn);
                incoming.refuse();
                continue;
            }

            let user_keys = Arc::clone(&self.user_keys);
            let active_clone = Arc::clone(&active);

            tokio::spawn(async move {
                active_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let remote = incoming.remote_address();

                match incoming.await {
                    Ok(conn) => {
                        tracing::info!("📥 [{}] connected", remote);
                        if let Err(e) = handle_connection(conn, user_keys, remote).await {
                            tracing::debug!("🔌 [{}] closed: {}", remote, e);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("❌ [{}] accept error: {}", remote, e);
                    }
                }

                active_clone.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            });
        }

        Ok(())
    }
}

async fn handle_connection(
    conn: Connection,
    user_keys: Arc<Vec<(UserEntry, [u8; 32])>>,
    remote: SocketAddr,
) -> anyhow::Result<()> {
    // AUTH с таймаутом 10 секунд
    let auth_result = tokio::time::timeout(
        Duration::from_secs(10),
        authenticate(&conn, &user_keys),
    ).await;

    let user_name = match auth_result {
        Ok(Ok(name)) => name,
        Ok(Err(e)) => {
            tracing::warn!("🔒 [{}] auth failed: {}", remote, e);
            conn.close(1u32.into(), b"auth failed");
            return Ok(());
        }
        Err(_) => {
            tracing::warn!("⏱️  [{}] auth timeout", remote);
            conn.close(1u32.into(), b"auth timeout");
            return Ok(());
        }
    };

    tracing::info!("✅ [{}] authenticated as '{}'", remote, user_name);

    // Обрабатываем стримы и датаграммы
    loop {
        tokio::select! {
            stream = conn.accept_bi() => {
                match stream {
                    Ok((send, recv)) => {
                        let name = user_name.clone();
                        tokio::spawn(async move {
                            handle_tcp_stream(send, recv, &name).await;
                        });
                    }
                    Err(e) => {
                        tracing::info!("🔌 [{}] '{}' disconnected: {}", remote, user_name, e);
                        break;
                    }
                }
            }
            datagram = conn.read_datagram() => {
                match datagram {
                    Ok(data) => {
                        let name = user_name.clone();
                        tokio::spawn(async move {
                            handle_udp_datagram(data, &name).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        }
    }

    Ok(())
}

/// Аутентификация: пробуем HMAC каждого пользователя
/// Возвращает имя пользователя если успешно
async fn authenticate(
    conn: &Connection,
    user_keys: &[(UserEntry, [u8; 32])],
) -> anyhow::Result<String> {
    let (mut send, mut recv) = conn.accept_bi().await?;

    let mut version = [0u8; 1];
    recv.read_exact(&mut version).await?;
    if version[0] != FLUX_VERSION {
        send_response(&mut send, STATUS_ERR, "unsupported version").await?;
        anyhow::bail!("Unsupported version: {}", version[0]);
    }

    let mut nonce = [0u8; 32];
    recv.read_exact(&mut nonce).await?;

    let mut received_mac = [0u8; 32];
    recv.read_exact(&mut received_mac).await?;

    // Перебираем всех пользователей (constant-time для каждого)
    for (user, key) in user_keys {
        let mut mac = HmacSha256::new_from_slice(key)?;
        mac.update(&nonce);
        let expected = mac.finalize().into_bytes();

        let mut diff = 0u8;
        for (a, b) in received_mac.iter().zip(expected.iter()) {
            diff |= a ^ b;
        }

        if diff == 0 {
            send.write_all(&[STATUS_OK]).await?;
            send.finish()?;
            return Ok(user.name.clone());
        }
    }

    send_response(&mut send, STATUS_ERR, "invalid credentials").await?;
    anyhow::bail!("No matching user");
}

async fn send_response(send: &mut SendStream, status: u8, msg: &str) -> anyhow::Result<()> {
    let bytes = msg.as_bytes();
    let len = bytes.len().min(255) as u8;
    send.write_all(&[status, len]).await?;
    send.write_all(&bytes[..len as usize]).await?;
    send.finish()?;
    Ok(())
}

async fn handle_tcp_stream(mut send: SendStream, mut recv: RecvStream, user: &str) {
    match read_proxy_request(&mut recv).await {
        Ok((host, port)) => {
            tracing::debug!("🔀 [{}] TCP → {}:{}", user, host, port);
            match TcpStream::connect(format!("{}:{}", host, port)).await {
                Ok(mut target) => {
                    let _ = send.write_all(&[STATUS_OK, 0x00]).await;
                    let (mut tr, mut tw) = target.split();
                    tokio::join!(
                        async {
                            let mut buf = vec![0u8; 32 * 1024];
                            loop {
                                match recv.read(&mut buf).await {
                                    Ok(Some(n)) if n > 0 => {
                                        if tw.write_all(&buf[..n]).await.is_err() { break; }
                                    }
                                    _ => break,
                                }
                            }
                        },
                        async {
                            let mut buf = vec![0u8; 32 * 1024];
                            loop {
                                match tr.read(&mut buf).await {
                                    Ok(n) if n > 0 => {
                                        if send.write_all(&buf[..n]).await.is_err() { break; }
                                    }
                                    _ => break,
                                }
                            }
                        }
                    );
                    tracing::debug!("✅ [{}] TCP {}:{} closed", user, host, port);
                }
                Err(e) => {
                    tracing::warn!("❌ [{}] TCP connect {}:{} failed: {}", user, host, port, e);
                    let msg = e.to_string();
                    let len = msg.len().min(255) as u8;
                    let _ = send.write_all(&[STATUS_ERR, len]).await;
                    let _ = send.write_all(&msg.as_bytes()[..len as usize]).await;
                }
            }
        }
        Err(e) => tracing::warn!("❌ [{}] bad proxy request: {}", user, e),
    }
}

async fn handle_udp_datagram(data: bytes::Bytes, user: &str) {
    match parse_udp_datagram(&data) {
        Ok((host, port, payload)) => {
            tracing::debug!("📦 [{}] UDP → {}:{} ({} bytes)", user, host, port, payload.len());
            match UdpSocket::bind("0.0.0.0:0").await {
                Ok(socket) => {
                    let _ = socket.send_to(payload, format!("{}:{}", host, port)).await;
                }
                Err(e) => tracing::warn!("❌ UDP socket: {}", e),
            }
        }
        Err(e) => tracing::warn!("❌ [{}] bad UDP datagram: {}", user, e),
    }
}

async fn read_proxy_request(recv: &mut RecvStream) -> anyhow::Result<(String, u16)> {
    let mut cmd = [0u8; 1];
    recv.read_exact(&mut cmd).await?;
    match cmd[0] {
        CMD_TCP | CMD_UDP => {}
        other => anyhow::bail!("Unknown cmd: 0x{:02x}", other),
    }

    let mut atyp = [0u8; 1];
    recv.read_exact(&mut atyp).await?;

    let host = match atyp[0] {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            recv.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            recv.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            recv.read_exact(&mut len).await?;
            let mut d = vec![0u8; len[0] as usize];
            recv.read_exact(&mut d).await?;
            String::from_utf8(d)?
        }
        other => anyhow::bail!("Unknown atyp: 0x{:02x}", other),
    };

    let mut port_b = [0u8; 2];
    recv.read_exact(&mut port_b).await?;
    Ok((host, u16::from_be_bytes(port_b)))
}

fn parse_udp_datagram(data: &[u8]) -> anyhow::Result<(String, u16, &[u8])> {
    if data.is_empty() { anyhow::bail!("Empty datagram"); }
    let mut i = 0;
    let cmd = data[i]; i += 1;
    match cmd {
        CMD_TCP | CMD_UDP => {}
        other => anyhow::bail!("Unknown cmd: 0x{:02x}", other),
    }

    if i >= data.len() { anyhow::bail!("Truncated"); }
    let atyp = data[i]; i += 1;

    let host = match atyp {
        ATYP_IPV4 => {
            if i + 4 > data.len() { anyhow::bail!("Truncated IPv4"); }
            let b: [u8; 4] = data[i..i+4].try_into()?; i += 4;
            std::net::Ipv4Addr::from(b).to_string()
        }
        ATYP_IPV6 => {
            if i + 16 > data.len() { anyhow::bail!("Truncated IPv6"); }
            let b: [u8; 16] = data[i..i+16].try_into()?; i += 16;
            std::net::Ipv6Addr::from(b).to_string()
        }
        ATYP_DOMAIN => {
            if i >= data.len() { anyhow::bail!("Truncated domain len"); }
            let len = data[i] as usize; i += 1;
            if i + len > data.len() { anyhow::bail!("Truncated domain"); }
            let d = String::from_utf8(data[i..i+len].to_vec())?; i += len;
            d
        }
        other => anyhow::bail!("Unknown atyp: 0x{:02x}", other),
    };

    if i + 2 > data.len() { anyhow::bail!("Truncated port"); }
    let port = u16::from_be_bytes([data[i], data[i+1]]); i += 2;

    Ok((host, port, &data[i..]))
}
