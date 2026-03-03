/// Интеграционные тесты FluxTunnel
///
/// cargo test -- --nocapture
/// cargo test fluxtunnel -- --nocapture  (только эти тесты)

#[cfg(test)]
mod fluxtunnel_integration {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::{BufMut, Bytes, BytesMut};
    use hkdf::Hkdf;
    use hmac::{Hmac, Mac};
    use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};
    use rand::RngCore;
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use sha2::Sha256;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    type HmacSha256 = Hmac<Sha256>;

    const TEST_PASSWORD: &str = "test-secret-password-123";
    const FLUX_VERSION: u8 = 0x01;
    const CMD_TCP: u8 = 0x01;
    const ATYP_IPV4: u8 = 0x01;
    const ATYP_DOMAIN: u8 = 0x02;
    const STATUS_OK: u8 = 0x00;

    // --- Утилиты ---

    fn derive_key(password: &str) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(Some(b"flux-tunnel-v1"), password.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(b"auth-key", &mut key).unwrap();
        key
    }

    fn build_auth_frame(derived_key: &[u8; 32]) -> Vec<u8> {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut mac = HmacSha256::new_from_slice(derived_key).unwrap();
        mac.update(&nonce);
        let mac_bytes = mac.finalize().into_bytes();
        let mut frame = vec![FLUX_VERSION];
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&mac_bytes);
        frame
    }

    fn build_tcp_proxy_request(host: &str, port: u16) -> Vec<u8> {
        let mut frame = vec![CMD_TCP];
        if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
            frame.push(ATYP_IPV4);
            frame.extend_from_slice(&ipv4.octets());
        } else {
            frame.push(ATYP_DOMAIN);
            frame.push(host.len() as u8);
            frame.extend_from_slice(host.as_bytes());
        }
        frame.extend_from_slice(&port.to_be_bytes());
        frame
    }

    fn generate_test_tls() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let cert = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
        (vec![cert_der], key_der)
    }

    fn test_server_config() -> ServerConfig {
        let (certs, key) = generate_test_tls();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        tls.alpn_protocols = vec![b"flux/1".to_vec()];
        ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ))
    }

    fn test_client_config() -> ClientConfig {
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        tls.dangerous().set_certificate_verifier(Arc::new(NoVerify));
        tls.alpn_protocols = vec![b"flux/1".to_vec()];
        ClientConfig::new(Arc::new(tls))
    }

    #[derive(Debug)]
    struct NoVerify;
    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }

    // --- Мини-сервер для тестов ---

    async fn start_test_flux_server(password: &str) -> SocketAddr {
        let server_config = test_server_config();
        let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let derived_key = Arc::new(derive_key(password));

        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let key = Arc::clone(&derived_key);
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        let _ = serve_test_connection(conn, key).await;
                    }
                });
            }
        });
        addr
    }

    async fn serve_test_connection(conn: Connection, key: Arc<[u8; 32]>) -> anyhow::Result<()> {
        // AUTH
        let (mut send, mut recv) = conn.accept_bi().await?;
        let mut version = [0u8; 1];
        recv.read_exact(&mut version).await?;
        if version[0] != FLUX_VERSION {
            send.write_all(&[0x01, 0x11]).await?;
            send.write_all(b"unsupported version").await?;
            send.finish()?;
            anyhow::bail!("Bad version");
        }
        let mut nonce = [0u8; 32];
        recv.read_exact(&mut nonce).await?;
        let mut received_mac = [0u8; 32];
        recv.read_exact(&mut received_mac).await?;

        let mut mac = HmacSha256::new_from_slice(&*key)?;
        mac.update(&nonce);
        let expected = mac.finalize().into_bytes();

        let mut diff = 0u8;
        for (a, b) in received_mac.iter().zip(expected.iter()) {
            diff |= a ^ b;
        }

        if diff != 0 {
            send.write_all(&[0x01, 0x12]).await?;
            send.write_all(b"invalid credentials").await?;
            send.finish()?;
            anyhow::bail!("Bad credentials");
        }

        send.write_all(&[STATUS_OK]).await?;
        send.finish()?;

        // Обрабатываем стримы
        loop {
            match conn.accept_bi().await {
                Ok((send, recv)) => {
                    tokio::spawn(handle_test_proxy_stream(send, recv));
                }
                Err(_) => break,
            }
        }
        Ok(())
    }

    async fn handle_test_proxy_stream(mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
        // cmd
        let mut buf = [0u8; 1];
        if recv.read_exact(&mut buf).await.is_err() {
            return;
        }
        // atyp
        if recv.read_exact(&mut buf).await.is_err() {
            return;
        }
        let host = match buf[0] {
            ATYP_IPV4 => {
                let mut b = [0u8; 4];
                if recv.read_exact(&mut b).await.is_err() {
                    return;
                }
                std::net::Ipv4Addr::from(b).to_string()
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                if recv.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut d = vec![0u8; len[0] as usize];
                if recv.read_exact(&mut d).await.is_err() {
                    return;
                }
                String::from_utf8_lossy(&d).to_string()
            }
            _ => return,
        };
        let mut port_b = [0u8; 2];
        if recv.read_exact(&mut port_b).await.is_err() {
            return;
        }
        let port = u16::from_be_bytes(port_b);

        match tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await {
            Ok(mut target) => {
                let _ = send.write_all(&[STATUS_OK, 0x00]).await;
                let (mut tr, mut tw) = target.split();
                tokio::join!(
                    async {
                        let mut b = vec![0u8; 8192];
                        loop {
                            match recv.read(&mut b).await {
                                Ok(Some(n)) if n > 0 => {
                                    if tw.write_all(&b[..n]).await.is_err() {
                                        break;
                                    }
                                }
                                _ => break,
                            }
                        }
                    },
                    async {
                        let mut b = vec![0u8; 8192];
                        loop {
                            match tr.read(&mut b).await {
                                Ok(n) if n > 0 => {
                                    if send.write_all(&b[..n]).await.is_err() {
                                        break;
                                    }
                                }
                                _ => break,
                            }
                        }
                    }
                );
            }
            Err(e) => {
                let msg = e.to_string();
                let len = msg.len().min(255) as u8;
                let _ = send.write_all(&[0x01, len]).await;
                let _ = send.write_all(&msg.as_bytes()[..len as usize]).await;
            }
        }
    }

    async fn start_echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(n) if n > 0 => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }
                });
            }
        });
        addr
    }

    // --- Unit тесты (без сети) ---

    #[test]
    fn test_derive_key_deterministic() {
        let k1 = derive_key("password123");
        let k2 = derive_key("password123");
        let k3 = derive_key("other-password");
        assert_eq!(k1, k2, "Same password → same key");
        assert_ne!(k1, k3, "Different passwords → different keys");
        println!("✅ Key derivation is deterministic");
    }

    #[test]
    fn test_auth_frame_structure() {
        let key = derive_key(TEST_PASSWORD);
        let frame = build_auth_frame(&key);
        assert_eq!(frame.len(), 65, "Auth frame = 1 + 32 + 32 bytes");
        assert_eq!(frame[0], FLUX_VERSION);
        println!("✅ Auth frame structure OK");
    }

    #[test]
    fn test_auth_frame_hmac_valid() {
        let key = derive_key(TEST_PASSWORD);
        let frame = build_auth_frame(&key);
        let nonce = &frame[1..33];
        let received_mac = &frame[33..65];
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(nonce);
        let expected = mac.finalize().into_bytes();
        assert_eq!(received_mac, expected.as_slice(), "HMAC должен совпадать");
        println!("✅ HMAC verification OK");
    }

    #[test]
    fn test_proxy_request_ipv4() {
        let req = build_tcp_proxy_request("1.2.3.4", 8080);
        assert_eq!(req[0], CMD_TCP);
        assert_eq!(req[1], ATYP_IPV4);
        assert_eq!(&req[2..6], &[1, 2, 3, 4]);
        assert_eq!(u16::from_be_bytes([req[6], req[7]]), 8080);
        println!("✅ IPv4 proxy request encoding OK");
    }

    #[test]
    fn test_proxy_request_domain() {
        let req = build_tcp_proxy_request("example.com", 443);
        assert_eq!(req[0], CMD_TCP);
        assert_eq!(req[1], ATYP_DOMAIN);
        assert_eq!(req[2], 11);
        assert_eq!(&req[3..14], b"example.com");
        assert_eq!(u16::from_be_bytes([req[14], req[15]]), 443);
        println!("✅ Domain proxy request encoding OK");
    }

    #[test]
    fn test_constant_time_eq() {
        fn ct_eq(a: &[u8], b: &[u8]) -> bool {
            if a.len() != b.len() {
                return false;
            }
            let mut d = 0u8;
            for (x, y) in a.iter().zip(b.iter()) {
                d |= x ^ y;
            }
            d == 0
        }
        assert!(ct_eq(b"hello", b"hello"));
        assert!(!ct_eq(b"hello", b"world"));
        assert!(!ct_eq(b"hello", b"hell"));
        assert!(ct_eq(&[], &[]));
        println!("✅ Constant-time equality OK");
    }

    // --- Интеграционные тесты ---

    #[tokio::test]
    async fn test_quic_connection_established() {
        let server_addr = start_test_flux_server(TEST_PASSWORD).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(test_client_config());

        let conn = endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .expect("QUIC connection failed");

        assert!(!conn.rtt().is_zero());
        conn.close(0u32.into(), b"ok");
        println!("✅ QUIC connection established");
    }

    #[tokio::test]
    async fn test_auth_success() {
        let server_addr = start_test_flux_server(TEST_PASSWORD).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(test_client_config());
        let conn = endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let key = derive_key(TEST_PASSWORD);
        let frame = build_auth_frame(&key);
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        s.write_all(&frame).await.unwrap();
        s.finish().unwrap();

        let mut status = [0u8; 1];
        r.read_exact(&mut status).await.unwrap();
        assert_eq!(
            status[0], STATUS_OK,
            "Auth с правильным паролем должна пройти"
        );
        conn.close(0u32.into(), b"ok");
        println!("✅ Auth success");
    }

    #[tokio::test]
    async fn test_auth_failure_wrong_password() {
        let server_addr = start_test_flux_server(TEST_PASSWORD).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(test_client_config());
        let conn = endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let wrong_key = derive_key("wrong-password");
        let frame = build_auth_frame(&wrong_key);
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        s.write_all(&frame).await.unwrap();
        s.finish().unwrap();

        let mut status = [0u8; 1];
        r.read_exact(&mut status).await.unwrap();
        assert_ne!(
            status[0], STATUS_OK,
            "Auth с неправильным паролем должна ПРОВАЛИТЬСЯ"
        );
        println!("✅ Auth correctly rejected wrong password");
    }

    #[tokio::test]
    async fn test_tcp_proxy_echo() {
        let echo_addr = start_echo_server().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let flux_addr = start_test_flux_server(TEST_PASSWORD).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(test_client_config());
        let conn = endpoint
            .connect(flux_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        // Auth
        let key = derive_key(TEST_PASSWORD);
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        s.write_all(&build_auth_frame(&key)).await.unwrap();
        s.finish().unwrap();
        let mut st = [0u8; 1];
        r.read_exact(&mut st).await.unwrap();
        assert_eq!(st[0], STATUS_OK);

        // Proxy
        let req = build_tcp_proxy_request(&echo_addr.ip().to_string(), echo_addr.port());
        let (mut ps, mut pr) = conn.open_bi().await.unwrap();
        ps.write_all(&req).await.unwrap();

        let mut proxy_status = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(3), pr.read_exact(&mut proxy_status))
            .await
            .expect("timeout")
            .expect("read failed");
        assert_eq!(proxy_status[0], STATUS_OK, "Proxy connect должен успешно");

        // Данные
        let payload = b"Hello, FluxTunnel!";
        ps.write_all(payload).await.unwrap();
        let mut echo_buf = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(3), pr.read_exact(&mut echo_buf))
            .await
            .expect("echo timeout")
            .expect("echo read failed");

        assert_eq!(echo_buf.as_slice(), payload);
        conn.close(0u32.into(), b"ok");
        println!("✅ TCP proxy echo test passed!");
    }

    #[tokio::test]
    async fn test_multiple_concurrent_streams() {
        let echo_addr = start_echo_server().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let flux_addr = start_test_flux_server(TEST_PASSWORD).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(test_client_config());
        let conn = endpoint
            .connect(flux_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let key = derive_key(TEST_PASSWORD);
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        s.write_all(&build_auth_frame(&key)).await.unwrap();
        s.finish().unwrap();
        let mut st = [0u8; 1];
        r.read_exact(&mut st).await.unwrap();
        assert_eq!(st[0], STATUS_OK);

        let ip = echo_addr.ip().to_string();
        let port = echo_addr.port();
        let mut handles = vec![];

        for i in 0u8..5 {
            let c = conn.clone();
            let ip = ip.clone();
            handles.push(tokio::spawn(async move {
                let req = build_tcp_proxy_request(&ip, port);
                let (mut ps, mut pr) = c.open_bi().await?;
                ps.write_all(&req).await?;
                let mut status = [0u8; 2];
                pr.read_exact(&mut status).await?;
                assert_eq!(status[0], STATUS_OK);

                let msg = format!("stream-{}-payload", i);
                ps.write_all(msg.as_bytes()).await?;
                let mut buf = vec![0u8; msg.len()];
                pr.read_exact(&mut buf).await?;
                assert_eq!(buf, msg.as_bytes());
                Ok::<_, anyhow::Error>(())
            }));
        }

        for h in handles {
            h.await.expect("panic").expect("stream error");
        }
        conn.close(0u32.into(), b"ok");
        println!("✅ 5 concurrent streams test passed!");
    }

    #[tokio::test]
    async fn test_large_data_transfer() {
        let echo_addr = start_echo_server().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let flux_addr = start_test_flux_server(TEST_PASSWORD).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(test_client_config());
        let conn = endpoint
            .connect(flux_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let key = derive_key(TEST_PASSWORD);
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        s.write_all(&build_auth_frame(&key)).await.unwrap();
        s.finish().unwrap();
        let mut st = [0u8; 1];
        r.read_exact(&mut st).await.unwrap();
        assert_eq!(st[0], STATUS_OK);

        let req = build_tcp_proxy_request(&echo_addr.ip().to_string(), echo_addr.port());
        let (mut ps, mut pr) = conn.open_bi().await.unwrap();
        ps.write_all(&req).await.unwrap();
        let mut proxy_status = [0u8; 2];
        pr.read_exact(&mut proxy_status).await.unwrap();
        assert_eq!(proxy_status[0], STATUS_OK);

        // 512KB
        let big: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();
        ps.write_all(&big).await.unwrap();

        let mut received = vec![0u8; big.len()];
        tokio::time::timeout(Duration::from_secs(10), pr.read_exact(&mut received))
            .await
            .expect("large data timeout")
            .expect("large data read failed");

        assert_eq!(received, big, "512KB должен дойти без изменений");
        conn.close(0u32.into(), b"ok");
        println!("✅ Large data (512KB) test passed!");
    }
}
