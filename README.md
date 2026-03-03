<div align="center">

```
███████╗██╗     ██╗   ██╗██╗  ██╗
██╔════╝██║     ██║   ██║╚██╗██╔╝
█████╗  ██║     ██║   ██║ ╚███╔╝
██╔══╝  ██║     ██║   ██║ ██╔██╗
██║     ███████╗╚██████╔╝██╔╝ ██╗
╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝
```

**A VPN kernel that actually makes sense.**  
Built on QUIC. Written in Rust. No bloat.

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange?style=flat-square&logo=rust)](https://rustup.rs)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![QUIC](https://img.shields.io/badge/transport-QUIC-blueviolet?style=flat-square)](https://quicwg.org)
[![Status](https://img.shields.io/badge/status-active%20development-yellow?style=flat-square)]()

</div>

---

## What is this

Most VPN kernels were designed for TCP and duct-taped to support UDP later.  
flux-core starts from QUIC — UDP is a first-class citizen, not an afterthought.

```
client ──QUIC──▶ flux-server ──TCP/UDP──▶ internet
         TLS 1.3    auth          proxy
```

**The stack:**
- Transport → QUIC via [quinn](https://github.com/quinn-rs/quinn)
- Protocol → FluxTunnel (custom, see below)
- API → REST + JSON (not gRPC)
- Config → YAML (not 5000 lines of JSON)
- WireGuard → userspace via [boringtun](https://github.com/cloudflare/boringtun) (no root needed)

---

## Protocols

### ⚡ FluxTunnel — native protocol

Built specifically for this project. Simple, fast, extensible.

| Feature | Detail |
|---|---|
| Transport | QUIC (UDP) |
| Auth | HMAC-SHA256 · HKDF · random nonce |
| TCP proxy | QUIC bidirectional streams |
| UDP proxy | QUIC datagrams (zero overhead) |
| TLS | 1.3, always on |
| ALPN | `flux/1` |

### 🚀 Hysteria2 — compatible client

Connects to existing Hysteria2 servers. Full auth support.

### 🔒 WireGuard — userspace

No kernel module. No root. Works everywhere via `boringtun`.

---

## Project layout

```
flux-core/
├── src/
│   ├── main.rs                  # flux-core  — REST API (port 8080)
│   ├── config.rs                # YAML config parser + validator
│   ├── protocols/
│   │   ├── mod.rs               # Protocol trait · ProtocolConfig · factory
│   │   ├── fluxtunnel.rs        # FluxTunnel client
│   │   ├── hysteria2.rs         # Hysteria2 client
│   │   └── wireguard.rs         # WireGuard client
│   └── server/
│       ├── main.rs              # flux-server — QUIC server binary
│       └── fluxtunnel_server.rs # FluxTunnel server logic
└── tests/
    └── fluxtunnel_integration.rs
```

Two binaries from one crate:

| Binary | Role |
|---|---|
| `flux-core` | REST API — create and manage tunnels |
| `flux-server` | QUIC server — accepts client connections |

---

## Getting started

### Build

```bash
git clone https://github.com/yourname/flux-core
cd flux-core
cargo build --release
```

### Run the server

```bash
# 1. Generate a password
./target/release/flux-server gen-password
# a3f8c2d19e4b7f6a0c5d2e8b1f4a7c3d6e9b2f5a8c1d4e7b0f3a6c9d2e5b8f1

# 2. Write a config
cat > /etc/flux/config.yaml << EOF
server:
  listen: "0.0.0.0:4433"

tls:
  cert: "/etc/flux/cert.pem"
  key:  "/etc/flux/key.pem"

users:
  - name: "alice"
    password: "a3f8c2d19e4b7f6a0c5d2e8b1f4a7c3d6e9b2f5a8c1d4e7b0f3a6c9d2e5b8f1"
EOF

# 3. Validate
./target/release/flux-server check-config /etc/flux/config.yaml
# ✅ Config is valid

# 4. Run
./target/release/flux-server /etc/flux/config.yaml
```

### Use the REST API

```bash
# Start
./target/release/flux-core

# Create a FluxTunnel
curl -X POST http://localhost:8080/tunnels \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "type": "flux_tunnel",
      "server_addr": "your-server.com:4433",
      "password": "your-64-char-password",
      "sni": "your-server.com",
      "insecure": false,
      "up_mbps": 0,
      "down_mbps": 0
    }
  }'

# Connect it
curl -X POST http://localhost:8080/tunnels/{id}/connect
```

---

## Config reference

```yaml
server:
  listen: "0.0.0.0:4433"   # required
  max_connections: 1024     # 0 = unlimited

tls:
  cert: "/etc/flux/cert.pem"  # required
  key:  "/etc/flux/key.pem"   # required

bandwidth:
  up_mbps: 0    # 0 = unlimited (server-wide total)
  down_mbps: 0

users:
  - name: "alice"
    password: "exactly-64-printable-ascii-chars-no-spaces-use-gen-password"

log:
  level: "info"              # trace / debug / info / warn / error
  file: "/var/log/flux.log"  # optional, omit for stdout only
```

> Passwords must be **exactly 64 characters**, printable ASCII, no spaces.  
> Generate: `flux-server gen-password`

---

## REST API

`GET /health` · `POST /tunnels` · `GET /tunnels` · `GET /tunnels/:id`  
`POST /tunnels/:id/connect` · `POST /tunnels/:id/disconnect`  
`DELETE /tunnels/:id` · `POST /tunnels/:id/test`

---

## Tests

```bash
# All tests
cargo test -- --nocapture

# Integration only (real QUIC client↔server, no mocks)
cargo test fluxtunnel -- --nocapture

# Config validation tests
cargo test config -- --nocapture
```

Integration tests spin up a real QUIC server + TCP echo server locally.  
No external dependencies, no internet required.

---

## Adding a protocol

Implement the `Protocol` trait, add a variant to `ProtocolConfig`. That's it.

```rust
// src/protocols/myprotocol.rs
#[async_trait]
impl Protocol for MyProtocol {
    fn name(&self) -> &str { "MyProtocol" }
    async fn connect(&mut self) -> Result<()> { ... }
    async fn send(&mut self, data: Bytes) -> Result<()> { ... }
    async fn receive(&mut self) -> Result<Bytes> { ... }
    async fn close(&mut self) -> Result<()> { ... }
    fn stats(&self) -> TunnelStats { ... }
    fn is_connected(&self) -> bool { ... }
}
```

```rust
// src/protocols/mod.rs — add to enum + create_protocol()
pub enum ProtocolConfig {
    FluxTunnel(FluxTunnelConfig),
    Hysteria2(Hysteria2Config),
    WireGuard(WireGuardConfig),
    MyProtocol(MyProtocolConfig),  // ← add this
}
```

REST API picks it up automatically. No other changes needed.

> **Note on VLESS/VMess:** this project doesn't implement Xray protocols by design,  
> but the architecture is open — fork and add whatever you need.

---

## Dependencies

| Crate | Purpose |
|---|---|
| `quinn` | QUIC transport |
| `rustls` | TLS 1.3 |
| `boringtun` | WireGuard userspace |
| `axum` | REST API |
| `rcgen` | Self-signed TLS cert generation |
| `serde_yaml` | YAML config |
| `hmac` + `hkdf` | FluxTunnel authentication |

---

## License

MIT — fork it, modify it, build on it.

---

<div align="center">

*flux-core is not affiliated with any existing VPN project.*  
*Built out of frustration. Maintained out of spite.* 🦀

</div>
