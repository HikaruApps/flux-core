use axum::{
    extract::{Path, State},
    routing::{get, post, delete},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use bytes::Bytes;

mod protocols;

use protocols::{create_protocol, Protocol, ProtocolConfig, TunnelStats};

// === State ===
type AppState = Arc<RwLock<FluxCore>>;

struct FluxCore {
    tunnels: HashMap<String, Box<dyn Protocol>>,
}

impl FluxCore {
    fn new() -> Self {
        Self {
            tunnels: HashMap::new(),
        }
    }
}

// === Models ===
#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    fn ok(data: T) -> Self {
        Self { success: true, data: Some(data), error: None }
    }
    fn err(msg: impl ToString) -> ApiResponse<T> {
        ApiResponse { success: false, data: None, error: Some(msg.to_string()) }
    }
}

#[derive(Serialize)]
struct TunnelInfo {
    id: String,
    protocol: String,
    connected: bool,
    stats: TunnelStats,
}

#[derive(Deserialize)]
struct CreateTunnelRequest {
    config: ProtocolConfig,
}

// === Handlers ===

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "name": "flux-core",
        "protocols": ["wireguard", "hysteria2", "fluxtunnel"]
    }))
}

async fn create_tunnel(
    State(state): State<AppState>,
    Json(req): Json<CreateTunnelRequest>,
) -> Json<ApiResponse<String>> {
    let mut core = state.write().await;

    match create_protocol(req.config) {
        Ok(protocol) => {
            let id = uuid::Uuid::new_v4().to_string();
            tracing::info!("✅ Created tunnel [{}] id={}", protocol.name(), id);
            core.tunnels.insert(id.clone(), protocol);
            Json(ApiResponse::ok(id))
        }
        Err(e) => {
            tracing::error!("❌ Create tunnel failed: {}", e);
            Json(ApiResponse::err(e))
        }
    }
}

async fn list_tunnels(State(state): State<AppState>) -> Json<ApiResponse<Vec<TunnelInfo>>> {
    let core = state.read().await;
    let tunnels = core.tunnels.iter().map(|(id, t)| TunnelInfo {
        id: id.clone(),
        protocol: t.name().to_string(),
        connected: t.is_connected(),
        stats: t.stats(),
    }).collect();
    Json(ApiResponse::ok(tunnels))
}

async fn get_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<TunnelInfo>> {
    let core = state.read().await;
    match core.tunnels.get(&id) {
        Some(t) => Json(ApiResponse::ok(TunnelInfo {
            id: id.clone(),
            protocol: t.name().to_string(),
            connected: t.is_connected(),
            stats: t.stats(),
        })),
        None => Json(ApiResponse::err("Tunnel not found")),
    }
}

async fn connect_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<String>> {
    let mut core = state.write().await;
    match core.tunnels.get_mut(&id) {
        Some(tunnel) => match tunnel.connect().await {
            Ok(_) => {
                tracing::info!("✅ Tunnel {} connected", id);
                Json(ApiResponse::ok("connected".to_string()))
            }
            Err(e) => {
                tracing::error!("❌ Tunnel {} connect failed: {}", id, e);
                Json(ApiResponse::err(e))
            }
        },
        None => Json(ApiResponse::err("Tunnel not found")),
    }
}

async fn disconnect_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<String>> {
    let mut core = state.write().await;
    match core.tunnels.get_mut(&id) {
        Some(tunnel) => match tunnel.close().await {
            Ok(_) => {
                tracing::info!("🔌 Tunnel {} disconnected", id);
                Json(ApiResponse::ok("disconnected".to_string()))
            }
            Err(e) => Json(ApiResponse::err(e)),
        },
        None => Json(ApiResponse::err("Tunnel not found")),
    }
}

async fn delete_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<String>> {
    let mut core = state.write().await;
    if let Some(mut tunnel) = core.tunnels.remove(&id) {
        let _ = tunnel.close().await;
        tracing::info!("🗑️ Tunnel {} deleted", id);
        Json(ApiResponse::ok("deleted".to_string()))
    } else {
        Json(ApiResponse::err("Tunnel not found"))
    }
}

async fn test_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<serde_json::Value>> {
    let mut core = state.write().await;
    match core.tunnels.get_mut(&id) {
        Some(tunnel) => {
            if !tunnel.is_connected() {
                return Json(ApiResponse::err("Tunnel not connected"));
            }

            let test_data = Bytes::from("flux-test-ping");
            let sent_at = std::time::Instant::now();

            match tunnel.send(test_data.clone()).await {
                Ok(_) => {
                    let elapsed = sent_at.elapsed();
                    let stats = tunnel.stats();
                    Json(ApiResponse::ok(serde_json::json!({
                        "sent_bytes": test_data.len(),
                        "rtt_ms": elapsed.as_millis(),
                        "stats": stats,
                    })))
                }
                Err(e) => Json(ApiResponse::err(e)),
            }
        }
        None => Json(ApiResponse::err("Tunnel not found")),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("flux_core=debug".parse().unwrap())
                .add_directive("info".parse().unwrap()),
        )
        .init();

    tracing::info!("⚡ flux-core v{} starting", env!("CARGO_PKG_VERSION"));

    let state = Arc::new(RwLock::new(FluxCore::new()));

    let app = Router::new()
        .route("/health", get(health))
        // Tunnels CRUD
        .route("/tunnels", post(create_tunnel))
        .route("/tunnels", get(list_tunnels))
        .route("/tunnels/:id", get(get_tunnel))
        .route("/tunnels/:id", delete(delete_tunnel))
        // Lifecycle
        .route("/tunnels/:id/connect", post(connect_tunnel))
        .route("/tunnels/:id/disconnect", post(disconnect_tunnel))
        // Diagnostics
        .route("/tunnels/:id/test", post(test_tunnel))
        .with_state(state);

    let addr = std::env::var("LISTEN_ADDR").unwrap_or("0.0.0.0:8080".to_string());
    tracing::info!("🌐 REST API → http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await
        .expect("Failed to bind");
    axum::serve(listener, app).await
        .expect("Server failed");
}
