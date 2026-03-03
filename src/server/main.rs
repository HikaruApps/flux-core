use flux_core::config::{Config, generate_password};

mod fluxtunnel_server;
use fluxtunnel_server::{FluxTunnelServer, ServerOptions, UserEntry};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        // flux-server gen-password
        Some("gen-password") => {
            println!("{}", generate_password());
            return Ok(());
        }
        // flux-server check-config /path/to/config.yaml
        Some("check-config") => {
            let path = args.get(2)
                .ok_or_else(|| anyhow::anyhow!("Usage: flux-server check-config <path>"))?;
            match Config::load(path) {
                Ok(cfg) => {
                    println!("✅ Config is valid");
                    println!("   listen:      {}", cfg.server.listen);
                    println!("   users:       {}", cfg.users.len());
                    println!("   max_conn:    {}", cfg.server.max_connections);
                    println!("   log level:   {}", cfg.log.level);
                    if cfg.bandwidth.up_mbps > 0 || cfg.bandwidth.down_mbps > 0 {
                        println!("   bandwidth:   up={}Mbps down={}Mbps",
                            cfg.bandwidth.up_mbps, cfg.bandwidth.down_mbps);
                    }
                }
                Err(e) => {
                    eprintln!("❌ {}", e);
                    std::process::exit(1);
                }
            }
            return Ok(());
        }
        _ => {}
    }

    // Путь к конфигу — первый аргумент или дефолт
    let config_path = args.get(1)
        .map(|s| s.as_str())
        .unwrap_or("/etc/flux/config.yaml");

    let cfg = Config::load(config_path)
        .map_err(|e| {
            eprintln!("❌ Failed to load config '{}': {}", config_path, e);
            anyhow::anyhow!(e)
        })?;

    init_logging(&cfg);

    tracing::info!("⚡ flux-server v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("📄 Config: {}", config_path);
    tracing::info!("📡 Listen: {}", cfg.server.listen);
    tracing::info!("👥 Users: {}", cfg.users.len());

    if cfg.bandwidth.up_mbps > 0 || cfg.bandwidth.down_mbps > 0 {
        tracing::info!("📶 Bandwidth: up={}Mbps down={}Mbps",
            cfg.bandwidth.up_mbps, cfg.bandwidth.down_mbps);
    }

    let users: Vec<UserEntry> = cfg.users.iter().map(|u| UserEntry {
        name: u.name.clone(),
        password: u.password.clone(),
    }).collect();

    let opts = ServerOptions {
        listen_addr: cfg.listen_addr(),
        users,
        cert_path: Some(cfg.tls.cert.to_string_lossy().to_string()),
        key_path: Some(cfg.tls.key.to_string_lossy().to_string()),
        max_connections: cfg.server.max_connections,
        up_mbps: cfg.bandwidth.up_mbps,
        down_mbps: cfg.bandwidth.down_mbps,
    };

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let server = FluxTunnelServer::new(opts)?;
            server.run().await
        })
}

fn init_logging(cfg: &Config) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cfg.log.level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    if let Some(log_file) = &cfg.log.file {
        tracing::info!("📝 Log file: {} (add tracing-appender for file output)", log_file.display());
    }
}
