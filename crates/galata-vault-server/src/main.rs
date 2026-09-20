//! `gv-server --config /etc/galata-vault/server.toml`
//! `gv-server check --config …`: validate the configuration, open the journal
//! and round-trip a probe through it, then exit. Run it before the first
//! start.
//! `gv-server local [--data-dir DIR] [--port N | --listen ADDR]
//! [--print-service launchd|systemd]`: this machine, no configuration file
//! (see `galata_vault_server::local`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use galata_vault_server::local::{self, LocalOptions};
use galata_vault_server::{AppState, ServerConfig, SystemClock, journal, router};
use galata_vault_server_core::data_dir::DataDir;
use galata_vault_store::{SqliteStore, Store, StoreConfig};

const USAGE: &str = "usage: gv-server [check] --config <path> (or set GV_SERVER_CONFIG)\n       \
                     gv-server local [--data-dir DIR] [--port N | --listen 127.0.0.1:N] \
                     [--print-service launchd|systemd]";

enum Mode {
    Serve(PathBuf),
    Check(PathBuf),
    Local(LocalOptions),
}

fn mode() -> anyhow::Result<Mode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (check, rest) = match args.first().map(String::as_str) {
        Some("local") => {
            return local::parse_args(&args[1..])
                .map(Mode::Local)
                .map_err(anyhow::Error::msg);
        }
        Some("check") => (true, &args[1..]),
        _ => (false, &args[..]),
    };
    let path = match rest {
        [flag, path] if flag == "--config" => PathBuf::from(path),
        [] => std::env::var_os("GV_SERVER_CONFIG")
            .map(PathBuf::from)
            .context(USAGE)?,
        _ => anyhow::bail!(USAGE),
    };
    Ok(if check {
        Mode::Check(path)
    } else {
        Mode::Serve(path)
    })
}

/// Everything startup would check, plus a real write through the journal.
async fn check(path: PathBuf) -> anyhow::Result<()> {
    let config = ServerConfig::load(&path)?;
    println!("config      ok: {}", path.display());
    let journal = journal::open(&config.journal)
        .map_err(anyhow::Error::msg)
        .context("opening the journal")?;
    let probe = {
        let journal = Arc::clone(&journal);
        tokio::task::spawn_blocking(move || journal.check().and_then(|()| journal.probe()))
            .await?
            .map_err(anyhow::Error::msg)?
    };
    println!("journal     ok: {}", journal.describe());
    println!("probe       ok: written, read back and matched: {probe}");
    Ok(())
}

/// `gv-server local`: resolve, check and lock the data directory, or print a
/// service definition instead of serving.
async fn local(opts: LocalOptions) -> anyhow::Result<()> {
    let listen = local::listen_addr(&opts).map_err(anyhow::Error::msg)?;
    let dir = local::resolve_data_dir(opts.data_dir.as_deref(), |k| std::env::var_os(k))
        .map_err(anyhow::Error::msg)?;
    if let Some(kind) = opts.print_service {
        let bin = std::env::current_exe().context("locating this binary")?;
        print!("{}", local::service_definition(kind, &bin, &dir, listen));
        return Ok(());
    }
    let config = local::config(&dir, listen);
    config.validate()?;
    // Held until the server stops: an embedded application or a second
    // local server is refused meanwhile, before either touches a file.
    let data = DataDir::open(&dir)?;
    tracing::warn!(
        data_dir = %dir.display(),
        "local mode: the journal shares this disk with the database, so losing the disk loses the vaults (single-machine durability)"
    );
    tracing::info!("{}", local::EXPIRY_NOTICE);
    let served = serve(config).await;
    drop(data);
    served
}

/// SIGINT or SIGTERM (what launchd and systemd send to stop a service).
async fn shutdown() {
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = terminate => {}
    }
}

/// The one serving path, whatever the configuration came from.
async fn serve(config: ServerConfig) -> anyhow::Result<()> {
    let store: Arc<dyn Store> = Arc::new(
        SqliteStore::open(StoreConfig {
            path: config.database.clone(),
            litestream: config.litestream,
            readers: 8,
        })
        .with_context(|| format!("opening {}", config.database.display()))?,
    );

    let journal = journal::open(&config.journal)
        .map_err(anyhow::Error::msg)
        .context("opening the journal")?;
    tracing::info!(journal = %journal.describe(), "journal ready");

    // Before any traffic: the core re-applies acknowledged critical
    // operations that a restored database predates. The store and the journal
    // are synchronous, so this runs on the blocking pool.
    let listen = config.listen;
    let state = tokio::task::spawn_blocking(move || {
        AppState::new(store, journal, config, Arc::new(SystemClock))
    })
    .await??;
    let replayed = state.core().replayed();
    if replayed > 0 {
        tracing::warn!(
            target: "security",
            replayed,
            "database was behind the journal: replayed {replayed} acknowledged critical operations (restore detected)"
        );
    }

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    tracing::info!(%listen, "gv-server listening");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Allow-listed logging: handlers never log headers, bodies or addresses.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("GV_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(true)
        // Logs on stderr; stdout carries `check` results and service definitions.
        .with_writer(std::io::stderr)
        // Colour only on a terminal: log files and journald get plain text.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();

    match mode()? {
        Mode::Check(path) => check(path).await,
        Mode::Local(opts) => local(opts).await,
        Mode::Serve(path) => serve(ServerConfig::load(&path)?).await,
    }
}
