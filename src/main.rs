use anyhow::Result;
use clap::Parser;
use kase::api::AppState;
use kase::cli::{Cli, Command};
use kase::store::InMemoryStore;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Command::Serve { port, bind } = &cli.command {
        let port = *port;
        let bind = bind.as_str();
        kase::otel::init()?;

        tracing::warn!("Running with in-memory store — all data will be lost on restart");
        let store = Arc::new(InMemoryStore::new());
        let state = AppState { store };
        let app = kase::api::router(state);

        let addr = format!("{bind}:{port}");
        tracing::info!("kase server listening on {addr}");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
    } else {
        kase::cli::execute(cli).await?;
    }

    Ok(())
}
