use anyhow::Result;
use clap::Parser;
use kase::api::AppState;
use kase::cli::{Cli, Command};
use kase::store::InMemoryStore;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Command::Serve { port } = &cli.command {
        let port = *port;
        kase::otel::init()?;

        let store = Arc::new(InMemoryStore::new());
        let state = AppState { store };
        let app = kase::api::router(state);

        let addr = format!("0.0.0.0:{port}");
        tracing::info!("kase server listening on {addr}");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
    } else {
        kase::cli::execute(cli).await?;
    }

    Ok(())
}
