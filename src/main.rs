use anyhow::Result;
use clap::Parser;
use kase::api::AppState;
use kase::cli::{Cli, Command};
use kase::store::{firestore_store::FirestoreStore, CaseStore, InMemoryStore};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider (needed by gcloud-sdk's jsonwebtoken)
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    if let Command::Serve {
        port,
        bind,
        store,
        project,
    } = &cli.command
    {
        let port = *port;
        let bind = bind.as_str();
        kase::otel::init()?;

        let store: Arc<dyn CaseStore> = match store.as_str() {
            "memory" => {
                tracing::warn!("Running with in-memory store — all data will be lost on restart");
                Arc::new(InMemoryStore::new())
            }
            "firestore" => {
                let project_id = project
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("--project required for firestore store"))?;
                tracing::info!(project = project_id, "Connecting to Firestore");
                let fs = FirestoreStore::new(project_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("firestore init failed: {e}"))?;
                Arc::new(fs)
            }
            other => anyhow::bail!("unknown store backend: {other} (use 'memory' or 'firestore')"),
        };

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
