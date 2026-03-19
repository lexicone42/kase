use axum::routing::{get, patch, post};
use axum::Router;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use crate::store::CaseStore;

pub mod cases;
pub mod ingest;
pub mod metrics;
pub mod middleware;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn CaseStore>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/ingest", post(ingest::ingest))
        .route("/api/v1/cases", get(cases::list_cases))
        .route("/api/v1/cases/{id}", get(cases::get_case))
        .route("/api/v1/cases/{id}", patch(cases::update_case))
        .route("/api/v1/cases/{id}/notes", post(cases::add_note))
        .route("/api/v1/cases/{id}/resolve", post(cases::resolve_case))
        .route("/api/v1/cases/{id}/merge", post(cases::merge_case))
        .route("/api/v1/triage", get(cases::triage))
        .route("/api/v1/metrics", get(metrics::get_metrics))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}
