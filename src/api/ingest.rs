use axum::extract::State;
use axum::Json;

use crate::model::*;
use crate::{ingest as engine, store::StoreError};

use super::middleware::ApiError;
use super::AppState;

#[tracing::instrument(skip_all, fields(scan_id))]
pub async fn ingest(
    State(state): State<AppState>,
    Json(scan): Json<ScanResult>,
) -> Result<Json<IngestResponse>, ApiError> {
    tracing::Span::current().record("scan_id", &scan.scan_id);
    let result = engine::ingest_scan(state.store.as_ref(), scan)
        .await
        .map_err(|e| ApiError::from(StoreError::Internal(e.to_string())))?;
    tracing::info!(
        created = result.created.len(),
        updated = result.updated.len(),
        mitigated = result.mitigated.len(),
        reopened = result.reopened.len(),
        "scan ingested"
    );
    Ok(Json(result))
}
