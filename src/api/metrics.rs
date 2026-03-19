use axum::extract::State;
use axum::Json;

use crate::model::*;
use crate::metrics as engine;

use super::middleware::ApiError;
use super::AppState;

pub async fn get_metrics(
    State(state): State<AppState>,
) -> Result<Json<CaseMetrics>, ApiError> {
    let cases = state.store.list(&ListParams::default()).await?;
    let metrics = engine::compute(&cases);
    Ok(Json(metrics))
}
