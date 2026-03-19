use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::store::StoreError;

pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": self.message,
        });
        (self.status, Json(body)).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(err: StoreError) -> Self {
        match &err {
            StoreError::NotFound(_) => ApiError {
                status: StatusCode::NOT_FOUND,
                message: err.to_string(),
            },
            StoreError::Internal(_) => ApiError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: err.to_string(),
            },
        }
    }
}
