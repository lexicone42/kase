use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

use kase::api::{router, AppState};
use kase::model::*;
use kase::store::{CaseStore, InMemoryStore};

fn test_state() -> (AppState, Arc<InMemoryStore>) {
    let store = Arc::new(InMemoryStore::new());
    let state = AppState {
        store: store.clone(),
    };
    (state, store)
}

#[tokio::test]
async fn health_check() {
    let (state, _store) = test_state();
    let app = router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn ingest_creates_cases() {
    let (state, store) = test_state();
    let app = router(state);

    let scan = ScanResult {
        scan_id: "test-001".into(),
        timestamp: chrono::Utc::now(),
        findings: vec![Finding {
            id: "f1".into(),
            resource_id: "gs://my-bucket".into(),
            resource_type: "storage.bucket".into(),
            policy_id: "gcp/storage/versioning".into(),
            severity: Severity::High,
            title: "Bucket versioning disabled".into(),
            description: "Storage bucket does not have versioning enabled".into(),
            provider: Provider::Gcp,
        }],
        attack_paths: vec![],
        chokepoints: vec![],
    };

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/ingest")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&scan).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    // Verify case was created
    let cases = store.list(&ListParams::default()).await.unwrap();
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].status, Status::Open);
    assert_eq!(cases[0].severity, Severity::High);
    assert_eq!(cases[0].findings.len(), 1);
}

#[tokio::test]
async fn list_cases_empty() {
    let (state, _store) = test_state();
    let app = router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/cases")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_nonexistent_case_returns_404() {
    let (state, _store) = test_state();
    let app = router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/cases/01ARYZ6S41TSV4RRFFQ69G5FAV")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn metrics_on_empty_store() {
    let (state, _store) = test_state();
    let app = router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}
