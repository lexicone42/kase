use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

use kase::api::{router, AppState};
use kase::model::*;
use kase::store::{CaseStore, InMemoryStore};

// === Helpers ===

fn test_app() -> (axum::Router, Arc<InMemoryStore>) {
    let store = Arc::new(InMemoryStore::new());
    let state = AppState {
        store: store.clone(),
    };
    (router(state), store)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn json_post(uri: &str, body: &impl serde::Serialize) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

fn json_patch(uri: &str, body: &impl serde::Serialize) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

async fn body_json<T: serde::de::DeserializeOwned>(
    resp: axum::http::Response<Body>,
) -> T {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn test_scan(findings: Vec<Finding>) -> ScanResult {
    ScanResult {
        scan_id: "test-scan".into(),
        timestamp: chrono::Utc::now(),
        source: "test".into(),
        findings,
        attack_paths: vec![],
        chokepoints: vec![],
    }
}

fn gcp_finding(id: &str, resource: &str, severity: Severity) -> Finding {
    Finding {
        id: id.into(),
        resource_id: resource.into(),
        resource_type: "storage.bucket".into(),
        policy_id: "gcp/test".into(),
        severity,
        title: format!("Finding {id}"),
        description: "Test finding".into(),
        provider: Provider::Gcp,
    }
}

fn aws_finding(id: &str, resource: &str, severity: Severity) -> Finding {
    Finding {
        id: id.into(),
        resource_id: resource.into(),
        resource_type: "s3.bucket".into(),
        policy_id: "aws/test".into(),
        severity,
        title: format!("AWS Finding {id}"),
        description: "Test AWS finding".into(),
        provider: Provider::Aws,
    }
}

// === Health ===

#[tokio::test]
async fn health_check() {
    let (app, _) = test_app();
    let resp = app.oneshot(get("/api/v1/health")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// === Ingest ===

#[tokio::test]
async fn ingest_single_finding_creates_case() {
    let (app, store) = test_app();
    let scan = test_scan(vec![gcp_finding("f1", "gs://bucket", Severity::High)]);

    let resp = app.oneshot(json_post("/api/v1/ingest", &scan)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let result: IngestResponse = body_json(resp).await;
    assert_eq!(result.created.len(), 1);
    assert!(result.updated.is_empty());

    let cases = store.list(&ListParams::default()).await.unwrap();
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].status, Status::Open);
    assert_eq!(cases[0].severity, Severity::High);
    assert_eq!(cases[0].findings.len(), 1);
}

#[tokio::test]
async fn ingest_multiple_findings_same_resource_creates_one_case() {
    let (app, store) = test_app();
    let scan = test_scan(vec![
        gcp_finding("f1", "gs://bucket", Severity::Medium),
        gcp_finding("f2", "gs://bucket", Severity::Critical),
        gcp_finding("f3", "gs://bucket", Severity::Low),
    ]);

    let resp = app.oneshot(json_post("/api/v1/ingest", &scan)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let cases = store.list(&ListParams::default()).await.unwrap();
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].severity, Severity::Critical); // max of the group
    assert_eq!(cases[0].findings.len(), 3);
}

#[tokio::test]
async fn ingest_different_resources_creates_multiple_cases() {
    let (app, store) = test_app();
    let scan = test_scan(vec![
        gcp_finding("f1", "gs://bucket-a", Severity::High),
        gcp_finding("f2", "gs://bucket-b", Severity::Medium),
    ]);

    let resp = app.oneshot(json_post("/api/v1/ingest", &scan)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let cases = store.list(&ListParams::default()).await.unwrap();
    assert_eq!(cases.len(), 2);
}

#[tokio::test]
async fn ingest_re_ingest_does_not_duplicate() {
    let (_, store) = test_app();
    let scan = test_scan(vec![gcp_finding("f1", "gs://bucket", Severity::High)]);

    kase::ingest::ingest_scan(store.as_ref(), scan.clone()).await.unwrap();
    assert_eq!(store.list(&ListParams::default()).await.unwrap().len(), 1);

    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();
    assert_eq!(store.list(&ListParams::default()).await.unwrap().len(), 1);
}

#[tokio::test]
async fn ingest_finding_disappears_mitigates_case() {
    let (_, store) = test_app();

    // Scan 1: finding present
    let scan1 = test_scan(vec![gcp_finding("f1", "gs://bucket", Severity::High)]);
    kase::ingest::ingest_scan(store.as_ref(), scan1).await.unwrap();

    let cases = store.list(&ListParams::default()).await.unwrap();
    assert_eq!(cases[0].status, Status::Open);
    let case_id = cases[0].id;

    // Scan 2: finding gone (same provider)
    let scan2 = test_scan(vec![gcp_finding("f-other", "gs://other-bucket", Severity::Low)]);
    let result = kase::ingest::ingest_scan(store.as_ref(), scan2).await.unwrap();
    assert!(result.mitigated.contains(&case_id));

    let case = store.get(case_id).await.unwrap();
    assert_eq!(case.status, Status::Mitigated);
    assert!(case.findings[0].resolved_at.is_some());
}

#[tokio::test]
async fn ingest_finding_reappears_reopens_case() {
    let (_, store) = test_app();

    // Scan 1: create case
    let scan1 = test_scan(vec![gcp_finding("f1", "gs://bucket", Severity::High)]);
    kase::ingest::ingest_scan(store.as_ref(), scan1).await.unwrap();
    let case_id = store.list(&ListParams::default()).await.unwrap()[0].id;

    // Scan 2: finding gone → mitigated
    let scan2 = test_scan(vec![gcp_finding("f-other", "gs://other", Severity::Low)]);
    kase::ingest::ingest_scan(store.as_ref(), scan2).await.unwrap();
    assert_eq!(store.get(case_id).await.unwrap().status, Status::Mitigated);

    // Scan 3: finding reappears → reopened
    let scan3 = test_scan(vec![gcp_finding("f1", "gs://bucket", Severity::High)]);
    let result = kase::ingest::ingest_scan(store.as_ref(), scan3).await.unwrap();
    assert!(result.reopened.contains(&case_id));

    let case = store.get(case_id).await.unwrap();
    assert_eq!(case.status, Status::Open);
    assert!(case.closed_at.is_none());
    assert!(case.resolution.is_none());
}

#[tokio::test]
async fn ingest_provider_scoping_does_not_mitigate_other_providers() {
    let (_, store) = test_app();

    // Create an AWS case
    let scan1 = test_scan(vec![aws_finding("f-aws", "arn:s3:::bucket", Severity::High)]);
    kase::ingest::ingest_scan(store.as_ref(), scan1).await.unwrap();
    let aws_case_id = store.list(&ListParams::default()).await.unwrap()[0].id;

    // Ingest a GCP-only scan with no findings matching the AWS case
    let scan2 = test_scan(vec![gcp_finding("f-gcp", "gs://new-bucket", Severity::Low)]);
    kase::ingest::ingest_scan(store.as_ref(), scan2).await.unwrap();

    // The AWS case should NOT be mitigated by a GCP scan
    let aws_case = store.get(aws_case_id).await.unwrap();
    assert_eq!(aws_case.status, Status::Open, "AWS case should not be mitigated by GCP scan");
}

#[tokio::test]
async fn ingest_empty_scan_does_not_mitigate_anything() {
    let (_, store) = test_app();

    // Create a case
    let scan1 = test_scan(vec![gcp_finding("f1", "gs://bucket", Severity::High)]);
    kase::ingest::ingest_scan(store.as_ref(), scan1).await.unwrap();

    // Empty scan (no findings = no providers = no scoping match)
    let empty_scan = ScanResult {
        scan_id: "empty".into(),
        timestamp: chrono::Utc::now(),
        source: "test".into(),
        findings: vec![],
        attack_paths: vec![],
        chokepoints: vec![],
    };
    let result = kase::ingest::ingest_scan(store.as_ref(), empty_scan).await.unwrap();
    assert!(result.mitigated.is_empty(), "Empty scan should not mitigate any cases");
}

// === GET cases ===

#[tokio::test]
async fn list_cases_empty() {
    let (app, _) = test_app();
    let resp = app.oneshot(get("/api/v1/cases")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cases: Vec<Case> = body_json(resp).await;
    assert!(cases.is_empty());
}

#[tokio::test]
async fn get_existing_case() {
    let (app, store) = test_app();
    let scan = test_scan(vec![gcp_finding("f1", "gs://bucket", Severity::High)]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();
    let case_id = store.list(&ListParams::default()).await.unwrap()[0].id;

    let resp = app
        .oneshot(get(&format!("/api/v1/cases/{case_id}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let case: Case = body_json(resp).await;
    assert_eq!(case.id, case_id);
}

#[tokio::test]
async fn get_nonexistent_case_returns_404() {
    let (app, _) = test_app();
    let resp = app
        .oneshot(get("/api/v1/cases/01ARYZ6S41TSV4RRFFQ69G5FAV"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_invalid_ulid_returns_400() {
    let (app, _) = test_app();
    let resp = app
        .oneshot(get("/api/v1/cases/not-a-ulid"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// === PATCH cases ===

#[tokio::test]
async fn update_case_status() {
    let (app, store) = test_app();
    let scan = test_scan(vec![gcp_finding("f1", "gs://bucket", Severity::High)]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();
    let case_id = store.list(&ListParams::default()).await.unwrap()[0].id;

    let update = CaseUpdate {
        status: Some(Status::InProgress),
        ..Default::default()
    };
    let resp = app
        .oneshot(json_patch(&format!("/api/v1/cases/{case_id}"), &update))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let case: Case = body_json(resp).await;
    assert_eq!(case.status, Status::InProgress);
}

#[tokio::test]
async fn update_case_assignee() {
    let (app, store) = test_app();
    let scan = test_scan(vec![gcp_finding("f1", "gs://bucket", Severity::High)]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();
    let case_id = store.list(&ListParams::default()).await.unwrap()[0].id;

    let update = CaseUpdate {
        assignee: Some("alice".into()),
        ..Default::default()
    };
    let resp = app
        .oneshot(json_patch(&format!("/api/v1/cases/{case_id}"), &update))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let case: Case = body_json(resp).await;
    assert_eq!(case.assignee.as_deref(), Some("alice"));
}

#[tokio::test]
async fn update_status_to_closed_sets_closed_at() {
    let (app, store) = test_app();
    let scan = test_scan(vec![gcp_finding("f1", "gs://bucket", Severity::High)]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();
    let case_id = store.list(&ListParams::default()).await.unwrap()[0].id;

    let update = CaseUpdate {
        status: Some(Status::Closed),
        ..Default::default()
    };
    let resp = app
        .oneshot(json_patch(&format!("/api/v1/cases/{case_id}"), &update))
        .await
        .unwrap();
    let case: Case = body_json(resp).await;
    assert!(case.closed_at.is_some());
}

#[tokio::test]
async fn update_status_to_open_clears_resolution() {
    let (_, store) = test_app();
    let scan = test_scan(vec![gcp_finding("f1", "gs://bucket", Severity::High)]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();
    let case_id = store.list(&ListParams::default()).await.unwrap()[0].id;

    // First resolve it
    let resolution = Resolution {
        kind: ResolutionKind::Remediated,
        description: "Fixed".into(),
        evidence: None,
        verified_by_scan: None,
    };
    store.resolve(case_id, resolution, Status::Closed).await.unwrap();

    // Now reopen via update
    let update = CaseUpdate {
        status: Some(Status::Open),
        ..Default::default()
    };
    let case = store.update(case_id, update).await.unwrap();
    assert_eq!(case.status, Status::Open);
    assert!(case.closed_at.is_none(), "closed_at should be cleared");
    assert!(case.resolution.is_none(), "resolution should be cleared");
}

// === Notes ===

#[tokio::test]
async fn add_note_to_case() {
    let (app, store) = test_app();
    let scan = test_scan(vec![gcp_finding("f1", "gs://bucket", Severity::High)]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();
    let case_id = store.list(&ListParams::default()).await.unwrap()[0].id;

    let note = NoteRequest {
        author: "alice".into(),
        content: "Working on fix".into(),
    };
    let resp = app
        .oneshot(json_post(&format!("/api/v1/cases/{case_id}/notes"), &note))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let case: Case = body_json(resp).await;
    // Should have the system note from ingest + our new note
    assert!(case.notes.len() >= 2);
    assert_eq!(case.notes.last().unwrap().author, "alice");
    assert_eq!(case.notes.last().unwrap().content, "Working on fix");
}

#[tokio::test]
async fn add_note_to_nonexistent_returns_404() {
    let (app, _) = test_app();
    let note = NoteRequest {
        author: "alice".into(),
        content: "Test".into(),
    };
    let resp = app
        .oneshot(json_post(
            "/api/v1/cases/01ARYZ6S41TSV4RRFFQ69G5FAV/notes",
            &note,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// === Resolve ===

#[tokio::test]
async fn resolve_case_as_remediated() {
    let (app, store) = test_app();
    let scan = test_scan(vec![gcp_finding("f1", "gs://bucket", Severity::High)]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();
    let case_id = store.list(&ListParams::default()).await.unwrap()[0].id;

    let req = ResolveRequest {
        kind: ResolutionKind::Remediated,
        description: "Fixed via PR #42".into(),
        evidence: Some("https://github.com/org/repo/pull/42".into()),
    };
    let resp = app
        .oneshot(json_post(
            &format!("/api/v1/cases/{case_id}/resolve"),
            &req,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let case: Case = body_json(resp).await;
    assert_eq!(case.status, Status::Closed);
    assert!(case.closed_at.is_some());
    let resolution = case.resolution.unwrap();
    assert_eq!(resolution.kind, ResolutionKind::Remediated);
    assert_eq!(resolution.evidence.as_deref(), Some("https://github.com/org/repo/pull/42"));
}

#[tokio::test]
async fn resolve_case_as_accepted() {
    let (app, store) = test_app();
    let scan = test_scan(vec![gcp_finding("f1", "gs://bucket", Severity::Low)]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();
    let case_id = store.list(&ListParams::default()).await.unwrap()[0].id;

    let req = ResolveRequest {
        kind: ResolutionKind::Accepted,
        description: "Legacy system, decom in Q3".into(),
        evidence: None,
    };
    let resp = app
        .oneshot(json_post(
            &format!("/api/v1/cases/{case_id}/resolve"),
            &req,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let case: Case = body_json(resp).await;
    assert_eq!(case.status, Status::Accepted);
}

// === Merge ===

#[tokio::test]
async fn merge_cases() {
    let (app, store) = test_app();

    // Create two cases on different resources
    let scan = test_scan(vec![
        gcp_finding("f1", "gs://bucket-a", Severity::Low),
        gcp_finding("f2", "gs://bucket-b", Severity::Critical),
    ]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();

    let cases = store.list(&ListParams::default()).await.unwrap();
    assert_eq!(cases.len(), 2);
    // cases sorted by severity desc, so Critical first
    let (target, source) = (&cases[0], &cases[1]);
    let target_id = target.id;
    let source_id = source.id;

    let req = MergeRequest {
        source_case_id: source_id,
    };
    let resp = app
        .oneshot(json_post(
            &format!("/api/v1/cases/{target_id}/merge"),
            &req,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let merged: Case = body_json(resp).await;
    assert_eq!(merged.findings.len(), 2);
    assert_eq!(merged.severity, Severity::Critical);

    // Source should be deleted
    assert!(store.get(source_id).await.is_err());
    // Only one case remains
    assert_eq!(store.list(&ListParams::default()).await.unwrap().len(), 1);
}

#[tokio::test]
async fn merge_self_returns_400() {
    let (app, store) = test_app();
    let scan = test_scan(vec![gcp_finding("f1", "gs://bucket", Severity::High)]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();
    let case_id = store.list(&ListParams::default()).await.unwrap()[0].id;

    let req = MergeRequest {
        source_case_id: case_id,
    };
    let resp = app
        .oneshot(json_post(
            &format!("/api/v1/cases/{case_id}/merge"),
            &req,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Case should still exist
    assert!(store.get(case_id).await.is_ok());
}

// === Filters ===

#[tokio::test]
async fn filter_by_status() {
    let (_, store) = test_app();

    // Create cases and move one to InProgress
    let scan = test_scan(vec![
        gcp_finding("f1", "gs://a", Severity::High),
        gcp_finding("f2", "gs://b", Severity::Medium),
    ]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();
    let cases = store.list(&ListParams::default()).await.unwrap();
    store
        .update(
            cases[0].id,
            CaseUpdate {
                status: Some(Status::InProgress),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let open_cases = store
        .list(&ListParams {
            status: Some("open".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(open_cases.len(), 1);
    assert_eq!(open_cases[0].status, Status::Open);

    let in_progress = store
        .list(&ListParams {
            status: Some("in_progress".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(in_progress.len(), 1);
    assert_eq!(in_progress[0].status, Status::InProgress);
}

#[tokio::test]
async fn filter_by_severity() {
    let (_, store) = test_app();
    let scan = test_scan(vec![
        gcp_finding("f1", "gs://a", Severity::Critical),
        gcp_finding("f2", "gs://b", Severity::Low),
    ]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();

    let critical = store
        .list(&ListParams {
            severity: Some("critical".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(critical.len(), 1);
    assert_eq!(critical[0].severity, Severity::Critical);
}

#[tokio::test]
async fn filter_by_provider() {
    let (_, store) = test_app();
    let scan = test_scan(vec![
        gcp_finding("f1", "gs://bucket", Severity::High),
        aws_finding("f2", "arn:s3:::bucket", Severity::High),
    ]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();

    let gcp_cases = store
        .list(&ListParams {
            provider: Some("gcp".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(gcp_cases.len(), 1);
    assert_eq!(gcp_cases[0].provider, Provider::Gcp);
}

// === Metrics ===

#[tokio::test]
async fn metrics_with_cases() {
    let (app, store) = test_app();

    let scan = test_scan(vec![
        gcp_finding("f1", "gs://a", Severity::Critical),
        gcp_finding("f2", "gs://b", Severity::High),
        gcp_finding("f3", "gs://c", Severity::Low),
    ]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();

    // Resolve one case
    let cases = store.list(&ListParams::default()).await.unwrap();
    let resolution = Resolution {
        kind: ResolutionKind::Remediated,
        description: "Fixed".into(),
        evidence: None,
        verified_by_scan: None,
    };
    store
        .resolve(cases[0].id, resolution, Status::Closed)
        .await
        .unwrap();

    let resp = app.oneshot(get("/api/v1/metrics")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let m: CaseMetrics = body_json(resp).await;
    assert_eq!(m.total_open, 2);
    assert_eq!(m.total_closed, 1);
    assert!(m.mttr_hours.is_some());
    assert!(m.sla_compliance_pct.is_some());
}

// === Triage ===

#[tokio::test]
async fn triage_returns_priority_sorted_cases() {
    let (app, store) = test_app();
    let scan = test_scan(vec![
        gcp_finding("f1", "gs://a", Severity::Low),
        gcp_finding("f2", "gs://b", Severity::Critical),
        gcp_finding("f3", "gs://c", Severity::High),
    ]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();

    let resp = app.oneshot(get("/api/v1/triage")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let items: Vec<TriageItem> = body_json(resp).await;
    assert_eq!(items.len(), 3);
    // Should be sorted: Critical, High, Low
    assert_eq!(items[0].case.severity, Severity::Critical);
    assert_eq!(items[1].case.severity, Severity::High);
    assert_eq!(items[2].case.severity, Severity::Low);
    assert_eq!(items[0].rank, 1);
}

#[tokio::test]
async fn triage_respects_limit() {
    let (app, store) = test_app();
    let scan = test_scan(vec![
        gcp_finding("f1", "gs://a", Severity::Low),
        gcp_finding("f2", "gs://b", Severity::High),
        gcp_finding("f3", "gs://c", Severity::Critical),
    ]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();

    let resp = app
        .oneshot(get("/api/v1/triage?limit=1"))
        .await
        .unwrap();
    let items: Vec<TriageItem> = body_json(resp).await;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].case.severity, Severity::Critical);
}

#[tokio::test]
async fn triage_excludes_closed_cases() {
    let (app, store) = test_app();
    let scan = test_scan(vec![
        gcp_finding("f1", "gs://a", Severity::Critical),
        gcp_finding("f2", "gs://b", Severity::High),
    ]);
    kase::ingest::ingest_scan(store.as_ref(), scan).await.unwrap();

    // Close the critical case
    let cases = store.list(&ListParams::default()).await.unwrap();
    let critical_id = cases.iter().find(|c| c.severity == Severity::Critical).unwrap().id;
    let resolution = Resolution {
        kind: ResolutionKind::Remediated,
        description: "Fixed".into(),
        evidence: None,
        verified_by_scan: None,
    };
    store.resolve(critical_id, resolution, Status::Closed).await.unwrap();

    let resp = app.oneshot(get("/api/v1/triage")).await.unwrap();
    let items: Vec<TriageItem> = body_json(resp).await;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].case.severity, Severity::High);
}

// === Full lifecycle ===

#[tokio::test]
async fn full_lifecycle_ingest_to_close() {
    let (_, store) = test_app();

    // 1. Scan discovers finding
    let scan1 = test_scan(vec![gcp_finding(
        "vuln-1",
        "gs://sensitive-data",
        Severity::Critical,
    )]);
    let result = kase::ingest::ingest_scan(store.as_ref(), scan1).await.unwrap();
    assert_eq!(result.created.len(), 1);
    let case_id = result.created[0];

    // 2. Assign to engineer
    store
        .update(
            case_id,
            CaseUpdate {
                status: Some(Status::InProgress),
                assignee: Some("bryan".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // 3. Add a note
    store
        .add_note(
            case_id,
            Note {
                author: "bryan".into(),
                content: "Terraform PR opened".into(),
                created_at: chrono::Utc::now(),
            },
        )
        .await
        .unwrap();

    // 4. Resolve
    let resolution = Resolution {
        kind: ResolutionKind::Remediated,
        description: "Applied versioning policy".into(),
        evidence: Some("PR #42".into()),
        verified_by_scan: None,
    };
    store
        .resolve(case_id, resolution, Status::Closed)
        .await
        .unwrap();

    // 5. Next scan confirms fix (finding is gone) — no change since already closed
    let scan2 = test_scan(vec![gcp_finding(
        "other-vuln",
        "gs://other-bucket",
        Severity::Low,
    )]);
    let result2 = kase::ingest::ingest_scan(store.as_ref(), scan2).await.unwrap();
    assert!(result2.mitigated.is_empty()); // already closed, not re-mitigated

    // 6. Verify final state
    let case = store.get(case_id).await.unwrap();
    assert_eq!(case.status, Status::Closed);
    assert!(case.resolution.is_some());
    assert_eq!(case.assignee.as_deref(), Some("bryan"));
    assert!(case.notes.len() >= 2); // system note + manual note
}
