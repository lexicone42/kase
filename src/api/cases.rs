use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use ulid::Ulid;

use crate::model::*;

use super::middleware::ApiError;
use super::AppState;

pub async fn list_cases(
    State(state): State<AppState>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<Case>>, ApiError> {
    let cases = state.store.list(&params).await?;
    Ok(Json(cases))
}

pub async fn get_case(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Case>, ApiError> {
    let id = parse_ulid(&id)?;
    let case = state.store.get(id).await?;
    Ok(Json(case))
}

pub async fn update_case(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(update): Json<CaseUpdate>,
) -> Result<Json<Case>, ApiError> {
    let id = parse_ulid(&id)?;
    let case = state.store.update(id, update).await?;
    Ok(Json(case))
}

pub async fn add_note(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<NoteRequest>,
) -> Result<Json<Case>, ApiError> {
    let id = parse_ulid(&id)?;
    let mut case = state.store.get(id).await?;
    case.notes.push(Note {
        author: req.author,
        content: req.content,
        created_at: chrono::Utc::now(),
    });
    case.updated_at = chrono::Utc::now();
    let case = state.store.save(case).await?;
    Ok(Json(case))
}

pub async fn resolve_case(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<Case>, ApiError> {
    let id = parse_ulid(&id)?;
    let mut case = state.store.get(id).await?;
    case.resolution = Some(Resolution {
        kind: req.kind,
        description: req.description,
        evidence: req.evidence,
        verified_by_scan: None,
    });
    case.status = match req.kind {
        ResolutionKind::Accepted => Status::Accepted,
        _ => Status::Closed,
    };
    case.closed_at = Some(chrono::Utc::now());
    case.updated_at = chrono::Utc::now();
    let case = state.store.save(case).await?;
    Ok(Json(case))
}

pub async fn merge_case(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    Json(req): Json<MergeRequest>,
) -> Result<Json<Case>, ApiError> {
    let target_id = parse_ulid(&target_id)?;
    let source = state.store.get(req.source_case_id).await?;
    let mut target = state.store.get(target_id).await?;

    // Merge findings
    for finding in source.findings {
        if !target
            .findings
            .iter()
            .any(|f| f.finding_id == finding.finding_id)
        {
            target.findings.push(finding);
        }
    }

    // Merge attack paths
    for path in source.attack_paths {
        if !target.attack_paths.contains(&path) {
            target.attack_paths.push(path);
        }
    }

    // Escalate severity if source is higher
    if source.severity > target.severity {
        target.severity = source.severity;
    }

    target.notes.push(Note {
        author: "kase-system".into(),
        content: format!("Merged from case {}", req.source_case_id),
        created_at: chrono::Utc::now(),
    });
    target.updated_at = chrono::Utc::now();

    let target = state.store.save(target).await?;
    state.store.delete(req.source_case_id).await?;

    Ok(Json(target))
}

fn parse_ulid(s: &str) -> Result<Ulid, ApiError> {
    s.parse().map_err(|_| ApiError {
        status: StatusCode::BAD_REQUEST,
        message: format!("invalid case ID: {s}"),
    })
}
