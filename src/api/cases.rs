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
    let note = Note {
        author: req.author,
        content: req.content,
        created_at: chrono::Utc::now(),
    };
    let case = state.store.add_note(id, note).await?;
    Ok(Json(case))
}

pub async fn resolve_case(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<Case>, ApiError> {
    let id = parse_ulid(&id)?;
    let resolution = Resolution {
        kind: req.kind,
        description: req.description,
        evidence: req.evidence,
        verified_by_scan: None,
    };
    let status = match req.kind {
        ResolutionKind::Accepted => Status::Accepted,
        _ => Status::Closed,
    };
    let case = state.store.resolve(id, resolution, status).await?;
    Ok(Json(case))
}

pub async fn merge_case(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    Json(req): Json<MergeRequest>,
) -> Result<Json<Case>, ApiError> {
    let target_id = parse_ulid(&target_id)?;

    // Prevent self-merge (would delete the case)
    if target_id == req.source_case_id {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            message: "cannot merge a case into itself".into(),
        });
    }

    let source = state.store.get(req.source_case_id).await?;
    let mut target = state.store.get(target_id).await?;

    // Merge findings (deduplicate by finding_id)
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

pub async fn triage(
    State(state): State<AppState>,
    Query(params): Query<TriageParams>,
) -> Result<Json<Vec<TriageItem>>, ApiError> {
    // Get open and in-progress cases
    let mut cases = state
        .store
        .list(&ListParams {
            status: Some("open,in_progress".into()),
            ..Default::default()
        })
        .await?;

    let now = chrono::Utc::now();

    // Sort by triage priority: overdue first, then severity, then finding count, then age
    cases.sort_by(|a, b| {
        let a_overdue = a.due_at.is_some_and(|d| d < now);
        let b_overdue = b.due_at.is_some_and(|d| d < now);

        b_overdue
            .cmp(&a_overdue)
            .then_with(|| {
                if a_overdue && b_overdue {
                    a.due_at.cmp(&b.due_at) // most overdue first
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .then_with(|| b.severity.cmp(&a.severity))
            .then_with(|| b.findings.len().cmp(&a.findings.len()))
            .then_with(|| a.created_at.cmp(&b.created_at))
    });

    let limit = params.limit.unwrap_or(5);
    let items: Vec<TriageItem> = cases
        .into_iter()
        .take(limit)
        .enumerate()
        .map(|(i, case)| {
            let overdue = case.due_at.is_some_and(|d| d < now);
            let sla_hours_remaining = case
                .due_at
                .map(|d| (d - now).num_minutes() as f64 / 60.0);
            TriageItem {
                case,
                rank: i + 1,
                overdue,
                sla_hours_remaining,
            }
        })
        .collect();

    Ok(Json(items))
}

fn parse_ulid(s: &str) -> Result<Ulid, ApiError> {
    s.parse().map_err(|_| ApiError {
        status: StatusCode::BAD_REQUEST,
        message: "invalid case ID format".into(),
    })
}
