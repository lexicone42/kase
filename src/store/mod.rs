use crate::model::*;
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use ulid::Ulid;

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("case not found: {0}")]
    NotFound(Ulid),
    #[error("{0}")]
    Internal(String),
}

#[async_trait]
pub trait CaseStore: Send + Sync {
    async fn save(&self, case: Case) -> StoreResult<Case>;
    async fn get(&self, id: Ulid) -> StoreResult<Case>;
    async fn list(&self, params: &ListParams) -> StoreResult<Vec<Case>>;
    async fn update(&self, id: Ulid, update: CaseUpdate) -> StoreResult<Case>;
    async fn delete(&self, id: Ulid) -> StoreResult<()>;
    async fn find_by_resource(&self, resource_id: &str) -> StoreResult<Option<Case>>;
    async fn find_by_finding(&self, finding_id: &str) -> StoreResult<Option<Case>>;

    /// Atomically add a note to a case (avoids TOCTOU with get+save).
    async fn add_note(&self, id: Ulid, note: Note) -> StoreResult<Case>;

    /// Atomically resolve a case (avoids TOCTOU with get+save).
    async fn resolve(
        &self,
        id: Ulid,
        resolution: Resolution,
        status: Status,
    ) -> StoreResult<Case>;
}

#[derive(Debug, Default, Clone)]
pub struct InMemoryStore {
    cases: Arc<RwLock<HashMap<Ulid, Case>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CaseStore for InMemoryStore {
    async fn save(&self, case: Case) -> StoreResult<Case> {
        let mut cases = self.cases.write().await;
        cases.insert(case.id, case.clone());
        Ok(case)
    }

    async fn get(&self, id: Ulid) -> StoreResult<Case> {
        let cases = self.cases.read().await;
        cases.get(&id).cloned().ok_or(StoreError::NotFound(id))
    }

    async fn list(&self, params: &ListParams) -> StoreResult<Vec<Case>> {
        let cases = self.cases.read().await;
        let mut result: Vec<Case> = cases.values().cloned().collect();

        if let Some(ref status_str) = params.status {
            let statuses: Vec<Status> = status_str
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            if !statuses.is_empty() {
                result.retain(|c| statuses.contains(&c.status));
            }
        }

        if let Some(ref sev_str) = params.severity {
            let severities: Vec<Severity> = sev_str
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            if !severities.is_empty() {
                result.retain(|c| severities.contains(&c.severity));
            }
        }

        if let Some(ref assignee) = params.assignee {
            result.retain(|c| c.assignee.as_deref() == Some(assignee.as_str()));
        }

        if let Some(ref prov_str) = params.provider {
            let providers: Vec<Provider> = prov_str
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            if !providers.is_empty() {
                result.retain(|c| providers.contains(&c.provider));
            }
        }

        if params.overdue == Some(true) {
            let now = Utc::now();
            result.retain(|c| {
                c.due_at.is_some_and(|d| d < now)
                    && !matches!(c.status, Status::Closed | Status::Accepted)
            });
        }

        // Sort by severity (desc) then created_at (desc)
        result.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| b.created_at.cmp(&a.created_at))
        });

        Ok(result)
    }

    async fn update(&self, id: Ulid, update: CaseUpdate) -> StoreResult<Case> {
        let mut cases = self.cases.write().await;
        let case = cases.get_mut(&id).ok_or(StoreError::NotFound(id))?;

        if let Some(status) = update.status {
            case.status = status;
            if matches!(status, Status::Closed | Status::Accepted) {
                case.closed_at = Some(Utc::now());
            } else {
                // Clear terminal-state fields when moving to non-terminal status
                case.closed_at = None;
                case.resolution = None;
            }
        }
        if let Some(assignee) = update.assignee {
            case.assignee = Some(assignee);
        }
        if let Some(severity) = update.severity {
            case.severity = severity;
        }
        if let Some(tags) = update.tags {
            case.tags = tags;
        }
        if let Some(due_at) = update.due_at {
            case.due_at = Some(due_at);
        }
        case.updated_at = Utc::now();

        Ok(case.clone())
    }

    async fn delete(&self, id: Ulid) -> StoreResult<()> {
        let mut cases = self.cases.write().await;
        cases.remove(&id).ok_or(StoreError::NotFound(id))?;
        Ok(())
    }

    async fn find_by_resource(&self, resource_id: &str) -> StoreResult<Option<Case>> {
        let cases = self.cases.read().await;
        Ok(cases
            .values()
            .find(|c| c.findings.iter().any(|f| f.resource_id == resource_id))
            .cloned())
    }

    async fn find_by_finding(&self, finding_id: &str) -> StoreResult<Option<Case>> {
        let cases = self.cases.read().await;
        Ok(cases
            .values()
            .find(|c| c.findings.iter().any(|f| f.finding_id == finding_id))
            .cloned())
    }

    async fn add_note(&self, id: Ulid, note: Note) -> StoreResult<Case> {
        let mut cases = self.cases.write().await;
        let case = cases.get_mut(&id).ok_or(StoreError::NotFound(id))?;
        case.notes.push(note);
        case.updated_at = Utc::now();
        Ok(case.clone())
    }

    async fn resolve(
        &self,
        id: Ulid,
        resolution: Resolution,
        status: Status,
    ) -> StoreResult<Case> {
        let mut cases = self.cases.write().await;
        let case = cases.get_mut(&id).ok_or(StoreError::NotFound(id))?;
        case.resolution = Some(resolution);
        case.status = status;
        case.closed_at = Some(Utc::now());
        case.updated_at = Utc::now();
        Ok(case.clone())
    }
}
