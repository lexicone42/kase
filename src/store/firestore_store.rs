use async_trait::async_trait;
use chrono::Utc;
use firestore::*;
use ulid::Ulid;

use crate::model::*;

use super::{apply_filters_and_sort, CaseStore, StoreError, StoreResult};

const COLLECTION: &str = "cases";

fn to_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Internal(e.to_string())
}

pub struct FirestoreStore {
    db: FirestoreDb,
}

impl FirestoreStore {
    pub async fn new(project_id: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let db = FirestoreDb::new(project_id).await?;
        Ok(Self { db })
    }
}

#[async_trait]
impl CaseStore for FirestoreStore {
    async fn save(&self, case: Case) -> StoreResult<Case> {
        let id = case.id.to_string();

        // Try insert; if already exists, delete and re-insert.
        // Firestore's update requires field masks which are awkward for full-doc replacement.
        let result = self
            .db
            .fluent()
            .insert()
            .into(COLLECTION)
            .document_id(&id)
            .object(&case)
            .execute::<Case>()
            .await;

        match result {
            Ok(_) => Ok(case),
            Err(_) => {
                // Document exists — delete and re-create
                let _ = self
                    .db
                    .fluent()
                    .delete()
                    .from(COLLECTION)
                    .document_id(&id)
                    .execute()
                    .await;
                self.db
                    .fluent()
                    .insert()
                    .into(COLLECTION)
                    .document_id(&id)
                    .object(&case)
                    .execute::<Case>()
                    .await
                    .map_err(to_err)?;
                Ok(case)
            }
        }
    }

    async fn get(&self, id: Ulid) -> StoreResult<Case> {
        let doc: Option<Case> = self
            .db
            .fluent()
            .select()
            .by_id_in(COLLECTION)
            .obj()
            .one(id.to_string())
            .await
            .map_err(to_err)?;
        doc.ok_or(StoreError::NotFound(id))
    }

    async fn list(&self, params: &ListParams) -> StoreResult<Vec<Case>> {
        // Fetch all cases, filter in memory.
        // Firestore composite queries can't handle our dynamic filter combos.
        let mut cases: Vec<Case> = self
            .db
            .fluent()
            .select()
            .from(COLLECTION)
            .obj()
            .query()
            .await
            .map_err(to_err)?;

        apply_filters_and_sort(&mut cases, params);
        Ok(cases)
    }

    async fn update(&self, id: Ulid, update: CaseUpdate) -> StoreResult<Case> {
        let mut case = self.get(id).await?;

        if let Some(status) = update.status {
            case.status = status;
            if matches!(status, Status::Closed | Status::Accepted) {
                case.closed_at = Some(Utc::now());
            } else {
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

        self.save(case.clone()).await?;
        Ok(case)
    }

    async fn delete(&self, id: Ulid) -> StoreResult<()> {
        // Verify it exists first
        self.get(id).await?;
        self.db
            .fluent()
            .delete()
            .from(COLLECTION)
            .document_id(id.to_string())
            .execute()
            .await
            .map_err(to_err)?;
        Ok(())
    }

    async fn find_by_resource(&self, resource_id: &str) -> StoreResult<Option<Case>> {
        // Firestore can't query nested array fields this way;
        // fetch all and filter in memory.
        let cases: Vec<Case> = self
            .db
            .fluent()
            .select()
            .from(COLLECTION)
            .obj()
            .query()
            .await
            .map_err(to_err)?;

        Ok(cases
            .into_iter()
            .find(|c| c.findings.iter().any(|f| f.resource_id == resource_id)))
    }

    async fn find_by_finding(&self, finding_id: &str) -> StoreResult<Option<Case>> {
        let cases: Vec<Case> = self
            .db
            .fluent()
            .select()
            .from(COLLECTION)
            .obj()
            .query()
            .await
            .map_err(to_err)?;

        Ok(cases
            .into_iter()
            .find(|c| c.findings.iter().any(|f| f.finding_id == finding_id)))
    }

    async fn add_note(&self, id: Ulid, note: Note) -> StoreResult<Case> {
        let mut case = self.get(id).await?;
        case.notes.push(note);
        case.updated_at = Utc::now();
        self.save(case.clone()).await?;
        Ok(case)
    }

    async fn resolve(
        &self,
        id: Ulid,
        resolution: Resolution,
        status: Status,
    ) -> StoreResult<Case> {
        let mut case = self.get(id).await?;
        case.resolution = Some(resolution);
        case.status = status;
        case.closed_at = Some(Utc::now());
        case.updated_at = Utc::now();
        self.save(case.clone()).await?;
        Ok(case)
    }
}
