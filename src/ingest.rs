use crate::model::*;
use crate::sla;
use crate::store::{CaseStore, StoreResult};
use std::collections::{HashMap, HashSet};
use ulid::Ulid;

/// Ingest a scan result: group findings into cases, apply auto-transitions.
pub async fn ingest_scan(
    store: &dyn CaseStore,
    scan: ScanResult,
) -> StoreResult<IngestResponse> {
    let now = scan.timestamp;
    let mut created = Vec::new();
    let mut updated = Vec::new();
    let mut mitigated = Vec::new();
    let mut reopened = Vec::new();

    // Group findings by resource_id (remediation unit)
    let mut by_resource: HashMap<&str, Vec<&Finding>> = HashMap::new();
    for finding in &scan.findings {
        by_resource
            .entry(&finding.resource_id)
            .or_default()
            .push(finding);
    }

    // Snapshot existing open/in-progress cases for disappearance detection
    let all_cases = store.list(&ListParams::default()).await?;
    let mut seen_case_ids = HashSet::new();

    // Process each resource group
    for (resource_id, findings) in &by_resource {
        let existing = store.find_by_resource(resource_id).await?;

        match existing {
            Some(mut case) => {
                let case_id = case.id;
                seen_case_ids.insert(case_id);

                // Update existing finding refs, add new ones
                for finding in findings {
                    if let Some(fref) = case
                        .findings
                        .iter_mut()
                        .find(|f| f.finding_id == finding.id)
                    {
                        fref.last_seen = now;
                        fref.resolved_at = None;
                    } else {
                        case.findings.push(FindingRef {
                            finding_id: finding.id.clone(),
                            resource_id: finding.resource_id.clone(),
                            policy_id: finding.policy_id.clone(),
                            first_seen: now,
                            last_seen: now,
                            resolved_at: None,
                        });
                    }
                }

                // Reopen if previously mitigated/closed
                if matches!(case.status, Status::Mitigated | Status::Closed) {
                    case.status = Status::Open;
                    case.closed_at = None;
                    case.resolution = None;
                    case.notes.push(Note {
                        author: "kase-system".into(),
                        content: format!(
                            "Reopened: findings reappeared in scan {}",
                            scan.scan_id
                        ),
                        created_at: now,
                    });
                    case.updated_at = now;
                    store.save(case).await?;
                    reopened.push(case_id);
                } else {
                    case.updated_at = now;
                    store.save(case).await?;
                    updated.push(case_id);
                }
            }
            None => {
                let max_severity = findings
                    .iter()
                    .map(|f| f.severity)
                    .max()
                    .unwrap_or(Severity::Info);
                let provider = findings[0].provider;
                let title = if findings.len() == 1 {
                    findings[0].title.clone()
                } else {
                    format!("{} findings on {}", findings.len(), resource_id)
                };

                let id = Ulid::new();
                let case = Case {
                    id,
                    title,
                    status: Status::Open,
                    severity: max_severity,
                    assignee: None,
                    findings: findings
                        .iter()
                        .map(|f| FindingRef {
                            finding_id: f.id.clone(),
                            resource_id: f.resource_id.clone(),
                            policy_id: f.policy_id.clone(),
                            first_seen: now,
                            last_seen: now,
                            resolved_at: None,
                        })
                        .collect(),
                    attack_paths: Vec::new(),
                    provider,
                    created_at: now,
                    updated_at: now,
                    due_at: Some(sla::deadline(max_severity, now)),
                    closed_at: None,
                    resolution: None,
                    notes: vec![Note {
                        author: "kase-system".into(),
                        content: format!("Created from scan {}", scan.scan_id),
                        created_at: now,
                    }],
                    tags: Vec::new(),
                };
                store.save(case).await?;
                created.push(id);
            }
        }
    }

    // Auto-mitigate: cases whose findings all disappeared from this scan
    for case in &all_cases {
        if seen_case_ids.contains(&case.id) {
            continue;
        }
        if !matches!(case.status, Status::Open | Status::InProgress) {
            continue;
        }

        let all_gone = case
            .findings
            .iter()
            .all(|f| !scan.findings.iter().any(|sf| sf.id == f.finding_id));

        if all_gone {
            let mut updated_case = case.clone();
            updated_case.status = Status::Mitigated;
            updated_case.updated_at = now;
            for fref in &mut updated_case.findings {
                if fref.resolved_at.is_none() {
                    fref.resolved_at = Some(now);
                }
            }
            updated_case.notes.push(Note {
                author: "kase-system".into(),
                content: format!("Mitigated: findings absent from scan {}", scan.scan_id),
                created_at: now,
            });
            store.save(updated_case).await?;
            mitigated.push(case.id);
        }
    }

    Ok(IngestResponse {
        created,
        updated,
        mitigated,
        reopened,
    })
}
