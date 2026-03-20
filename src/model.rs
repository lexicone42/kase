use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

// === Core domain types ===

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Case {
    pub id: Ulid,
    pub title: String,
    pub status: Status,
    pub severity: Severity,
    pub assignee: Option<String>,
    pub findings: Vec<FindingRef>,
    pub attack_paths: Vec<String>,
    pub provider: Provider,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub due_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
    pub resolution: Option<Resolution>,
    pub notes: Vec<Note>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Open,
    InProgress,
    Mitigated,
    Accepted,
    Closed,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Mitigated => write!(f, "mitigated"),
            Self::Accepted => write!(f, "accepted"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

impl std::str::FromStr for Status {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(Self::Open),
            "in-progress" | "in_progress" => Ok(Self::InProgress),
            "mitigated" => Ok(Self::Mitigated),
            "accepted" => Ok(Self::Accepted),
            "closed" => Ok(Self::Closed),
            _ => Err(format!("unknown status: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(format!("unknown severity: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Gcp,
    Aws,
    Azure,
    Github,
    #[serde(alias = "google_workspace")]
    Workspace,
    Cloudflare,
    Other,
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gcp => write!(f, "gcp"),
            Self::Aws => write!(f, "aws"),
            Self::Azure => write!(f, "azure"),
            Self::Github => write!(f, "github"),
            Self::Workspace => write!(f, "workspace"),
            Self::Cloudflare => write!(f, "cloudflare"),
            Self::Other => write!(f, "other"),
        }
    }
}

impl std::str::FromStr for Provider {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "gcp" => Ok(Self::Gcp),
            "aws" => Ok(Self::Aws),
            "azure" => Ok(Self::Azure),
            "github" => Ok(Self::Github),
            "workspace" | "google_workspace" => Ok(Self::Workspace),
            "cloudflare" => Ok(Self::Cloudflare),
            "other" => Ok(Self::Other),
            _ => Err(format!("unknown provider: {s}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingRef {
    pub finding_id: String,
    pub resource_id: String,
    pub policy_id: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resolution {
    pub kind: ResolutionKind,
    pub description: String,
    pub evidence: Option<String>,
    pub verified_by_scan: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionKind {
    Remediated,
    Accepted,
    FalsePositive,
    Duplicate,
    WontFix,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Note {
    pub author: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
}

// === Scan ingest types (karkinos-compatible) ===

/// Accepts both kase's minimal format and karkinos's richer output.
/// Extra karkinos fields (duration_secs, providers_scanned, summary, etc.) are ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub timestamp: DateTime<Utc>,
    #[serde(default = "default_source")]
    pub source: String,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub attack_paths: Vec<AttackPath>,
    #[serde(default)]
    pub chokepoints: Vec<Chokepoint>,
}

fn default_source() -> String {
    "karkinos".into()
}

/// A finding from a scan. Accepts both kase's flat format and karkinos's
/// nested `resource: ResourceRef` format via custom deserialization.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub resource_id: String,
    pub resource_type: String,
    pub policy_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub provider: Provider,
}

// Custom deserializer that handles both flat (kase) and nested (karkinos) formats.
impl<'de> serde::Deserialize<'de> for Finding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ResourceRef {
            id: String,
            #[serde(default)]
            resource_type: String,
            provider: Provider,
        }

        #[derive(Deserialize)]
        struct RawFinding {
            id: String,
            policy_id: String,
            severity: Severity,
            title: String,
            description: String,
            // Flat format (kase native)
            resource_id: Option<String>,
            resource_type: Option<String>,
            provider: Option<Provider>,
            // Nested format (karkinos native)
            resource: Option<ResourceRef>,
        }

        let raw = RawFinding::deserialize(deserializer)?;

        // Prefer nested resource if present (karkinos format), fall back to flat fields
        let (resource_id, resource_type, provider) = if let Some(r) = raw.resource {
            (r.id, r.resource_type, r.provider)
        } else {
            (
                raw.resource_id
                    .ok_or_else(|| serde::de::Error::missing_field("resource_id or resource"))?,
                raw.resource_type.unwrap_or_default(),
                raw.provider
                    .ok_or_else(|| serde::de::Error::missing_field("provider or resource"))?,
            )
        };

        Ok(Finding {
            id: raw.id,
            resource_id,
            resource_type,
            policy_id: raw.policy_id,
            severity: raw.severity,
            title: raw.title,
            description: raw.description,
            provider,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub title: String,
    pub finding_ids: Vec<String>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chokepoint {
    pub resource_id: String,
    pub finding_ids: Vec<String>,
    pub severity: Severity,
}

// === API request/response types ===

#[derive(Debug, Default, Deserialize)]
pub struct ListParams {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub assignee: Option<String>,
    pub provider: Option<String>,
    pub overdue: Option<bool>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CaseUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NoteRequest {
    pub author: String,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResolveRequest {
    pub kind: ResolutionKind,
    pub description: String,
    pub evidence: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MergeRequest {
    pub source_case_id: Ulid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IngestResponse {
    pub created: Vec<Ulid>,
    pub updated: Vec<Ulid>,
    pub mitigated: Vec<Ulid>,
    pub reopened: Vec<Ulid>,
}

// === Triage ===

#[derive(Debug, Default, Deserialize)]
pub struct TriageParams {
    /// Max cases to return (default 5)
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TriageItem {
    pub case: Case,
    pub rank: usize,
    pub overdue: bool,
    /// Hours until SLA deadline (negative = past due)
    pub sla_hours_remaining: Option<f64>,
}

// === Metrics ===

#[derive(Debug, Serialize, Deserialize)]
pub struct CaseMetrics {
    pub total_open: usize,
    pub total_in_progress: usize,
    pub total_mitigated: usize,
    pub total_closed: usize,
    pub total_accepted: usize,
    pub overdue: usize,
    pub mttr_hours: Option<f64>,
    pub sla_compliance_pct: Option<f64>,
    pub by_severity: std::collections::HashMap<String, usize>,
    pub by_provider: std::collections::HashMap<String, usize>,
}
