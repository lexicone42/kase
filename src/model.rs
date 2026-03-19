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
    Workspace,
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
            "workspace" => Ok(Self::Workspace),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub timestamp: DateTime<Utc>,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub attack_paths: Vec<AttackPath>,
    #[serde(default)]
    pub chokepoints: Vec<Chokepoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
