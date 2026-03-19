# Kase — Cloud-Native Security Case Management

Companion to [karkinos](https://github.com/lexicone42/karkinos) (CSPM scanner). Tracks findings through their lifecycle: discovery → triage → remediation → verification → closure.

## Design Principles

1. **Multi-user, multi-agent from day 1.** Humans and Claude instances are both first-class participants. No local-only mode — the primary store is a cloud database.
2. **Cases track remediation, not detection.** The grouping unit is "what needs to be fixed," not "what was found." 20 buckets missing versioning = 1 case with 1 Terraform PR.
3. **Auto-transitions close the loop.** When karkinos scans and findings disappear, cases auto-advance. The human/Claude does the fix; kase verifies it.
4. **OTel-native observability.** Scan spans, case lifecycle spans, MTTR as trace duration. Queryable in Cloud Trace, Grafana, or any OTel backend.

## Architecture (GCP-native)

```
Scanner (Cloud Run Job)     Human (CLI)           Claude (Claude Code)
        │                       │                        │
        └───────────┬───────────┘────────────────────────┘
                    ▼
           Cloud Run Service (kase API)
                    │
        ┌───────────┼───────────────┐
        ▼           ▼               ▼
   Firestore    Cloud Tasks     Pub/Sub
   (state)      (SLA timers)    (events)
                                    │
                                    ▼
                              BigQuery (analytics sync)
```

### Three actors, one API

| Actor | How they call it | Auth |
|-------|-----------------|------|
| **Karkinos scanner** (Cloud Run Job) | HTTP POST to `/ingest` after each scan | Workload Identity (SA) |
| **Human** (CLI: `kase list`, `kase assign`) | HTTP via CLI client | ADC / `gcloud auth` |
| **Claude** (Claude Code terminal) | Same CLI as human | Same ADC |

### Why Firestore

- **Real-time listeners** — enables future web UI without polling
- **Document model** — cases are self-contained documents, good fit
- **Serverless** — no connection pools, no scaling config
- **Free tier** — 1GB, 50K reads/day, 20K writes/day covers small teams
- **Same auth** as everything else in the GCP ecosystem

### Why not SQLite

The original spec proposed SQLite. Problems:
- Single-user only (no concurrent Claude + human access)
- Requires `kase ingest` to run locally (can't be called from Cloud Run scanner)
- Sync to Firestore adds complexity that just using Firestore avoids
- No real-time capabilities

## Data Model

### Case

```rust
struct Case {
    id: Ulid,                       // monotonic, sortable
    title: String,                  // human/Claude-generated summary
    status: Status,                 // Open → InProgress → Mitigated → Closed (or Accepted)
    severity: Severity,             // mirrors karkinos severity
    assignee: Option<String>,       // email or handle
    findings: Vec<FindingRef>,      // karkinos finding IDs
    attack_paths: Vec<String>,      // related attack path titles
    provider: Provider,             // primary provider (for routing)
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    due_at: Option<DateTime<Utc>>,  // SLA deadline
    closed_at: Option<DateTime<Utc>>,
    resolution: Option<Resolution>,
    notes: Vec<Note>,               // audit trail
    tags: Vec<String>,
}

enum Status { Open, InProgress, Mitigated, Accepted, Closed }

struct Resolution {
    kind: ResolutionKind,           // Remediated | Accepted | FalsePositive | Duplicate | WontFix
    description: String,
    evidence: Option<String>,       // PR link, terraform plan, etc.
    verified_by_scan: Option<String>, // scan_id that confirmed fix
}
```

### Grouping: remediation units, not findings

Findings are grouped into cases by:
1. **Same resource** → same case (all findings on `gs://my-bucket` = 1 case)
2. **Same policy + resource pattern** → grouped case (12 buckets matching `data-lake-*` missing versioning = 1 case)
3. **Chokepoint** → cross-cutting case (karkinos chokepoint = 1 case covering all affected findings)
4. **Attack path** → end-to-end case (workflow vuln → OIDC → cloud admin = 1 case)

Override: `kase merge CASE_A CASE_B`, `kase split CASE_ID`.

### Auto-transitions

When karkinos scan results are ingested:

| Condition | Action |
|-----------|--------|
| New finding, no matching case | Create case (status: Open, SLA clock starts) |
| Finding still present, case exists | Update `last_seen`, no status change |
| Finding disappeared, case Open/InProgress | Move to Mitigated |
| Finding disappeared again in next scan | Move to Closed (verified) |
| Finding reappears after closure | Reopen with note |
| Case marked Accepted | Add finding IDs to karkinos baseline |

## API Design

REST API on Cloud Run. Firestore handles the persistence.

```
POST   /api/v1/ingest              # ScanResult JSON → create/update cases
GET    /api/v1/cases               # list (filters: status, severity, assignee, provider, overdue)
GET    /api/v1/cases/:id           # get single case
PATCH  /api/v1/cases/:id           # update (status, assignee, tags)
POST   /api/v1/cases/:id/notes     # add note
POST   /api/v1/cases/:id/resolve   # resolve with evidence
POST   /api/v1/cases/:id/merge     # merge another case into this one
GET    /api/v1/metrics             # MTTR, SLA compliance, trending
GET    /api/v1/health              # readiness probe
```

## CLI

The CLI is a thin HTTP client for the API. Same `kase` binary, just points at the Cloud Run URL.

```sh
# Configure
export KASE_URL=https://kase-xxxxx-uc.a.run.app

# Ingest (usually called by karkinos scanner, but can be manual)
kase ingest scan-result.json

# List / filter
kase list
kase list --status open,in-progress --severity critical,high
kase list --assignee bryan --overdue

# Triage
kase show CASE_ID
kase assign CASE_ID --to bryan
kase status CASE_ID in-progress
kase note CASE_ID "Terraform PR opened: https://github.com/..."
kase accept CASE_ID --reason "Legacy system, decommission in Q3"
kase close CASE_ID --resolution remediated --evidence "PR #42"

# Metrics
kase metrics
kase metrics --since 30d
```

## OTel Integration

### Scan spans (emitted by karkinos)

```
karkinos.scan
├── duration: 28.1s
├── attributes:
│   ├── scan.id: "abc123"
│   ├── resources.count: 208
│   ├── findings.count: 74
│   ├── findings.critical: 1
│   └── providers: ["gcp", "github", "workspace"]
└── events:
    ├── cross_provider_edges: 3
    └── attack_paths: 0
```

### Case lifecycle spans (emitted by kase)

```
kase.case.lifecycle
├── duration: 18h 23m (= MTTR for this case)
├── attributes:
│   ├── case.id: "KASE-01"
│   ├── case.severity: "critical"
│   ├── case.provider: "gcp"
│   ├── case.policy_ids: ["workspace/mfa-enforced"]
│   ├── case.finding_count: 1
│   └── case.resolution: "remediated"
└── events:
    ├── created: 2026-03-19T18:00:00Z
    ├── assigned: 2026-03-19T18:05:00Z (to: bryan)
    ├── status_changed: in_progress
    ├── note_added: "MFA enforcement enabled"
    ├── status_changed: mitigated
    └── closed: 2026-03-20T12:23:00Z (verified by scan def456)
```

### Metrics (derived from spans)

- **MTTR** = avg(case lifecycle span duration) where resolution = remediated
- **SLA compliance** = cases closed within SLA / total closed
- **Open case count** = gauge metric, emitted per scan
- **Finding detection-to-fix latency** = first_seen → resolved_at on FindingRef

## Crate Structure

```
kase/
├── Cargo.toml
├── DESIGN.md              # this file
├── src/
│   ├── main.rs            # CLI entry point (clap)
│   ├── lib.rs             # public API
│   ├── model.rs           # Case, FindingRef, Resolution, Note, Status
│   ├── api/
│   │   ├── mod.rs         # axum router setup
│   │   ├── ingest.rs      # POST /ingest — ScanResult → Cases
│   │   ├── cases.rs       # CRUD endpoints
│   │   ├── metrics.rs     # GET /metrics
│   │   └── middleware.rs   # auth, tracing, error handling
│   ├── store/
│   │   ├── mod.rs         # CaseStore trait
│   │   └── firestore.rs   # Firestore implementation
│   ├── ingest.rs          # Grouping logic: findings → cases
│   ├── sla.rs             # SLA calculation, deadline management
│   ├── metrics.rs         # MTTR, compliance, trending computation
│   ├── otel.rs            # OpenTelemetry setup (traces + metrics)
│   └── cli.rs             # CLI commands (thin HTTP client)
├── deploy/
│   ├── kase.smelt         # Smelt IaC (Cloud Run + Firestore + Pub/Sub)
│   ├── Dockerfile
│   └── cloudbuild.yaml
└── tests/
    └── integration.rs
```

## Dependencies

```toml
[dependencies]
# API framework
axum = "0.8"
tokio = { version = "1", features = ["full"] }
tower = "0.5"
tower-http = { version = "0.6", features = ["cors", "trace"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# CLI
clap = { version = "4", features = ["derive"] }

# GCP
google-cloud-firestore = "0.6"
gcp_auth = "0.12"

# Observability
opentelemetry = "0.28"
opentelemetry-otlp = "0.28"
opentelemetry_sdk = "0.28"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
tracing-opentelemetry = "0.28"

# Time / IDs
chrono = { version = "0.4", features = ["serde"] }
ulid = "1"

# HTTP client (for CLI)
reqwest = { version = "0.12", features = ["json", "rustls-tls-native-roots"], default-features = false }
```

## GCP Resources Needed

For the kase service itself:
- `run.googleapis.com` — Cloud Run service (the API)
- `firestore.googleapis.com` — Firestore database
- `cloudtasks.googleapis.com` — SLA deadline timers (optional)
- `pubsub.googleapis.com` — Case events (optional)

IAM:
- kase service account needs `roles/datastore.user` (Firestore read/write)
- karkinos scanner SA needs permission to call the kase Cloud Run service (`roles/run.invoker`)

## Relationship to Karkinos

Karkinos scans → produces ScanResult JSON → kase ingests it.

Two integration modes:
1. **Pipeline**: `karkinos scan --save scan.json && kase ingest scan.json` (scanner pushes to kase API)
2. **Direct**: karkinos Cloud Run Job calls kase API as a post-scan step (configured via `[export.kase]` in config.toml)

Kase reads karkinos's `ScanResult` type directly — shared via a `karkinos-model` crate or just serde-compatible JSON. The model types (Finding, AttackPath, Chokepoint, etc.) are the contract.

## Learning Goals

This project is explicitly a vehicle for learning:
- **GCP services**: Firestore, Cloud Run, Cloud Tasks, Pub/Sub, IAM
- **OpenTelemetry**: Traces, metrics, OTLP export, Cloud Trace integration
- **axum**: Rust async web framework
- **Cloud-native Rust**: Building services that deploy to GCP
