# Kase — Development Guide

Security case management system. Companion to [karkinos](https://github.com/lexicone42/karkinos) (CSPM scanner).

## Build & Test

```sh
cargo build              # build
cargo test               # 45 tests (28 integration + 17 property)
cargo run -- serve       # start API server on 127.0.0.1:3000
cargo run -- --help      # CLI usage
```

## Architecture

```
kase binary (single binary, two modes)
├── serve mode:  axum API server (port 3000)
│   ├── POST /api/v1/ingest       ← karkinos pushes ScanResult here
│   ├── GET/PATCH /api/v1/cases/* ← CRUD + notes + resolve + merge
│   └── GET /api/v1/metrics       ← MTTR, SLA compliance
└── CLI mode:    thin reqwest client pointing at KASE_URL
    └── kase list, show, assign, status, note, accept, close, metrics
```

**Store trait** (`src/store/mod.rs`): `CaseStore` with async methods. `InMemoryStore` for dev, Firestore planned for production.

**Ingest engine** (`src/ingest.rs`): Groups findings by `resource_id` into cases. Auto-transitions: new→Open, disappeared→Mitigated, reappeared→Reopened.

## Critical Invariants

1. **Provider-scoped auto-mitigation**: The ingest engine only auto-mitigates cases whose `provider` matches a provider seen in the current scan. A GCP scan must NOT mitigate AWS cases. An empty scan mitigates nothing. This was the most dangerous bug found during hardening.

2. **Atomic store operations**: `add_note()` and `resolve()` are trait methods (not get+save) to avoid TOCTOU races under concurrent access. `merge()` still uses get+save — be careful here.

3. **Status state cleanup**: When `update()` moves a case to a non-terminal status (Open, InProgress, Mitigated), it clears `closed_at` and `resolution`. This prevents stale resolution data on reopened cases.

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `Case` | `model.rs` | Core entity — findings, status, SLA, notes |
| `ScanResult` | `model.rs` | Input from karkinos scans |
| `CaseStore` | `store/mod.rs` | Async trait for persistence |
| `IngestResponse` | `model.rs` | Created/updated/mitigated/reopened counts |
| `CaseMetrics` | `model.rs` | Aggregated MTTR, SLA, status breakdowns |

## Testing

- **Property tests** (`tests/properties.rs`): proptest-based. Truncate safety, SLA monotonicity, enum roundtrips, metrics invariants, ingest correctness.
- **Integration tests** (`tests/integration.rs`): Full API through axum router using tower::oneshot. Covers all endpoints, ingest lifecycle, filters, merge, full end-to-end.

## CLI JSON Mode

All CLI commands support `--json` for machine-readable output (useful for Claude agents):
```sh
kase list --json
kase show CASE_ID --json
kase metrics --json
```

## Quick Smoke Test

```sh
cargo run -- serve &
sleep 1
cargo run -- ingest examples/scan-result.json
cargo run -- list
cargo run -- metrics
kill %1
```

## Deployment Target

- GCP project in a "Security Tooling" resource folder
- Cloud Run for the API service
- Firestore for persistence
- Cloud Trace + Cloud Monitoring for OTel data
- See `deploy/` for Dockerfile and Cloud Build config
