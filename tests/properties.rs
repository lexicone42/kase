use chrono::{DateTime, Utc};
use proptest::prelude::*;
use std::collections::HashSet;

use kase::cli::truncate;
use kase::metrics;
use kase::model::*;
use kase::sla;
use kase::store::{CaseStore, InMemoryStore};

// === Strategies ===

fn arb_severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Info),
        Just(Severity::Low),
        Just(Severity::Medium),
        Just(Severity::High),
        Just(Severity::Critical),
    ]
}

fn arb_status() -> impl Strategy<Value = Status> {
    prop_oneof![
        Just(Status::Open),
        Just(Status::InProgress),
        Just(Status::Mitigated),
        Just(Status::Accepted),
        Just(Status::Closed),
    ]
}

fn arb_provider() -> impl Strategy<Value = Provider> {
    prop_oneof![
        Just(Provider::Gcp),
        Just(Provider::Aws),
        Just(Provider::Azure),
        Just(Provider::Github),
        Just(Provider::Workspace),
        Just(Provider::Other),
    ]
}

fn arb_datetime() -> impl Strategy<Value = DateTime<Utc>> {
    // Year 2000 to 2050
    (946684800i64..2524608000i64)
        .prop_map(|secs| DateTime::from_timestamp(secs, 0).unwrap())
}

fn arb_finding(provider: Provider) -> impl Strategy<Value = Finding> {
    (
        "[a-z0-9]{6,12}",
        "[a-z0-9:/-]{8,30}",
        "[a-z.]{5,15}",
        "[a-z./]{5,20}",
        arb_severity(),
        "[a-zA-Z ]{5,40}",
        "[a-zA-Z ]{10,80}",
    )
        .prop_map(
            move |(id, resource_id, resource_type, policy_id, severity, title, description)| {
                Finding {
                    id,
                    resource_id,
                    resource_type,
                    policy_id,
                    severity,
                    title,
                    description,
                    provider,
                }
            },
        )
}

fn arb_case() -> impl Strategy<Value = Case> {
    (
        arb_status(),
        arb_severity(),
        arb_provider(),
        arb_datetime(),
        arb_datetime(),
        prop::option::of(arb_datetime()),
    )
        .prop_map(
            |(status, severity, provider, created_at, updated_at, closed_at)| {
                let closed_at = if matches!(status, Status::Closed | Status::Accepted) {
                    closed_at.or(Some(updated_at))
                } else {
                    None
                };
                Case {
                    id: ulid::Ulid::new(),
                    title: "Test case".into(),
                    status,
                    severity,
                    assignee: None,
                    findings: vec![],
                    attack_paths: vec![],
                    provider,
                    created_at,
                    updated_at,
                    due_at: Some(sla::deadline(severity, created_at)),
                    closed_at,
                    resolution: None,
                    notes: vec![],
                    tags: vec![],
                }
            },
        )
}

// === truncate properties ===

proptest! {
    #[test]
    fn truncate_never_panics(s in "\\PC{0,200}", max in 0usize..200) {
        let _ = truncate(&s, max);
    }

    #[test]
    fn truncate_output_fits(s in "\\PC{0,200}", max in 4usize..200) {
        let result = truncate(&s, max);
        prop_assert!(result.chars().count() <= max,
            "truncate({:?}, {}) produced {} chars", s, max, result.chars().count());
    }

    #[test]
    fn truncate_preserves_short_strings(s in "[a-z]{0,10}") {
        let result = truncate(&s, 20);
        prop_assert_eq!(result, s);
    }
}

// === SLA properties ===

proptest! {
    #[test]
    fn sla_severity_monotonicity(from in arb_datetime()) {
        let deadlines = [
            sla::deadline(Severity::Critical, from),
            sla::deadline(Severity::High, from),
            sla::deadline(Severity::Medium, from),
            sla::deadline(Severity::Low, from),
            sla::deadline(Severity::Info, from),
        ];
        for i in 0..deadlines.len() - 1 {
            prop_assert!(deadlines[i] <= deadlines[i + 1],
                "Severity monotonicity violated: {:?} deadline ({}) > {:?} deadline ({})",
                [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info][i],
                deadlines[i],
                [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info][i+1],
                deadlines[i + 1]);
        }
    }

    #[test]
    fn sla_deadline_in_future(sev in arb_severity(), from in arb_datetime()) {
        let deadline = sla::deadline(sev, from);
        prop_assert!(deadline > from, "deadline {} should be after from {}", deadline, from);
    }
}

// === Status/Severity roundtrip properties ===

proptest! {
    #[test]
    fn status_display_fromstr_roundtrip(status in arb_status()) {
        let s = status.to_string();
        let parsed: Status = s.parse().unwrap();
        prop_assert_eq!(parsed, status);
    }

    #[test]
    fn severity_display_fromstr_roundtrip(sev in arb_severity()) {
        let s = sev.to_string();
        let parsed: Severity = s.parse().unwrap();
        prop_assert_eq!(parsed, sev);
    }

    #[test]
    fn provider_display_fromstr_roundtrip(prov in arb_provider()) {
        let s = prov.to_string();
        let parsed: Provider = s.parse().unwrap();
        prop_assert_eq!(parsed, prov);
    }
}

// === Metrics properties ===

proptest! {
    #[test]
    fn metrics_status_counts_sum_to_total(cases in prop::collection::vec(arb_case(), 0..50)) {
        let m = metrics::compute(&cases);
        let sum = m.total_open + m.total_in_progress + m.total_mitigated
            + m.total_closed + m.total_accepted;
        prop_assert_eq!(sum, cases.len(),
            "Status count sum {} != case count {}", sum, cases.len());
    }

    #[test]
    fn metrics_mttr_non_negative(cases in prop::collection::vec(arb_case(), 0..50)) {
        let m = metrics::compute(&cases);
        if let Some(mttr) = m.mttr_hours {
            prop_assert!(mttr >= 0.0, "MTTR should be non-negative, got {}", mttr);
        }
    }

    #[test]
    fn metrics_sla_compliance_bounded(cases in prop::collection::vec(arb_case(), 0..50)) {
        let m = metrics::compute(&cases);
        if let Some(pct) = m.sla_compliance_pct {
            prop_assert!(pct >= 0.0 && pct <= 100.0,
                "SLA compliance should be 0-100%, got {}", pct);
        }
    }

    #[test]
    fn metrics_severity_counts_sum(cases in prop::collection::vec(arb_case(), 0..50)) {
        let m = metrics::compute(&cases);
        let sum: usize = m.by_severity.values().sum();
        prop_assert_eq!(sum, cases.len());
    }

    #[test]
    fn metrics_provider_counts_sum(cases in prop::collection::vec(arb_case(), 0..50)) {
        let m = metrics::compute(&cases);
        let sum: usize = m.by_provider.values().sum();
        prop_assert_eq!(sum, cases.len());
    }
}

// === Ingest properties (async — use runtime block_on) ===

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn ingest_every_finding_tracked(
        findings in prop::collection::vec(arb_finding(Provider::Gcp), 1..15)
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = InMemoryStore::new();
            let scan = ScanResult {
                scan_id: "prop-test".into(),
                timestamp: Utc::now(),
                findings: findings.clone(),
                attack_paths: vec![],
                chokepoints: vec![],
            };
            kase::ingest::ingest_scan(&store, scan).await.unwrap();

            let cases = store.list(&ListParams::default()).await.unwrap();
            let tracked: HashSet<&str> = cases.iter()
                .flat_map(|c| c.findings.iter().map(|f| f.finding_id.as_str()))
                .collect();

            for f in &findings {
                prop_assert!(tracked.contains(f.id.as_str()),
                    "Finding {} not tracked in any case", f.id);
            }

            Ok(())
        })?;
    }

    #[test]
    fn ingest_case_count_lte_finding_count(
        findings in prop::collection::vec(arb_finding(Provider::Gcp), 1..15)
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = InMemoryStore::new();
            let scan = ScanResult {
                scan_id: "prop-test".into(),
                timestamp: Utc::now(),
                findings: findings.clone(),
                attack_paths: vec![],
                chokepoints: vec![],
            };
            kase::ingest::ingest_scan(&store, scan).await.unwrap();

            let cases = store.list(&ListParams::default()).await.unwrap();
            prop_assert!(cases.len() <= findings.len(),
                "Case count {} > finding count {}", cases.len(), findings.len());

            Ok(())
        })?;
    }

    #[test]
    fn ingest_idempotent(
        findings in prop::collection::vec(arb_finding(Provider::Gcp), 1..10)
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = InMemoryStore::new();
            let scan = ScanResult {
                scan_id: "prop-test".into(),
                timestamp: Utc::now(),
                findings: findings.clone(),
                attack_paths: vec![],
                chokepoints: vec![],
            };

            kase::ingest::ingest_scan(&store, scan.clone()).await.unwrap();
            let cases_after_first = store.list(&ListParams::default()).await.unwrap();

            kase::ingest::ingest_scan(&store, scan).await.unwrap();
            let cases_after_second = store.list(&ListParams::default()).await.unwrap();

            prop_assert_eq!(cases_after_first.len(), cases_after_second.len(),
                "Re-ingest created duplicates: {} -> {}", cases_after_first.len(), cases_after_second.len());

            Ok(())
        })?;
    }
}

// === Store roundtrip ===

proptest! {
    #[test]
    fn store_save_get_roundtrip(case in arb_case()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = InMemoryStore::new();
            let saved = store.save(case.clone()).await.unwrap();
            let retrieved = store.get(saved.id).await.unwrap();
            prop_assert_eq!(saved, retrieved);
            Ok(())
        })?;
    }
}
