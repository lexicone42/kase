use crate::model::*;
use crate::sla;
use std::collections::HashMap;

/// Compute aggregate metrics across all cases.
pub fn compute(cases: &[Case]) -> CaseMetrics {
    let mut total_open = 0;
    let mut total_in_progress = 0;
    let mut total_mitigated = 0;
    let mut total_closed = 0;
    let mut total_accepted = 0;
    let mut overdue = 0;
    let mut by_severity: HashMap<String, usize> = HashMap::new();
    let mut by_provider: HashMap<String, usize> = HashMap::new();
    let mut remediation_hours = Vec::new();
    let mut sla_met = 0usize;
    let mut sla_total = 0usize;

    for case in cases {
        match case.status {
            Status::Open => total_open += 1,
            Status::InProgress => total_in_progress += 1,
            Status::Mitigated => total_mitigated += 1,
            Status::Closed => total_closed += 1,
            Status::Accepted => total_accepted += 1,
        }

        if sla::is_overdue(case.due_at)
            && !matches!(case.status, Status::Closed | Status::Accepted)
        {
            overdue += 1;
        }

        *by_severity.entry(case.severity.to_string()).or_default() += 1;
        *by_provider
            .entry(format!("{:?}", case.provider).to_lowercase())
            .or_default() += 1;

        // MTTR and SLA for resolved cases
        if let Some(closed_at) = case.closed_at {
            let hours = (closed_at - case.created_at).num_hours() as f64;
            remediation_hours.push(hours);

            sla_total += 1;
            if case.due_at.is_none_or(|d| closed_at <= d) {
                sla_met += 1;
            }
        }
    }

    let mttr_hours = if remediation_hours.is_empty() {
        None
    } else {
        let sum: f64 = remediation_hours.iter().sum();
        Some(sum / remediation_hours.len() as f64)
    };

    let sla_compliance_pct = if sla_total == 0 {
        None
    } else {
        Some(sla_met as f64 / sla_total as f64 * 100.0)
    };

    CaseMetrics {
        total_open,
        total_in_progress,
        total_mitigated,
        total_closed,
        total_accepted,
        overdue,
        mttr_hours,
        sla_compliance_pct,
        by_severity,
        by_provider,
    }
}
