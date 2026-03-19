use crate::model::Severity;
use chrono::{DateTime, Duration, Utc};

/// Calculate SLA deadline based on severity.
pub fn deadline(severity: Severity, from: DateTime<Utc>) -> DateTime<Utc> {
    let hours = match severity {
        Severity::Critical => 24,   // 1 day
        Severity::High => 72,       // 3 days
        Severity::Medium => 168,    // 7 days
        Severity::Low => 720,       // 30 days
        Severity::Info => 2160,     // 90 days
    };
    from + Duration::hours(hours)
}

/// Check if a case is overdue.
pub fn is_overdue(due_at: Option<DateTime<Utc>>) -> bool {
    due_at.is_some_and(|d| d < Utc::now())
}
