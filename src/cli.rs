use crate::model::*;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use reqwest::Client;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "kase", about = "Cloud-native security case management")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// API server URL
    #[arg(
        long,
        env = "KASE_URL",
        default_value = "http://localhost:3000",
        global = true
    )]
    pub url: String,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start the API server
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value = "3000")]
        port: u16,
        /// Bind address (use 0.0.0.0 for network access)
        #[arg(short, long, default_value = "127.0.0.1")]
        bind: String,
    },
    /// Ingest a scan result file
    Ingest {
        /// Path to scan result JSON file
        path: PathBuf,
    },
    /// List cases
    List {
        /// Filter by status (comma-separated: open,in-progress)
        #[arg(long)]
        status: Option<String>,
        /// Filter by severity (comma-separated: critical,high)
        #[arg(long)]
        severity: Option<String>,
        /// Filter by assignee
        #[arg(long)]
        assignee: Option<String>,
        /// Show only overdue cases
        #[arg(long)]
        overdue: bool,
    },
    /// Show a single case
    Show {
        /// Case ID (ULID)
        id: String,
    },
    /// Assign a case
    Assign {
        /// Case ID
        id: String,
        /// Assignee
        #[arg(long)]
        to: String,
    },
    /// Update case status
    Status {
        /// Case ID
        id: String,
        /// New status (open, in-progress, mitigated, accepted, closed)
        status: String,
    },
    /// Add a note to a case
    Note {
        /// Case ID
        id: String,
        /// Note message
        message: String,
        /// Author (defaults to $USER)
        #[arg(long, env = "USER")]
        author: Option<String>,
    },
    /// Accept risk for a case
    Accept {
        /// Case ID
        id: String,
        /// Reason for acceptance
        #[arg(long)]
        reason: String,
    },
    /// Close/resolve a case
    Close {
        /// Case ID
        id: String,
        /// Resolution type (remediated, false-positive, duplicate, wont-fix)
        #[arg(long, default_value = "remediated")]
        resolution: String,
        /// Evidence (e.g. PR link)
        #[arg(long)]
        evidence: Option<String>,
    },
    /// Show metrics
    Metrics,
}

pub async fn execute(cli: Cli) -> Result<()> {
    let client = Client::new();
    let base = cli.url.trim_end_matches('/');

    match cli.command {
        Command::Serve { .. } => unreachable!("handled in main"),

        Command::Ingest { path } => {
            let data = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let scan: ScanResult = serde_json::from_str(&data)
                .with_context(|| format!("parsing {}", path.display()))?;
            let resp: IngestResponse = client
                .post(format!("{base}/api/v1/ingest"))
                .json(&scan)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!(
                "Created: {} | Updated: {} | Mitigated: {} | Reopened: {}",
                resp.created.len(),
                resp.updated.len(),
                resp.mitigated.len(),
                resp.reopened.len()
            );
        }

        Command::List {
            status,
            severity,
            assignee,
            overdue,
        } => {
            let mut request = client.get(format!("{base}/api/v1/cases"));
            if let Some(ref s) = status {
                request = request.query(&[("status", s)]);
            }
            if let Some(ref s) = severity {
                request = request.query(&[("severity", s)]);
            }
            if let Some(ref a) = assignee {
                request = request.query(&[("assignee", a)]);
            }
            if overdue {
                request = request.query(&[("overdue", "true")]);
            }

            let cases: Vec<Case> = request
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            if cases.is_empty() {
                println!("No cases found.");
                return Ok(());
            }

            println!(
                "{:<28} {:<12} {:<10} {:<15} {}",
                "ID", "STATUS", "SEVERITY", "ASSIGNEE", "TITLE"
            );
            println!("{}", "-".repeat(80));
            for case in &cases {
                println!(
                    "{:<28} {:<12} {:<10} {:<15} {}",
                    case.id,
                    case.status,
                    case.severity,
                    case.assignee.as_deref().unwrap_or("-"),
                    truncate(&case.title, 40),
                );
            }
            println!("\n{} case(s)", cases.len());
        }

        Command::Show { id } => {
            let case: Case = client
                .get(format!("{base}/api/v1/cases/{id}"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            print_case(&case);
        }

        Command::Assign { id, to } => {
            let update = CaseUpdate {
                assignee: Some(to.clone()),
                ..Default::default()
            };
            let case: Case = client
                .patch(format!("{base}/api/v1/cases/{id}"))
                .json(&update)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("Assigned {} to {}", case.id, to);
        }

        Command::Status { id, status } => {
            let parsed: crate::model::Status =
                status.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            let update = CaseUpdate {
                status: Some(parsed),
                ..Default::default()
            };
            let case: Case = client
                .patch(format!("{base}/api/v1/cases/{id}"))
                .json(&update)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("Updated {} -> {}", case.id, case.status);
        }

        Command::Note {
            id,
            message,
            author,
        } => {
            let req = NoteRequest {
                author: author.unwrap_or_else(|| "unknown".into()),
                content: message,
            };
            let _case: Case = client
                .post(format!("{base}/api/v1/cases/{id}/notes"))
                .json(&req)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("Note added to {id}");
        }

        Command::Accept { id, reason } => {
            let req = ResolveRequest {
                kind: ResolutionKind::Accepted,
                description: reason,
                evidence: None,
            };
            let case: Case = client
                .post(format!("{base}/api/v1/cases/{id}/resolve"))
                .json(&req)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("Accepted risk for {} -> {}", case.id, case.status);
        }

        Command::Close {
            id,
            resolution,
            evidence,
        } => {
            let kind = match resolution.as_str() {
                "remediated" => ResolutionKind::Remediated,
                "false-positive" | "false_positive" => ResolutionKind::FalsePositive,
                "duplicate" => ResolutionKind::Duplicate,
                "wont-fix" | "wont_fix" => ResolutionKind::WontFix,
                other => anyhow::bail!("unknown resolution: {other}"),
            };
            let req = ResolveRequest {
                kind,
                description: format!("Closed as {resolution}"),
                evidence,
            };
            let case: Case = client
                .post(format!("{base}/api/v1/cases/{id}/resolve"))
                .json(&req)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("Closed {} -> {}", case.id, case.status);
        }

        Command::Metrics => {
            let metrics: CaseMetrics = client
                .get(format!("{base}/api/v1/metrics"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!(
                "Cases: {} open, {} in-progress, {} mitigated, {} closed, {} accepted",
                metrics.total_open,
                metrics.total_in_progress,
                metrics.total_mitigated,
                metrics.total_closed,
                metrics.total_accepted
            );
            if metrics.overdue > 0 {
                println!("Overdue: {}", metrics.overdue);
            }
            if let Some(mttr) = metrics.mttr_hours {
                println!("MTTR: {:.1}h", mttr);
            }
            if let Some(sla) = metrics.sla_compliance_pct {
                println!("SLA compliance: {:.1}%", sla);
            }
        }
    }

    Ok(())
}

/// Truncate a string to `max` characters, appending "..." if truncated.
/// Safe for all UTF-8 strings and all max values.
pub fn truncate(s: &str, max: usize) -> String {
    if max < 4 {
        return s.chars().take(max).collect();
    }
    let char_count = s.chars().count();
    if char_count <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max - 3).collect();
        format!("{truncated}...")
    }
}

fn print_case(case: &Case) {
    println!("Case: {}", case.id);
    println!("Title: {}", case.title);
    println!("Status: {}", case.status);
    println!("Severity: {}", case.severity);
    println!("Provider: {:?}", case.provider);
    if let Some(ref assignee) = case.assignee {
        println!("Assignee: {assignee}");
    }
    if let Some(due) = case.due_at {
        let overdue = if due < chrono::Utc::now() {
            " (OVERDUE)"
        } else {
            ""
        };
        println!("Due: {due}{overdue}");
    }
    println!("Created: {}", case.created_at);
    println!("Updated: {}", case.updated_at);
    if let Some(closed) = case.closed_at {
        println!("Closed: {closed}");
    }

    println!("\nFindings ({}):", case.findings.len());
    for f in &case.findings {
        let status = if f.resolved_at.is_some() {
            "resolved"
        } else {
            "active"
        };
        println!("  {} on {} [{status}]", f.finding_id, f.resource_id);
    }

    if let Some(ref resolution) = case.resolution {
        println!("\nResolution: {:?}", resolution.kind);
        println!("  {}", resolution.description);
        if let Some(ref evidence) = resolution.evidence {
            println!("  Evidence: {evidence}");
        }
    }

    if !case.notes.is_empty() {
        println!("\nNotes:");
        for note in &case.notes {
            println!(
                "  [{} by {}] {}",
                note.created_at.format("%Y-%m-%d %H:%M"),
                note.author,
                note.content
            );
        }
    }

    if !case.tags.is_empty() {
        println!("\nTags: {}", case.tags.join(", "));
    }
}
