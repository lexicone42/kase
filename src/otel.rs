use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize observability. Console logging always; OTel OTLP export when
/// the `otel` feature is enabled and OTEL_EXPORTER_OTLP_ENDPOINT is set.
///
/// TODO: Add opentelemetry + opentelemetry-otlp + tracing-opentelemetry deps
/// behind an `otel` feature flag, targeting Cloud Trace as the backend.
pub fn init() -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,kase=debug"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    Ok(())
}
