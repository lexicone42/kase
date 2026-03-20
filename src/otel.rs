use anyhow::Result;
use opentelemetry::global;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize observability.
///
/// - Always: console logging via tracing-subscriber
/// - If GOOGLE_CLOUD_PROJECT is set: exports traces to Cloud Trace
///   via opentelemetry-stackdriver (direct API, no collector needed)
pub async fn init() -> Result<OtelGuard> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,kase=debug"));

    let project_id = std::env::var("GOOGLE_CLOUD_PROJECT").ok();

    if project_id.is_some() {
        init_with_cloud_trace(env_filter).await
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
        tracing::info!("OTel: console logging only (set GOOGLE_CLOUD_PROJECT for Cloud Trace)");
        Ok(OtelGuard { provider: None })
    }
}

async fn init_with_cloud_trace(env_filter: EnvFilter) -> Result<OtelGuard> {
    let authorizer = opentelemetry_stackdriver::GcpAuthorizer::new()
        .await
        .map_err(|e| anyhow::anyhow!("GCP authorizer init failed: {e}"))?;

    let (exporter, export_future) = opentelemetry_stackdriver::StackDriverExporter::builder()
        .build(authorizer)
        .await
        .map_err(|e| anyhow::anyhow!("Cloud Trace exporter init failed: {e}"))?;

    // Spawn the export loop as a background task
    tokio::spawn(export_future);

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build();

    global::set_tracer_provider(provider.clone());

    let otel_layer = tracing_opentelemetry::layer()
        .with_tracer(global::tracer("kase"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .with(otel_layer)
        .init();

    tracing::info!("OTel: exporting traces to Cloud Trace");
    Ok(OtelGuard {
        provider: Some(provider),
    })
}

/// Guard that flushes traces on drop.
pub struct OtelGuard {
    provider: Option<SdkTracerProvider>,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            if let Err(e) = provider.shutdown() {
                eprintln!("OTel shutdown error: {e}");
            }
        }
    }
}
