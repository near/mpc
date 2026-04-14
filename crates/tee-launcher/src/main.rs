#[tokio::main]
async fn main() {
    // Install the default rustls crypto provider. Currently not needed
    // (dstack SDK communicates via unix socket, not TLS), but kept as a
    // safety net: if a dependency adds a TLS code path in the future,
    // missing this call would cause a runtime panic.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default rustls CryptoProvider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    if let Err(e) = tee_launcher::run().await {
        tracing::error!("Error: {e}");
        std::process::exit(1);
    }
}
