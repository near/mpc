#[tokio::main]
async fn main() {
    // Install the default rustls crypto provider before any TLS usage.
    // Required because rustls is configured with default-features=false,
    // and indirect consumers like hyper-rustls (via reqwest) call
    // ClientConfig::builder() without an explicit provider.
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
