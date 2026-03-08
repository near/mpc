use anyhow::{Context, bail};
use attestation_cli::cli::Cli;
use attestation_cli::{data, output, verify};
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let static_data = data::load(&cli)
        .await
        .context("failed to load attestation data")?;

    match verify::run_verification(&static_data, &cli) {
        Ok(result) => {
            output::print_success(&static_data, &result);
            Ok(())
        }
        Err(err) => {
            output::print_failure(&static_data, &err);
            bail!("attestation verification failed");
        }
    }
}
