use anyhow::{Context, bail};
use attestation_cli::cli::{self, Cli};
use attestation_cli::{data, output, verify};
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        cli::Command::Verify(args) => {
            let static_data = data::load_static_web_data(&args)
                .await
                .context("failed to load attestation data")?;

            match verify::run_verification(&static_data, &args) {
                Ok(result) => {
                    println!(
                        "{}",
                        output::Success {
                            data: &static_data,
                            result: &result
                        }
                    );
                    Ok(())
                }
                Err(err) => {
                    println!(
                        "{}",
                        output::Failure {
                            data: &static_data,
                            err: &err
                        }
                    );
                    bail!("attestation verification failed");
                }
            }
        }
    }
}
