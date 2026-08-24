use anyhow::{Context, bail};
use attestation_cli::cli::{Cli, Command};
use attestation_cli::{data, output, tcb_status, verify};
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let command = Cli::parse().command;
    let source = match &command {
        Command::Verify(args) => &args.source,
        Command::TcbStatus(source) => source,
    };
    let static_data = data::load(source)
        .await
        .context("failed to load attestation data")?;

    match &command {
        Command::Verify(args) => match verify::run_verification(&static_data, args) {
            Ok(result) => {
                output::print_success(&static_data, &result);
                Ok(())
            }
            Err(err) => {
                output::print_failure(&static_data, &err);
                bail!("attestation verification failed");
            }
        },
        Command::TcbStatus(_) => {
            let report = tcb_status::run(&static_data).await?;
            output::print_tcb_status(&report);
            // The verdict and what to do about it are already printed; this
            // sets the exit code, at the cost of a second line on stderr.
            if report.is_up_to_date() {
                Ok(())
            } else {
                bail!("platform TCB check failed")
            }
        }
    }
}
