use anyhow::{Context, bail};
use attestation_cli::cli::{Cli, Command};
use attestation_cli::tcb_status::{EvaluationDataSet, TcbVerdict};
use attestation_cli::{data, output, tcb_status, verify};
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let command = Cli::parse().command;
    let source = match &command {
        Command::Verify(args) => &args.source,
        Command::TcbStatus(args) => &args.source,
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
        Command::TcbStatus(args) => {
            let report =
                tcb_status::run(&static_data, args.as_of, args.evaluation_data_set).await?;
            output::print_tcb_status(&report);
            let up_to_date = match args.evaluation_data_set {
                Some(EvaluationDataSet::Early) => report.early.as_ref(),
                None | Some(EvaluationDataSet::Standard) => report.standard.as_ref(),
            }
            .is_some_and(TcbVerdict::is_up_to_date);
            // The verdict and what to do about it are already printed; this
            // sets the exit code, at the cost of a second line on stderr.
            if up_to_date {
                Ok(())
            } else {
                bail!("platform TCB check failed")
            }
        }
    }
}
