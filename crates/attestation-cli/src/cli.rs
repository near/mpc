use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "attestation-cli")]
#[command(about = "Standalone verification tool for MPC node TEE attestations")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Verify a TEE attestation from an MPC node
    Verify(VerifyArgs),
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Fetch attestation data from a node's /public_data HTTP endpoint
    #[arg(long, group = "source")]
    pub url: Option<String>,

    /// Read attestation data from a saved JSON file (same format as /public_data response)
    #[arg(long, group = "source")]
    pub file: Option<PathBuf>,

    /// Allowed MPC Docker image hash (hex-encoded SHA256, repeatable)
    #[arg(long = "allowed-image-hash", required = true)]
    pub allowed_image_hashes: Vec<String>,

    /// Path to the launcher docker-compose YAML file (SHA256 is computed by the CLI)
    #[arg(long = "launcher-compose-file")]
    pub launcher_compose_file: PathBuf,

    /// Path to expected TCB measurements JSON file. If not provided, uses the compiled-in
    /// default measurements (same as the MPC contract/node).
    #[arg(long = "expected-measurements")]
    pub expected_measurements: Option<PathBuf>,
}
