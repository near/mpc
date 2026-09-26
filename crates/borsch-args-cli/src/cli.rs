use crate::types::ArgType;
use clap::{ArgGroup, Parser};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "borsh-args-cli")]
#[command(about = "Decode a borsh-encoded contract-call argument file into reviewable JSON")]
#[command(group(ArgGroup::new("source").required(true)))]
pub struct Cli {
    /// Which contract method's argument(s) the input was encoded for.
    #[arg(long, value_enum)]
    pub r#type: ArgType,
    /// Path to the raw borsh-encoded arguments
    #[arg(long, group = "source")]
    pub file: Option<PathBuf>,
    /// The borsh-encoded arguments as a base64 string
    #[arg(long, group = "source")]
    pub base64: Option<String>,
}

impl Cli {
    /// Resolves arguments supplied (`--file` / `--base64`).
    pub fn input_bytes(&self) -> anyhow::Result<Vec<u8>> {
        use anyhow::Context;
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        match (&self.file, &self.base64) {
            (Some(path), None) => {
                std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))
            }
            (None, Some(b64)) => STANDARD
                .decode(b64.trim())
                .context("failed to base64-decode --base64 input"),
            _ => unreachable!("--file and --base64 are a required, mutually exclusive group"),
        }
    }
}
