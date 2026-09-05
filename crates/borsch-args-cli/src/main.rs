use anyhow::Result;
use borsch_args_cli::cli::Cli;
use clap::Parser;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let bytes = cli.input_bytes()?;
    let decoded = cli.r#type.decode(&bytes)?;
    println!("{}", serde_json::to_string_pretty(&decoded)?);
    Ok(())
}
