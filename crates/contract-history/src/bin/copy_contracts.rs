use clap::Parser;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    std::fs::create_dir_all(&args.target_dir)?;

    std::fs::write(
        args.target_dir.join("signer_mainnet.wasm"),
        contract_history::current_mainnet(),
    )?;

    std::fs::write(
        args.target_dir.join("signer_testnet.wasm"),
        contract_history::current_testnet(),
    )?;

    println!("Copied contracts to {}", args.target_dir.display());

    Ok(())
}

#[derive(Parser)]
pub struct Args {
    #[arg(short, long, help = "Where to export the contracts to")]
    target_dir: PathBuf,
}
