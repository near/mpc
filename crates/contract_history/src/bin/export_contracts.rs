fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target_dir = std::path::Path::new("pytest/common_lib/current_contracts");
    std::fs::create_dir_all(target_dir)?;

    std::fs::write(
        target_dir.join("signer_mainnet.wasm"),
        contract_history::current_mainnet(),
    )?;

    std::fs::write(
        target_dir.join("signer_testnet.wasm"),
        contract_history::current_testnet(),
    )?;

    println!("Copied contracts to {}", target_dir.display());

    Ok(())
}
