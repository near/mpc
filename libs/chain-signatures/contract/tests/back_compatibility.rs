use crate::common::{gen_accounts, CONTRACT_FILE_PATH, PARTICIPANT_LEN};
use mpc_contract::config::InitConfig;
use mpc_contract::primitives::thresholds::{Threshold, ThresholdParameters};
use near_workspaces::network::Sandbox;
use near_workspaces::{Contract, Worker};
use std::fs;

pub mod common;

const OLD_CONTRACT_PATH: &str = "../compiled-contracts/last-breaking-changes.wasm";

async fn init_contract(worker: Worker<Sandbox>, contract: &Contract) -> anyhow::Result<()> {
    let (_, participants) = gen_accounts(&worker, PARTICIPANT_LEN).await;

    let threshold = ((participants.len() as f64) * 0.6).ceil() as u64;
    let threshold = Threshold::new(threshold);
    let threshold_parameters = ThresholdParameters::new(participants, threshold).unwrap();

    contract
        .call("init")
        .args_json(serde_json::json!({
            "parameters": threshold_parameters,
            "init_config": None::<InitConfig>,
        }))
        .transact()
        .await?
        .into_result()?;
    Ok(())
}

async fn healthcheck(contract: &Contract) -> anyhow::Result<bool> {
    let status = contract
        .call("state")
        .transact()
        .await?
        .into_result()
        .is_ok();
    Ok(status)
}

async fn deploy_old(worker: &Worker<Sandbox>) -> anyhow::Result<Contract> {
    let old_wasm = std::fs::read(OLD_CONTRACT_PATH)?;
    let old_contract = worker.dev_deploy(&old_wasm).await?;
    Ok(old_contract)
}

async fn upgrade_to_new(old_contract: Contract) -> anyhow::Result<Contract> {
    let new_wasm = std::fs::read(CONTRACT_FILE_PATH)?;
    let new_contract = old_contract
        .as_account()
        .deploy(&new_wasm)
        .await?
        .into_result()?;
    Ok(new_contract)
}

async fn migrate(contract: &Contract) -> anyhow::Result<()> {
    contract.call("migrate").transact().await?.into_result()?;
    Ok(())
}

/// Checks the contract in the following order:
/// 1. Are there any state-breaking changes?
/// 2. If so, does `migrate()` still work correctly?
///
/// These checks use the previous contract version (the one that introduced breaking changes)
/// as a baseline. If step 2 fails, you will be prompted to update the baseline contract.
#[tokio::test]
async fn back_compatibility() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;

    let contract = deploy_old(&worker).await?;

    init_contract(worker, &contract).await?;

    assert!(healthcheck(&contract).await?);

    let contract = upgrade_to_new(contract).await?;

    if healthcheck(&contract).await? {
        println!("✅ Back compatibility check succeeded: no breaking changes found 🫧.");
        return Ok(());
    }

    println!("🟨 Found breaking changes in the contract state.");
    println!("⚙️ Testing migration() call...");

    assert!(
        migrate(&contract).await.is_ok(),
        "❌ Back compatibility check failed: migration() failed"
    );

    if healthcheck(&contract).await? {
        println!("✅ Back compatibility check succeeded: migration() works fine 👍");
        println!("⚠️ But, you should update \"last-breaking-changes\" contract to the new version. Run this:");
        let input = fs::canonicalize(CONTRACT_FILE_PATH)?.into_os_string();
        let destination = fs::canonicalize(OLD_CONTRACT_PATH)?.into_os_string();
        println!("\tcp {:?} {:?}", input, destination);
        return Err(anyhow::anyhow!("Check logs for more details."));
    };

    anyhow::bail!("❌Back compatibility check failed: state() call doesnt work after migration().")
}
