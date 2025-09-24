use std::collections::HashSet;

use crate::sandbox::common::{
    current_contract, gen_accounts, get_participants, get_tee_accounts, PARTICIPANT_LEN,
};
use mpc_contract::{
    config::InitConfig,
    primitives::thresholds::{Threshold, ThresholdParameters},
};
use near_sdk::AccountId;
use near_workspaces::{network::Sandbox, Contract, Worker};

enum Network {
    Testnet,
    Mainnet,
}

fn contract_code(network: Network) -> &'static [u8] {
    match network {
        Network::Mainnet => contract_history::current_mainnet(),
        Network::Testnet => contract_history::current_testnet(),
    }
}

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

async fn deploy_old(worker: &Worker<Sandbox>, network: Network) -> anyhow::Result<Contract> {
    let old_wasm = contract_code(network);
    let old_contract = worker.dev_deploy(old_wasm).await?;
    Ok(old_contract)
}

async fn upgrade_to_new(old_contract: Contract) -> anyhow::Result<Contract> {
    let new_wasm = current_contract();
    let new_contract = old_contract
        .as_account()
        .deploy(new_wasm)
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
async fn back_compatibility(network: Network) -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;

    let contract = deploy_old(&worker, network).await?;

    init_contract(worker, &contract).await?;

    assert!(healthcheck(&contract).await?);

    let contract = upgrade_to_new(contract).await?;

    if healthcheck(&contract).await? {
        println!("✅ Back compatibility check succeeded: no breaking changes found 🫧.");
        return Ok(());
    }

    println!("🟨 Found breaking changes in the contract state.");
    println!("⚙️ Testing migration() call...");

    migrate(&contract)
        .await
        .expect("❌ Back compatibility check failed: migration() failed");

    let health_check_status = healthcheck(&contract).await?;
    anyhow::ensure!(health_check_status, "❌Back compatibility check failed: state() call doesnt work after migration(). Probably you should introduce new logic to the `migrate()` method.");

    println!("✅ Back compatibility check succeeded: migration() works fine 👍");

    Ok(())
}

#[tokio::test]
async fn test_back_compatiblity_mainnet() {
    back_compatibility(Network::Mainnet).await.unwrap();
}

#[tokio::test]
async fn test_back_compatiblity_testnet() {
    back_compatibility(Network::Testnet).await.unwrap();
}

#[tokio::test]
async fn participant_set_is_unchanged_during_upgrade() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract = deploy_old(&worker, Network::Testnet).await?;

    init_contract(worker, &contract).await?;

    let initial_participants = get_participants(&contract).await?;

    let contract = upgrade_to_new(contract).await?;

    migrate(&contract)
        .await
        .expect("❌ Back compatibility check failed: migration() failed");

    let participants_after_upgrade = get_participants(&contract).await?;
    assert_eq!(
        initial_participants, participants_after_upgrade,
        "Participant set must not change after an upgrade."
    );

    Ok(())
}

#[tokio::test]
async fn test_all_participants_have_valid_attestation_for_soft_launch() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let contract = deploy_old(&worker, Network::Testnet).await?;

    init_contract(worker, &contract).await?;

    let initial_participants = get_participants(&contract).await?;
    let participant_set_is_not_empty = !initial_participants.participants().is_empty();
    assert!(
        participant_set_is_not_empty,
        "Test must contain a contract with at least one participant"
    );

    let contract = upgrade_to_new(contract).await?;

    migrate(&contract)
        .await
        .expect("❌ Back compatibility check failed: migration() failed");

    let accounts_with_tee_attestation_post_upgrade: HashSet<AccountId> =
        get_tee_accounts(&contract)
            .await
            .unwrap()
            .into_iter()
            .map(|node_id| node_id.account_id)
            .collect();

    let participant_set: HashSet<AccountId> = initial_participants
        .participants()
        .iter()
        .map(|(account_id, _, _)| account_id)
        .cloned()
        .collect();

    assert_eq!(
        accounts_with_tee_attestation_post_upgrade, participant_set,
        "All initial participants must have a valid attestation post upgrade."
    );
    Ok(())
}
