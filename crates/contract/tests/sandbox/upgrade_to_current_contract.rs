use crate::sandbox::common::{
    current_contract, execute_key_generation_and_add_random_state, gen_accounts,
    propose_and_vote_contract_binary, submit_signature_response, PARTICIPANT_LEN,
};
use mpc_contract::{
    crypto_shared::SignatureResponse,
    primitives::{
        participants::Participants,
        thresholds::{Threshold, ThresholdParameters},
    },
    state::ProtocolContractState,
};
use near_workspaces::{network::Sandbox, Account, Contract, Worker};
use rstest::rstest;

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

async fn init_old_contract(
    worker: Worker<Sandbox>,
    contract: &Contract,
) -> anyhow::Result<(Vec<Account>, Participants)> {
    let (accounts, participants) = gen_accounts(&worker, PARTICIPANT_LEN).await;

    let threshold = ((participants.len() as f64) * 0.6).ceil() as u64;
    let threshold = Threshold::new(threshold);
    let threshold_parameters = ThresholdParameters::new(participants.clone(), threshold).unwrap();

    contract
        .call("init")
        .args_json(serde_json::json!({
            "parameters": threshold_parameters,
        }))
        .transact()
        .await?
        .into_result()?;
    Ok((accounts, participants))
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

/// Migrates the contract to a current contract build
/// and sanity checks that the upgraded code matches compiled contract bytes.
async fn migrate_and_assert_contract_code(contract: &Contract) -> anyhow::Result<()> {
    contract.call("migrate").transact().await?.into_result()?;
    let code_hash_post_upgrade = contract.view_code().await.unwrap();
    let current_code_hash = current_contract();

    assert_eq!(*current_code_hash, code_hash_post_upgrade);

    Ok(())
}

/// Checks the contract in the following order:
/// 1. Are there any state-breaking changes?
/// 2. If so, does `migrate()` still work correctly?
///
/// These checks use the previous contract version (the one that introduced breaking changes)
/// as a baseline. If step 2 fails, you will be prompted to update the baseline contract.
#[rstest]
#[tokio::test]
async fn back_compatibility_without_state(
    #[values(Network::Mainnet, Network::Testnet)] network: Network,
) -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;

    let contract = deploy_old(&worker, network).await?;

    init_old_contract(worker, &contract).await?;

    assert!(healthcheck(&contract).await?);

    let contract = upgrade_to_new(contract).await?;

    if healthcheck(&contract).await? {
        println!("✅ Back compatibility check succeeded: no breaking changes found 🫧.");
        return Ok(());
    }

    println!("🟨 Found breaking changes in the contract state.");
    println!("⚙️ Testing migration() call...");

    migrate_and_assert_contract_code(&contract)
        .await
        .expect("❌ Back compatibility check failed: migration() failed");

    if healthcheck(&contract).await? {
        println!("✅ Back compatibility check succeeded: migration() works fine 👍");
        return Ok(());
    };

    anyhow::bail!(
        "❌Back compatibility check failed: state() call doesnt work after migration(). Probably you should introduce new logic to the `migrate()` method."
    )
}

/// Ensures that contracts deployed with the production binary (Mainnet or Testnet)
/// can be upgraded to the [`current_contract`] binary using the proposal-and-vote flow.
#[rstest]
#[tokio::test]
async fn propose_upgrade_from_production_to_current_binary(
    #[values(Network::Mainnet, Network::Testnet)] network: Network,
) {
    let worker = near_workspaces::sandbox().await.unwrap();
    let contract = deploy_old(&worker, network).await.unwrap();
    let (accounts, participants) = init_old_contract(worker, &contract).await.unwrap();

    // Add state so migration logic is exercised
    execute_key_generation_and_add_random_state(&accounts, participants, &contract).await;

    let state_pre_upgrade: ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();

    propose_and_vote_contract_binary(&accounts, &contract, current_contract()).await;

    let state_post_upgrade: ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();

    assert_eq!(
        state_pre_upgrade, state_post_upgrade,
        "State of the contract should remain the same post upgrade."
    );
}

//// Verifies that upgrading the contract preserves state and functionality.
///
/// This test:
/// 1. Deploys an older version of the contract.
/// 2. Initializes it with participants and submits a parameter update proposal.
/// 3. Adds multiple domains with both `Ed25519` and `Secp256k1` schemes.
/// 4. Submits pending signature requests across those domains.
/// 5. Captures the full pre-upgrade state.
/// 6. Upgrades the contract to the new version and runs `migrate()`.
/// 7. Asserts that the state (participants, domains, proposals, signature requests, etc.)
///    is identical post-upgrade.
/// 8. Confirms that pending signature requests created before the upgrade
///    can still be responded to afterward.
#[rstest]
#[tokio::test]
async fn upgrade_preserves_state_and_requests(
    #[values(Network::Mainnet, Network::Testnet)] network: Network,
) {
    let worker = near_workspaces::sandbox().await.unwrap();
    let contract = deploy_old(&worker, network).await.unwrap();
    let (accounts, participants) = init_old_contract(worker, &contract).await.unwrap();

    let injected_contract_state =
        execute_key_generation_and_add_random_state(&accounts, participants, &contract).await;

    let state_pre_upgrade: ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();

    assert!(healthcheck(&contract).await.unwrap());
    let contract = upgrade_to_new(contract).await.unwrap();
    migrate_and_assert_contract_code(&contract)
        .await
        .expect("❌ migration() failed");

    let state_post_upgrade: ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();

    assert_eq!(
        state_pre_upgrade, state_post_upgrade,
        "State of the contract should remain the same post upgrade."
    );

    for pending in injected_contract_state.pending_sign_requests {
        submit_signature_response(
            &pending.signature_request,
            &pending.signature_response,
            &contract,
        )
        .await
        .unwrap();

        let execution = pending.transaction.await.unwrap().into_result().unwrap();
        let returned: SignatureResponse = execution.json().unwrap();

        assert_eq!(
            returned, pending.signature_response,
            "Returned signature response does not match"
        );
    }
}
