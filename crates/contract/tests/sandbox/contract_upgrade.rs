use crate::sandbox::common::{
    call_contract_key_generation, create_message_payload_and_response, current_contract,
    gen_accounts, respond_to_sign_request, submit_sign_request, PARTICIPANT_LEN,
};
use mpc_contract::{
    config::InitConfig,
    crypto_shared::SignatureResponse,
    primitives::{
        domain::{DomainConfig, SignatureScheme},
        participants::Participants,
        signature::{SignRequestArgs, SignatureRequest},
        thresholds::{Threshold, ThresholdParameters},
    },
    state::ProtocolContractState,
};
use near_workspaces::{network::Sandbox, operations::TransactionStatus, Account, Contract, Worker};
use rstest::rstest;
use serde_json::json;

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

struct PendingSignRequest {
    transaction: TransactionStatus,
    signature_request: SignatureRequest,
    signature_response: SignatureResponse,
}

async fn init_contract(
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
            "init_config": Some(InitConfig {
                key_event_timeout_blocks: Some(10_000),
                ..Default::default()
            }),
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

    init_contract(worker, &contract).await?;

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

/// Verifies that upgrading the contract preserves all state and functionality.
///
/// Steps:
/// 1. Deploy an old version of the contract.
/// 2. Initialize it with participants.
/// 3. Submit a parameter update proposal.
/// 4. Register multiple domains with both `Ed25519` and `Secp256k1` schemes.
/// 5. Submit pending signature requests across those domains.
/// 6. Capture the pre-upgrade state.
/// 7. Upgrade to the new version and run `migrate()`.
/// 8. Assert that the state (participants, domains, proposals, signature requests, etc.) is unchanged.
/// 9. Verify that pending signature requests created before the upgrade can still be responded to afterward
#[rstest]
#[tokio::test]
async fn upgrade_keeps_participants_and_domains_intact(
    #[values(Network::Mainnet, Network::Testnet)] network: Network,
) {
    const EPOCH_ID: u64 = 0;

    let worker = near_workspaces::sandbox().await.unwrap();
    let contract = deploy_old(&worker, network).await.unwrap();
    let (accounts, participants) = init_contract(worker, &contract).await.unwrap();

    let domains_to_add = [
        DomainConfig {
            id: 0.into(),
            scheme: SignatureScheme::Ed25519,
        },
        DomainConfig {
            id: 1.into(),
            scheme: SignatureScheme::Secp256k1,
        },
        DomainConfig {
            id: 2.into(),
            scheme: SignatureScheme::Ed25519,
        },
    ];

    // Create a proposal to increase threshold to 3.
    let dummy_threshold_parameters =
        ThresholdParameters::new(participants, Threshold::new(3)).unwrap();
    let arbitrary_participant_account = &accounts[0];
    let dummy_proposal = json!({
        "prospective_epoch_id": 1,
        "proposal": dummy_threshold_parameters,
    });

    arbitrary_participant_account
        .call(contract.id(), "vote_new_parameters")
        .args_json(dummy_proposal)
        .max_gas()
        .transact()
        .await
        .unwrap()
        .unwrap();

    // Add the domains above to the contract so we have additional state on the contract
    // that should be persisted after the upgrade
    let shared_secret_keys =
        call_contract_key_generation(&domains_to_add, &accounts, &contract, EPOCH_ID).await;

    let signature_request_payloads = ["hello world", "hello world!!!!"];
    let mut pending_sign_requests = vec![];
    let predecessor_id = contract.id();
    let path = "test";

    for (domain, shared_secret_key) in domains_to_add.iter().zip(shared_secret_keys.iter()) {
        let domain_id = domain.id;

        for message in signature_request_payloads {
            let (payload, signature_request, signature_response) =
                create_message_payload_and_response(
                    domain_id,
                    predecessor_id,
                    message,
                    path,
                    shared_secret_key,
                )
                .await;

            let request = SignRequestArgs {
                payload_v2: Some(payload),
                path: path.into(),
                domain_id: Some(domain_id),
                ..Default::default()
            };

            let transaction = submit_sign_request(&request, &contract).await.unwrap();

            let pending_sign_request = PendingSignRequest {
                transaction,
                signature_request,
                signature_response,
            };

            pending_sign_requests.push(pending_sign_request);
        }
    }

    let state_pre_upgrade: ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();

    assert!(healthcheck(&contract).await.unwrap());

    let contract = upgrade_to_new(contract).await.unwrap();
    migrate_and_assert_contract_code(&contract)
        .await
        .expect("❌ Back compatibility check failed: migration() failed");

    let state_post_upgrade: ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();

    assert_eq!(
        state_pre_upgrade, state_post_upgrade,
        "State of the contract should remain the same post upgrade."
    );

    println!("✅ Protocol state was preserved post upgrade. 👍");

    // Check that pending signature requests added pre upgrade can be responded to post upgrade.
    for pending_sign_request in pending_sign_requests {
        let signature_response_sent_to_contract = &pending_sign_request.signature_response;

        respond_to_sign_request(
            &pending_sign_request.signature_request,
            signature_response_sent_to_contract,
            &contract,
        )
        .await
        .unwrap();

        let execution = pending_sign_request.transaction.await.unwrap();
        dbg!(&execution);
        let execution = execution.into_result().unwrap();
        let signature_response_returned_by_contract: SignatureResponse = execution.json().unwrap();

        assert_eq!(
            &signature_response_returned_by_contract, signature_response_sent_to_contract,
            "Returned signature response does not match response that was sent to the contract."
        );
    }

    println!("✅ Pending requests are preserved and can be responded to post upgrade. 👍");
}
