#![allow(non_snake_case)]

use crate::sandbox::{
    common::{
        call_contract_key_generation, execute_key_generation_and_add_random_state, gen_account,
        gen_accounts, init, make_foreign_chain_available, propose_and_vote_contract_binary,
        submit_attestations,
    },
    utils::{
        consts::PARTICIPANT_LEN,
        contract_build::current_contract,
        mpc_contract::{
            get_participants, get_state, get_tee_accounts, prepay_and_submit_participant_info,
            tee_verifier_account_id, vote_add_launcher_hash, vote_tee_verifier_change,
        },
        shared_key_utils::DomainKey,
        sign_utils::{make_and_submit_requests, submit_ckd_response, submit_signature_response},
        transactions::CallMpcContract,
        views::ViewMpcContract,
    },
};
use anyhow::Context as _;
use mpc_contract::primitives::{
    key_state::EpochId,
    participants::Participants,
    test_utils::bogus_tee_verifier_account_id,
    thresholds::{GovernanceThreshold, GovernanceThresholdParameters},
};
use mpc_contract::storage_keys::StorageKey;
use near_account_id::AccountId;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types as dtos;
use near_mpc_contract_interface::types::ProtocolContractState;
use near_mpc_contract_interface::types::{
    CKDResponse, DomainConfig, DomainPurpose, Protocol, ReconstructionThreshold,
};
use near_mpc_sdk::sign::SignatureRequestResponse;
use near_workspaces::{Account, Contract, Worker, network::Sandbox};
use rand_core::OsRng;
use rstest::rstest;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy)]
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

/// The production contract predates the verifier argument and ignores it, so the verifier
/// stays unset.
async fn init_old_contract_without_tee_verifier(
    worker: &Worker<Sandbox>,
    contract: &Contract,
    number_of_participants: usize,
) -> anyhow::Result<(Vec<Account>, Participants)> {
    let (accounts, participants) = gen_accounts(worker, number_of_participants).await;

    let threshold = ((participants.len() as f64) * 0.6).ceil() as u64;
    let threshold = GovernanceThreshold::new(threshold);
    let threshold_parameters: near_mpc_contract_interface::types::GovernanceThresholdParameters =
        GovernanceThresholdParameters::new(participants.clone(), threshold)
            .unwrap()
            .into();
    contract
        .as_account()
        .call_mpc(contract.id())
        .init(threshold_parameters, bogus_tee_verifier_account_id(), None)
        .await?
        .into_result()?;
    Ok((accounts, participants))
}

async fn init_old_contract(
    worker: &Worker<Sandbox>,
    contract: &Contract,
    number_of_participants: usize,
) -> anyhow::Result<(Vec<Account>, Participants)> {
    let (accounts, participants) =
        init_old_contract_without_tee_verifier(worker, contract, number_of_participants).await?;
    vote_tee_verifier_change(&accounts, contract, &bogus_tee_verifier_account_id()).await?;
    Ok((accounts, participants))
}

async fn healthcheck(contract: &Contract) -> anyhow::Result<bool> {
    let status = contract
        .call(method_names::STATE)
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
    contract
        .call(method_names::MIGRATE)
        .transact()
        .await?
        .into_result()?;
    let code_hash_post_upgrade = contract.view_code().await.unwrap();
    let current_code_hash = current_contract();

    assert_eq!(*current_code_hash, code_hash_post_upgrade);

    Ok(())
}

/// Checks the contract in the following order:
/// 1. Are there any state-breaking changes?
/// 2. If so, does [`migrate()`] still work correctly?
///
/// These checks use the previous contract version (the one that introduced breaking changes)
/// as a baseline. If step 2 fails, you will be prompted to update the baseline contract.
#[rstest]
#[tokio::test]
async fn back_compatibility_without_state(
    #[values(Network::Mainnet, Network::Testnet)] network: Network,
) -> anyhow::Result<()> {
    let worker = test_utils::sandbox::start_sandbox().await?;

    let contract = deploy_old(&worker, network).await?;

    init_old_contract(&worker, &contract, PARTICIPANT_LEN).await?;

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

#[rstest]
#[tokio::test]
async fn migrate__should_carry_over_the_voted_in_tee_verifier(
    #[values(Network::Mainnet, Network::Testnet)] network: Network,
) -> anyhow::Result<()> {
    // Given
    let worker = test_utils::sandbox::start_sandbox().await?;
    let contract = deploy_old(&worker, network).await?;
    init_old_contract(&worker, &contract, PARTICIPANT_LEN).await?;

    // When
    let contract = upgrade_to_new(contract).await?;
    migrate_and_assert_contract_code(&contract).await?;

    // Then
    assert_eq!(
        tee_verifier_account_id(&contract).await,
        bogus_tee_verifier_account_id()
    );
    Ok(())
}

#[rstest]
#[tokio::test]
async fn migrate__should_fail_when_no_tee_verifier_is_configured(
    #[values(Network::Mainnet, Network::Testnet)] network: Network,
) -> anyhow::Result<()> {
    // Given
    let worker = test_utils::sandbox::start_sandbox().await?;
    let contract = deploy_old(&worker, network).await?;
    init_old_contract_without_tee_verifier(&worker, &contract, PARTICIPANT_LEN).await?;

    // When
    let contract = upgrade_to_new(contract).await?;
    let err = contract
        .call(method_names::MIGRATE)
        .transact()
        .await?
        .into_result()
        .expect_err("migrate must fail without a configured TEE verifier");

    // Then
    assert!(
        err.to_string().contains("No TEE verifier is configured"),
        "unexpected migrate failure: {err}"
    );
    let contract = contract
        .as_account()
        .deploy(contract_code(network))
        .await?
        .into_result()?;
    assert!(healthcheck(&contract).await?);
    Ok(())
}

/// Entries the upgrade under test has to carry across. Migration cost scales with this, and
/// `stored_attestations` keeps entries for non-participants too, so it is sized past the real
/// fleet (18 on mainnet, 19 on testnet when this was written) rather than at [`PARTICIPANT_LEN`].
const STORED_ATTESTATION_ENTRIES: usize = 25;

/// Tops the stored attestations up to `total` with entries owned by non-participants, the way a
/// prospective node's submission would.
async fn fill_stored_attestations(worker: &Worker<Sandbox>, contract: &Contract, total: usize) {
    let mut accounts = Vec::with_capacity(total - PARTICIPANT_LEN);
    for _ in PARTICIPANT_LEN..total {
        accounts.push(gen_account(worker).await.0);
    }

    let submissions = accounts
        .iter()
        .enumerate()
        .map(|(index, account)| async move {
            let tls_key = dtos::Ed25519PublicKey([u8::try_from(index).unwrap(); 32]);
            let result = prepay_and_submit_participant_info(
                account,
                contract,
                &dtos::Attestation::Mock(dtos::MockAttestation::Valid),
                &tls_key,
            )
            .await
            .expect("submit_participant_info should not error");
            assert!(result.is_success(), "filler submission failed: {result:?}");
        });
    futures::future::join_all(submissions).await;

    let stored = get_tee_accounts(contract).await.unwrap();
    assert_eq!(stored.len(), total, "stored attestation count");
}

/// Ensures that contracts deployed with the production binary (Mainnet or Testnet)
/// can be upgraded to the [`current_contract`] binary using the proposal-and-vote flow.
#[rstest]
#[tokio::test]
async fn propose_upgrade_from_production_to_current_binary(
    #[values(Network::Mainnet, Network::Testnet)] network: Network,
) {
    let worker = test_utils::sandbox::start_sandbox().await.unwrap();
    let contract = deploy_old(&worker, network).await.unwrap();
    let (accounts, participants) = init_old_contract(&worker, &contract, PARTICIPANT_LEN)
        .await
        .unwrap();
    let mpc_contract = worker.view_mpc(contract.id());

    submit_attestations(&contract, &accounts, &participants).await;
    fill_stored_attestations(&worker, &contract, STORED_ATTESTATION_ENTRIES).await;

    // Add state so migration logic is exercised
    execute_key_generation_and_add_random_state(
        &accounts,
        participants,
        &contract,
        &worker,
        &mut OsRng,
    )
    .await;

    // Vote in a launcher image hash so migration decodes a non-empty `entries` vec off the
    // real production layout, not just the empty-vec path.
    let launcher_hash = mpc_primitives::hash::LauncherImageHash::from([0xAA; 32]);
    for account in &accounts {
        vote_add_launcher_hash(account, &contract, &launcher_hash)
            .await
            .unwrap();
    }
    assert!(
        mpc_contract
            .allowed_launcher_image_hashes()
            .await
            .unwrap()
            .value
            .contains(&launcher_hash),
        "launcher hash should be voted in before the upgrade"
    );

    let state_pre_upgrade: ProtocolContractState = get_state(&contract).await;

    propose_and_vote_contract_binary(&accounts, &contract, current_contract()).await;

    let state_post_upgrade: ProtocolContractState = get_state(&contract).await;

    assert_eq!(
        state_pre_upgrade, state_post_upgrade,
        "State of the contract should remain the same post upgrade."
    );

    assert!(
        mpc_contract
            .allowed_launcher_image_hashes()
            .await
            .unwrap()
            .value
            .contains(&launcher_hash),
        "launcher hash should survive migration to the current binary"
    );
}

//// Verifies that upgrading the contract preserves state and functionality.
///
/// This test:
/// 1. Deploys an older version of the contract.
/// 2. Initializes it with participants and submits a parameter update proposal.
/// 3. Adds multiple domains with both [`Ed25519`] and [`Secp256k1`] schemes.
/// 4. Submits pending signature requests across those domains.
/// 5. Captures the full pre-upgrade state.
/// 6. Upgrades the contract to the new version and runs [`migrate()`].
/// 7. Asserts that the state (participants, domains, proposals, signature requests, etc.)
///    is identical post-upgrade.
/// 8. Confirms that pending signature requests created before the upgrade
///    can still be responded to afterward.
#[rstest]
#[tokio::test]
async fn upgrade_preserves_state_and_requests(
    #[values(Network::Mainnet, Network::Testnet)] network: Network,
) {
    let worker = test_utils::sandbox::start_sandbox().await.unwrap();
    let contract = deploy_old(&worker, network).await.unwrap();
    let (accounts, participants) = init_old_contract(&worker, &contract, PARTICIPANT_LEN)
        .await
        .unwrap();

    let attested_account = &accounts[0];

    submit_attestations(&contract, &accounts, &participants).await;

    let injected_contract_state = execute_key_generation_and_add_random_state(
        &accounts,
        participants,
        &contract,
        &worker,
        &mut OsRng,
    )
    .await;

    let state_pre_upgrade: ProtocolContractState = get_state(&contract).await;

    assert!(healthcheck(&contract).await.unwrap());
    let contract = upgrade_to_new(contract).await.unwrap();
    migrate_and_assert_contract_code(&contract)
        .await
        .expect("❌ migration() failed");

    let state_post_upgrade: ProtocolContractState = get_state(&contract).await;

    assert_eq!(
        state_pre_upgrade, state_post_upgrade,
        "State of the contract should remain the same post upgrade."
    );

    for pending in injected_contract_state.pending_sign_requests {
        submit_signature_response(&pending.response, &contract, attested_account)
            .await
            .unwrap();

        let execution = pending.transaction.await.unwrap().into_result().unwrap();
        let returned: SignatureRequestResponse = execution.json().unwrap();

        assert_eq!(
            returned, pending.response.response,
            "Returned signature response does not match"
        );
    }
}

/// During the soft-launch transition every participant re-submits their TEE
/// attestation on the old contract (populating the previously-optional
/// `account_public_key` field). The #1710 migration drops any stored entry
/// that still has a missing account key, so this test reproduces the
/// production sequence: soft-launch re-submissions first, then the upgrade,
/// and verifies that every initial participant still has a stored attestation
/// after migration.
#[tokio::test]
async fn all_participants_get_valid_mock_attestation_for_soft_launch_upgrade() -> anyhow::Result<()>
{
    let worker = test_utils::sandbox::start_sandbox().await?;
    let contract = deploy_old(&worker, Network::Testnet).await?;

    let (accounts, participants) = init_old_contract(&worker, &contract, PARTICIPANT_LEN).await?;

    let initial_participants = get_participants(&contract).await?;
    let participant_set_is_not_empty = !initial_participants.participants.is_empty();
    assert!(
        participant_set_is_not_empty,
        "Test must contain a contract with at least one participant"
    );

    submit_attestations(&contract, &accounts, &participants).await;

    let contract = upgrade_to_new(contract).await?;

    migrate_and_assert_contract_code(&contract)
        .await
        .expect("❌ Back compatibility check failed: migration() failed");

    let accounts_with_tee_attestation_post_upgrade: HashSet<AccountId> =
        get_tee_accounts(&contract)
            .await
            .unwrap()
            .into_iter()
            .map(|node_id| node_id.account_id.clone())
            .collect();

    let participant_set: HashSet<AccountId> = initial_participants
        .participants
        .iter()
        .map(|(account_id, _, _)| account_id.clone())
        .collect();

    assert_eq!(
        accounts_with_tee_attestation_post_upgrade, participant_set,
        "All initial participants must have a valid attestation post upgrade."
    );
    Ok(())
}

//// Verifies that upgrading the contract preserves state and allows the new
/// functionality, in this case only CKD
///
/// This test:
/// 1. Deploys an older version of the contract.
/// 2. Initializes it with participants and submits a parameter update proposal.
/// 3. Adds multiple domains with both [`Ed25519`] and [`Secp256k1`] schemes.
/// 4. Submits pending signature requests across those domains.
/// 5. Captures the full pre-upgrade state.
/// 6. Upgrades the contract to the new version and runs [`migrate()`].
/// 7. Asserts that the state (participants, domains, proposals, signature requests, etc.)
///    is identical post-upgrade.
/// 10. Adds new domains, including CKD
/// 11. Submits new signature and ckd requests
/// 12. Confirms that pending signature and ckd requests created before and after the upgrade
///    can still be responded to.
#[rstest]
#[tokio::test]
async fn upgrade_allows_new_request_types(
    #[values(Network::Mainnet, Network::Testnet)] network: Network,
) {
    let rng = &mut OsRng;

    let worker = test_utils::sandbox::start_sandbox().await.unwrap();
    let contract = deploy_old(&worker, network).await.unwrap();
    let (accounts, participants) = init_old_contract(&worker, &contract, PARTICIPANT_LEN)
        .await
        .unwrap();
    let attested_account = &accounts[0];

    submit_attestations(&contract, &accounts, &participants).await;

    let injected_contract_state = execute_key_generation_and_add_random_state(
        &accounts,
        participants,
        &contract,
        &worker,
        rng,
    )
    .await;

    let state_pre_upgrade: ProtocolContractState = get_state(&contract).await;

    assert!(healthcheck(&contract).await.unwrap());
    let contract = upgrade_to_new(contract).await.unwrap();
    migrate_and_assert_contract_code(&contract)
        .await
        .expect("❌ migration() failed");

    let state_post_upgrade: ProtocolContractState = get_state(&contract).await;

    assert_eq!(
        state_pre_upgrade, state_post_upgrade,
        "State of the contract should remain the same post upgrade."
    );

    let first_available_domain_id = injected_contract_state.domain_keys.len() as u64;

    // 2. Add new domains
    let domains_to_add = [
        DomainConfig {
            id: first_available_domain_id.into(),
            protocol: Protocol::ConfidentialKeyDerivation,
            reconstruction_threshold: ReconstructionThreshold::new(6),
            purpose: DomainPurpose::CKD,
        },
        DomainConfig {
            id: (first_available_domain_id + 1).into(),
            protocol: Protocol::Frost,
            reconstruction_threshold: ReconstructionThreshold::new(6),
            purpose: DomainPurpose::Sign,
        },
    ];

    const EPOCH_ID: u64 = 0;
    let added_domain_keys =
        call_contract_key_generation(&domains_to_add, &accounts, &contract, EPOCH_ID).await;

    let current_keys: Vec<DomainKey> = injected_contract_state
        .domain_keys
        .clone()
        .iter()
        .chain(added_domain_keys.iter())
        .cloned()
        .collect();

    let (pending_sign_requests, pending_ckd_requests) =
        make_and_submit_requests(&current_keys, &contract, &worker, rng).await;

    for pending in injected_contract_state
        .pending_sign_requests
        .into_iter()
        .chain(pending_sign_requests.into_iter())
    {
        submit_signature_response(&pending.response, &contract, attested_account)
            .await
            .unwrap();

        let execution = pending.transaction.await.unwrap().into_result().unwrap();
        let returned: SignatureRequestResponse = execution.json().unwrap();

        assert_eq!(
            returned, pending.response.response,
            "Returned signature response does not match"
        );
    }

    for pending in pending_ckd_requests {
        submit_ckd_response(&pending.ckd_response, &contract, attested_account)
            .await
            .unwrap();

        let execution = pending.transaction.await.unwrap().into_result().unwrap();
        let returned: CKDResponse = execution.json().unwrap();

        assert_eq!(
            returned, pending.ckd_response.response,
            "Returned ckd response does not match"
        );
    }
}

#[tokio::test]
async fn init_running_rejects_external_callers_pre_initialization() {
    let (worker, contract) = init().await;
    let number_of_participants = 2;
    let (accounts, participants) = gen_accounts(&worker, number_of_participants).await;

    let threshold_parameters: dtos::GovernanceThresholdParameters =
        GovernanceThresholdParameters::new(
            participants.clone(),
            GovernanceThreshold::new(number_of_participants as u64),
        )
        .unwrap()
        .into();

    let init_running_args = serde_json::json!({
            "domains": [],
            "next_domain_id": 0,
            "keyset": dtos::Keyset::new(EpochId::new(2), vec![]),
            "parameters": threshold_parameters,
    });

    let execution_error = accounts[0]
        .call(contract.id(), method_names::INIT_RUNNING)
        .max_gas()
        .args_json(init_running_args)
        .transact()
        .await
        .unwrap()
        .into_result()
        .expect_err("method is private and not callable from participant account.");

    let error_message = format!("{:?}", execution_error);

    let expected_error_message = "Smart contract panicked: Method init_running is private";

    assert!(
        error_message.contains(expected_error_message),
        "init_running call was accepted by external caller. expected method to be private. {:?}",
        error_message
    )
}

/// Legacy per-node support registered on the old contract must not break the
/// upgrade, and the current foreign-chain state must survive it. The upgrade runs
/// through the proposal-and-vote flow so the migration is bound by the production gas
/// budget while clearing more legacy entries.
#[rstest]
#[tokio::test]
async fn upgrade__should_drop_legacy_support_and_preserve_foreign_chains_state(
    #[values(Network::Mainnet, Network::Testnet)] network: Network,
) -> anyhow::Result<()> {
    // Given
    const LEGACY_PARTICIPANT_LEN: usize = 20;
    let all_chains = [
        dtos::ForeignChain::Solana,
        dtos::ForeignChain::Bitcoin,
        dtos::ForeignChain::Ethereum,
        dtos::ForeignChain::Base,
        dtos::ForeignChain::Bnb,
        dtos::ForeignChain::Arbitrum,
        dtos::ForeignChain::Abstract,
        dtos::ForeignChain::Starknet,
        dtos::ForeignChain::Polygon,
        dtos::ForeignChain::HyperEvm,
        dtos::ForeignChain::Ton,
        dtos::ForeignChain::Aptos,
        dtos::ForeignChain::Sui,
        dtos::ForeignChain::Avalanche,
        dtos::ForeignChain::Adi,
        dtos::ForeignChain::Fogo,
    ];
    let worker = test_utils::sandbox::start_sandbox().await?;
    let contract = deploy_old(&worker, network).await?;
    let (accounts, participants) =
        init_old_contract(&worker, &contract, LEGACY_PARTICIPANT_LEN).await?;
    submit_attestations(&contract, &accounts, &participants).await;
    call_contract_key_generation(
        &[DomainConfig {
            id: 0.into(),
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(6),
            purpose: DomainPurpose::ForeignTx,
        }],
        &accounts,
        &contract,
        0,
    )
    .await;
    let chain = dtos::ForeignChain::Bitcoin;
    make_foreign_chain_available(chain, &contract, &accounts).await;
    for account in &accounts {
        account
            .call(contract.id(), "register_foreign_chain_support")
            .args_json(serde_json::json!({ "foreign_chain_support": all_chains }))
            .transact()
            .await?
            .into_result()?;
    }
    let configs_before: dtos::ForeignChainsConfigs = contract
        .view(method_names::GET_FOREIGN_CHAINS_CONFIGS)
        .await?
        .json()
        .context("GET_FOREIGN_CHAINS_CONFIGS json")?;
    let available_before: dtos::AvailableForeignChains = contract
        .view(method_names::GET_AVAILABLE_FOREIGN_CHAINS)
        .await?
        .json()
        .context("GET_AVAILABLE_FOREIGN_CHAINS json")?;
    let allowed_before: BTreeMap<dtos::ForeignChain, dtos::ChainEntry> = contract
        .view(method_names::ALLOWED_FOREIGN_CHAIN_PROVIDERS)
        .await?
        .json()
        .context("ALLOWED_FOREIGN_CHAIN_PROVIDERS json")?;
    assert_eq!(configs_before.len(), LEGACY_PARTICIPANT_LEN);
    assert_eq!(*available_before, BTreeSet::from([chain]));
    assert!(allowed_before.contains_key(&chain));
    let legacy_keys = legacy_support_storage_keys(&accounts)?;
    let state_before = worker.view_state(contract.id()).await?;
    let missing: Vec<_> = legacy_keys
        .iter()
        .filter(|key| !state_before.contains_key(*key))
        .collect();
    assert!(
        missing.is_empty(),
        "legacy map storage keys must exist before the upgrade: {missing:?}"
    );

    // When
    propose_and_vote_contract_binary(&accounts, &contract, current_contract()).await;

    // Then
    let configs_after: dtos::ForeignChainsConfigs = contract
        .view(method_names::GET_FOREIGN_CHAINS_CONFIGS)
        .await?
        .json()
        .context("GET_FOREIGN_CHAINS_CONFIGS json")?;
    let available_after: dtos::AvailableForeignChains = contract
        .view(method_names::GET_AVAILABLE_FOREIGN_CHAINS)
        .await?
        .json()
        .context("GET_AVAILABLE_FOREIGN_CHAINS json")?;
    let allowed_after: BTreeMap<dtos::ForeignChain, dtos::ChainEntry> = contract
        .view(method_names::ALLOWED_FOREIGN_CHAIN_PROVIDERS)
        .await?
        .json()
        .context("ALLOWED_FOREIGN_CHAIN_PROVIDERS json")?;
    assert_eq!(configs_after, configs_before);
    assert_eq!(available_after, available_before);
    assert_eq!(allowed_after, allowed_before);
    let state_after = worker.view_state(contract.id()).await?;
    let leftover: Vec<_> = legacy_keys
        .iter()
        .filter(|key| state_after.contains_key(*key))
        .collect();
    assert!(
        leftover.is_empty(),
        "legacy map storage must be reclaimed: {leftover:?}"
    );

    let error = contract
        .view("get_foreign_chain_support_by_node")
        .await
        .expect_err("legacy view must be removed");
    let error = format!("{error:?}");
    assert!(
        error.contains("MethodResolveError(MethodNotFound)"),
        "{error}"
    );
    Ok(())
}

/// Raw storage keys written by the `3.15.1` `IterableMap<AccountId, BTreeSet<ForeignChain>>`.
fn legacy_support_storage_keys(accounts: &[Account]) -> anyhow::Result<Vec<Vec<u8>>> {
    let prefix = borsh::to_vec(&StorageKey::_DeprecatedSupportedForeignChainsByNode)?;
    let indices_prefix = [prefix.as_slice(), b"v"].concat();
    let values_prefix = [prefix.as_slice(), b"m"].concat();

    let mut keys = Vec::with_capacity(accounts.len() * 2);
    for (index, account) in accounts.iter().enumerate() {
        let index = u32::try_from(index)?;
        keys.push([indices_prefix.as_slice(), &index.to_le_bytes()].concat());
        keys.push(
            Sha256::digest([values_prefix.as_slice(), &borsh::to_vec(account.id())?].concat())
                .to_vec(),
        );
    }
    Ok(keys)
}
