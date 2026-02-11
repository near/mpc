use crate::sandbox::utils::{
    consts::{CURRENT_CONTRACT_DEPLOY_DEPOSIT, GAS_FOR_INIT, GAS_FOR_VOTE_UPDATE},
    contract_build::current_contract,
    initializing_utils::{start_keygen_instance, vote_add_domains, vote_public_key},
    interface::IntoInterfaceType,
    mpc_contract::{assert_running_return_threshold, get_state, submit_participant_info},
    shared_key_utils::{make_key_for_domain, DomainKey},
    sign_utils::{make_and_submit_requests, PendingSignRequest},
};
use contract_interface::types::{self as dtos, Attestation, MockAttestation};
use digest::Digest;
use dtos::ProtocolContractState;
use mpc_contract::{
    crypto_shared::types::PublicKeyExtended,
    primitives::{
        domain::{DomainConfig, DomainId, SignatureScheme},
        key_state::{AttemptId, EpochId, KeyForDomain, Keyset},
        participants::{ParticipantInfo, Participants},
        test_utils::bogus_ed25519_near_public_key,
        thresholds::{Threshold, ThresholdParameters},
    },
    tee::tee_state::NodeId,
    update::{ProposeUpdateArgs, UpdateId},
};
use near_account_id::AccountId;
use near_sdk::NearToken;
use near_workspaces::{
    network::Sandbox,
    operations::TransactionStatus,
    result::{ExecutionFinalResult, ExecutionSuccess},
    types::AccessKeyPermission,
    AccessKey, Contract,
};
use near_workspaces::{result::Execution, Account, Worker};
use rand_core::CryptoRngCore;
use serde_json::json;
use std::{collections::BTreeSet, task::Poll, time::Duration};
use tokio::time::timeout;

pub async fn create_account_given_id(
    worker: &Worker<Sandbox>,
    account_id: AccountId,
) -> Result<Execution<Account>, near_workspaces::error::Error> {
    let (_, sk) = worker.generate_dev_account_credentials();
    worker.create_root_account_subaccount(account_id, sk).await
}

pub fn gen_participant_info() -> ParticipantInfo {
    ParticipantInfo {
        url: "127.0.0.1".into(),
        sign_pk: bogus_ed25519_near_public_key(),
    }
}

pub fn candidates(names: Option<Vec<AccountId>>) -> Participants {
    let mut participants: Participants = Participants::new();
    let names = names.unwrap_or_else(|| {
        vec![
            "alice.near".parse().unwrap(),
            "bob.near".parse().unwrap(),
            "caesar.near".parse().unwrap(),
        ]
    });

    for account_id in names {
        let _ = participants.insert(account_id.clone(), gen_participant_info());
    }
    participants
}

pub async fn gen_account(worker: &Worker<Sandbox>) -> (Account, AccountId) {
    let account = worker.dev_create_account().await.unwrap();
    let id = account.id().into();
    (account, id)
}

/// Create `amount` accounts and return them along with the candidate info.
/// This creates accounts async, but as this is not supported by
/// near_workspaces, hence the way to do so is very low level
pub async fn gen_accounts(worker: &Worker<Sandbox>, amount: usize) -> (Vec<Account>, Participants) {
    let root_account = worker.root_account().unwrap();
    let mut accounts = Vec::with_capacity(amount);
    let mut account_ids = Vec::with_capacity(amount);
    let mut account_creation_transactions = Vec::with_capacity(amount);
    for _ in 0..amount {
        let (account_id, sk) = worker.generate_dev_account_credentials();
        let account_id = format!("{}.{}", account_id, root_account.id())
            .parse()
            .unwrap();
        let transaction = root_account
            .batch(&account_id)
            .create_account()
            .add_key(
                sk.public_key(),
                AccessKey {
                    nonce: 0,
                    permission: AccessKeyPermission::FullAccess,
                },
            )
            .transfer(NearToken::from_near(100))
            .transact_async()
            .await
            .unwrap();
        account_creation_transactions.push(transaction);
        let account = Account::from_secret_key(account_id.clone(), sk, worker);
        accounts.push(account);
        account_ids.push(account_id);
    }
    for transaction in account_creation_transactions {
        // We had a flaky test here (#1913) before timeout, hopefully 100 seconds is enough
        let result = wait_for_transaction(Duration::from_secs(100), transaction)
            .await
            .unwrap();
        dbg!(&result);
        assert!(result.is_success());
    }
    let candidates = candidates(Some(account_ids));
    (accounts, candidates)
}

pub async fn init() -> (Worker<Sandbox>, Contract) {
    let worker = near_workspaces::sandbox().await.unwrap();
    let wasm = &current_contract();
    let contract = worker.dev_deploy(wasm).await.unwrap();
    (worker, contract)
}

/// Creates threshold parameters with 60% threshold (rounded up).
pub fn make_threshold_params(participants: &Participants) -> ThresholdParameters {
    let threshold = Threshold::new(((participants.len() as f64) * 0.6).ceil() as u64);
    ThresholdParameters::new(participants.clone(), threshold).unwrap()
}

/// Initialize the contract with the given parameters.
pub async fn init_contract(
    contract: &Contract,
    params: ThresholdParameters,
    init_config: Option<dtos::InitConfig>,
) -> ExecutionSuccess {
    let result = contract
        .call("init")
        .args_json(json!({
            "parameters": params,
            "init_config": init_config,
        }))
        .gas(GAS_FOR_INIT)
        .transact()
        .await
        .unwrap();
    assert!(result.is_success(), "init failed: {:?}", result);
    result.into_result().unwrap()
}

/// Initialize contract in Running state with domains and keyset.
pub async fn init_contract_running(
    contract: &Contract,
    domains: Vec<DomainConfig>,
    next_domain_id: u64,
    keyset: Keyset,
    params: ThresholdParameters,
) -> ExecutionSuccess {
    let result = contract
        .call("init_running")
        .args_json(json!({
            "domains": domains,
            "next_domain_id": next_domain_id,
            "keyset": keyset,
            "parameters": params,
        }))
        .gas(GAS_FOR_INIT)
        .transact()
        .await
        .unwrap();
    assert!(result.is_success(), "init_running failed: {:?}", result);
    result.into_result().unwrap()
}

pub struct DomainPublicKey {
    public_key: PublicKeyExtended,
    config: DomainConfig,
}

/// Initializes the contract with `pks` as public keys, a set of participants and a threshold.
pub async fn init_with_candidates(
    pks: Vec<dtos::PublicKey>,
    init_config: Option<dtos::InitConfig>,
    number_of_participants: usize,
) -> (
    Worker<Sandbox>,
    Contract,
    Vec<Account>,
    Vec<DomainPublicKey>,
) {
    let (worker, contract) = init().await;
    let (accounts, participants) = gen_accounts(&worker, number_of_participants).await;
    let threshold_parameters = make_threshold_params(&participants);
    let mut ret_domains: Vec<DomainPublicKey> = Vec::new();

    let init = if !pks.is_empty() {
        let (domains, keys): (Vec<_>, Vec<_>) = pks
            .into_iter()
            .enumerate()
            .map(|(i, pk)| {
                let domain_id = DomainId((i as u64) * 2);
                let scheme = match pk {
                    dtos::PublicKey::Ed25519(_) => SignatureScheme::Ed25519,
                    dtos::PublicKey::Secp256k1(_) => SignatureScheme::Secp256k1,
                    dtos::PublicKey::Bls12381(_) => SignatureScheme::Bls12381,
                };
                let key: PublicKeyExtended = pk.try_into().unwrap();
                ret_domains.push(DomainPublicKey {
                    public_key: key.clone(),
                    config: DomainConfig {
                        id: domain_id,
                        scheme,
                    },
                });
                (
                    DomainConfig {
                        id: domain_id,
                        scheme,
                    },
                    KeyForDomain {
                        attempt: AttemptId::new(),
                        domain_id,
                        key,
                    },
                )
            })
            .unzip();

        let next_domain_id = (domains.len() as u64) * 2;
        let keyset = Keyset::new(EpochId::new(5), keys);
        init_contract_running(
            &contract,
            domains,
            next_domain_id,
            keyset,
            threshold_parameters,
        )
        .await
    } else {
        init_contract(&contract, threshold_parameters, init_config).await
    };

    // Give each participant a valid attestation initially
    submit_attestations(&contract, &accounts, &participants).await;

    dbg!(init);
    (worker, contract, accounts, ret_domains)
}

pub struct SandboxTestSetup {
    pub worker: Worker<Sandbox>,
    pub contract: Contract,
    pub mpc_signer_accounts: Vec<Account>,
    pub keys: Vec<DomainKey>,
}

pub async fn init_env(
    schemes: &[SignatureScheme],
    number_of_participants: usize,
) -> SandboxTestSetup {
    let (public_keys, secret_keys): (Vec<_>, Vec<_>) = schemes
        .iter()
        .map(|scheme| make_key_for_domain(*scheme))
        .collect();
    let (worker, contract, mpc_signer_accounts, domains) =
        init_with_candidates(public_keys, None, number_of_participants).await;
    let keys = domains
        .into_iter()
        .zip(secret_keys.into_iter())
        .map(|(public, secret)| DomainKey {
            domain_config: public.config,
            domain_secret_key: secret,
            domain_public_key: public.public_key,
        })
        .collect();
    SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    }
}

/// Upgrades the given contract to the [`current_contract`] binary.
///
/// This function:
/// 1. Submits a proposal to upgrade the contract.
/// 2. Casts votes until the proposal is executed.
/// 3. Verifies the contract was upgraded by checking the contract's binary.
///
/// Panics if:
/// - The proposal transaction fails,
/// - The state call is not deserializable,
/// - Or the post-upgrade code does not match the expected binary.
pub async fn propose_and_vote_contract_binary(
    accounts: &[Account],
    contract: &Contract,
    new_contract_binary: &[u8],
) {
    let propose_update_execution = accounts[0]
        .call(contract.id(), "propose_update")
        .args_borsh(ProposeUpdateArgs {
            code: Some(new_contract_binary.to_vec()),
            config: None,
        })
        .max_gas()
        .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
        .transact()
        .await
        .expect("propose update call succeeds");

    assert!(
        propose_update_execution.is_success(),
        "propose update call failed"
    );

    let proposal_id: UpdateId = propose_update_execution.json().unwrap();

    // Try calling into state and see if it works.
    let state_request_execution = accounts[0]
        .call(contract.id(), "state")
        .transact()
        .await
        .expect("state request succeeds");

    let _state: ProtocolContractState = state_request_execution
        .json()
        .expect("state is deserializable.");

    vote_update_till_completion(contract, accounts, &proposal_id).await;

    let contract_binary_post_upgrade = contract.view_code().await.unwrap();
    assert_eq!(
        hash(new_contract_binary),
        hash(&contract_binary_post_upgrade),
        "Code hash post upgrade is not matching the proposed binary."
    );
}

pub async fn vote_update_till_completion(
    contract: &Contract,
    accounts: &[Account],
    proposal_id: &UpdateId,
) {
    for voter in accounts {
        let execution = voter
            .call(contract.id(), "vote_update")
            .args_json(serde_json::json!({
                "id": proposal_id,
            }))
            .gas(GAS_FOR_VOTE_UPDATE)
            .transact()
            .await
            .unwrap();

        dbg!(&execution);

        let update_occurred: bool = execution.json().expect("Vote cast was unsuccessful");

        if update_occurred {
            return;
        }
    }
    panic!("Update didn't occurred")
}

pub async fn submit_tee_attestations(
    contract: &Contract,
    env_accounts: &mut [Account],
    node_ids: &BTreeSet<NodeId>,
) -> anyhow::Result<()> {
    env_accounts.sort_by(|left, right| left.id().cmp(right.id()));
    for (account, node_id) in env_accounts.iter().zip(node_ids) {
        assert_eq!(*account.id(), node_id.account_id, "AccountId mismatch");
        let attestation = Attestation::Mock(MockAttestation::Valid); // TODO(#1109): add TLS key.
        let result = submit_participant_info(
            account,
            contract,
            &attestation,
            &node_id.tls_public_key.into_interface_type(),
        )
        .await?;
        assert!(result.is_success());
    }
    Ok(())
}

/// Submit mock attestations for all participants in parallel.
pub async fn submit_attestations(
    contract: &Contract,
    accounts: &[Account],
    participants: &Participants,
) {
    let futures: Vec<_> = participants
        .participants()
        .iter()
        .zip(accounts)
        .enumerate()
        .map(|(i, ((_, _, participant), account))| async move {
            let attestation = Attestation::Mock(MockAttestation::Valid);
            let tls_key = (&participant.sign_pk).into_interface_type();
            let success = submit_participant_info(account, contract, &attestation, &tls_key)
                .await
                .expect("submit_participant_info should not error")
                .is_success();
            assert!(
                success,
                "submit_participant_info failed for participant {}",
                i
            );
        })
        .collect();
    futures::future::join_all(futures).await;
}

/// This function assumes that the accounts are sorted by participant id.
/// Returns the shared_secret_key in the same order as
/// the corresponding domain configs supplied.
pub async fn call_contract_key_generation<const N: usize>(
    domains_to_add: &[DomainConfig; N],
    accounts: &[Account],
    contract: &Contract,
    expected_epoch_id: u64,
) -> [DomainKey; N] {
    let mut domain_keys = vec![];

    let existing_domains = {
        let state: ProtocolContractState = get_state(contract).await;
        match state {
            ProtocolContractState::Running(state) => state.domains.domains.len(),
            _ => panic!("ProtocolContractState must be Running"),
        }
    };

    vote_add_domains(contract, accounts, domains_to_add)
        .await
        .unwrap();

    let state: ProtocolContractState = get_state(contract).await;
    match state {
        ProtocolContractState::Initializing(state) => {
            assert_eq!(
                state.domains.domains.len(),
                existing_domains + domains_to_add.len()
            );
        }
        _ => panic!("should be in initializing state"),
    };

    for domain in domains_to_add.iter() {
        let key_event_id = dtos::KeyEventId {
            epoch_id: dtos::EpochId(expected_epoch_id),
            domain_id: dtos::DomainId(*domain.id),
            attempt_id: dtos::AttemptId(0),
        };
        start_keygen_instance(contract, accounts, key_event_id)
            .await
            .unwrap();
        let (public_key, shared_secret_key) = make_key_for_domain(domain.scheme);

        domain_keys.push(DomainKey {
            domain_config: domain.clone(),
            domain_secret_key: shared_secret_key,
            domain_public_key: public_key.clone().try_into().unwrap(),
        });

        vote_public_key(contract, accounts, key_event_id, public_key)
            .await
            .unwrap();
    }

    let state: ProtocolContractState = get_state(contract).await;
    match state {
        ProtocolContractState::Running(state) => {
            assert_eq!(state.keyset.epoch_id.0, expected_epoch_id);
            assert_eq!(
                state.domains.domains.len(),
                domains_to_add.len() + existing_domains
            );
        }
        state => panic!("should be in running state. Actual state: {state:#?}"),
    };

    domain_keys.try_into().unwrap()
}

pub struct InjectedContractState {
    pub pending_sign_requests: Vec<PendingSignRequest>,
    pub domain_keys: Vec<DomainKey>,
}

/// Adds dummy state to a contract (threshold proposal, domains, sign requests)
/// so that migration paths are exercised in upgrade tests.
///
/// The pending signature requests can be responded to.
pub async fn execute_key_generation_and_add_random_state(
    accounts: &[Account],
    participants: Participants,
    contract: &Contract,
    worker: &Worker<Sandbox>,
    rng: &mut impl CryptoRngCore,
) -> InjectedContractState {
    const EPOCH_ID: u64 = 0;
    let threshold = assert_running_return_threshold(contract).await;

    // 1. Submit a threshold proposal (raise threshold to threshold + 1).
    let dummy_threshold_parameters =
        ThresholdParameters::new(participants, Threshold::new(threshold.0 + 1)).unwrap();
    let dummy_proposal = json!({
        "prospective_epoch_id": 1,
        "proposal": dummy_threshold_parameters,
    });
    accounts[0]
        .call(contract.id(), "vote_new_parameters")
        .args_json(dummy_proposal)
        .max_gas()
        .transact()
        .await
        .unwrap()
        .unwrap();

    // 2. Add multiple domains.
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
    let domain_keys =
        call_contract_key_generation(&domains_to_add, accounts, contract, EPOCH_ID).await;

    // 3. Submit pending sign requests.
    let (pending_sign_requests, _) =
        make_and_submit_requests(&domain_keys, contract, worker, rng).await;

    InjectedContractState {
        pending_sign_requests,
        domain_keys: domain_keys.to_vec(),
    }
}

fn hash(code: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(code);
    hasher.finalize().into()
}

pub async fn generate_participant_and_submit_attestation(
    worker: &Worker<Sandbox>,
    contract: &Contract,
) -> (Account, AccountId, ParticipantInfo) {
    let (new_account, account_id) = gen_account(worker).await;
    let new_participant = gen_participant_info();

    // Submit attestation for the new participant, otherwise
    // the contract will reject the resharing.
    let result = submit_participant_info(
        &new_account,
        contract,
        &dtos::Attestation::Mock(dtos::MockAttestation::Valid),
        &new_participant.sign_pk.into_interface_type(),
    )
    .await
    .expect("Attestation submission for new account must succeed.");
    assert!(result.is_success());
    (new_account, account_id, new_participant)
}

// This function is needed because in case of timeouts the wait function
// for transactions fails instead of retrying.
// See near_workspaces::operations::TransactionStatus in
// https://github.com/near/near-workspaces-rs/blob/dc729222070b508381b8dc81c027b0c0e6720567/workspaces/src/operations.rs#L494
pub async fn wait_for_transaction(
    timeout_s: Duration,
    transaction: TransactionStatus,
) -> anyhow::Result<ExecutionFinalResult> {
    let mut result = None;
    let loop_future = async {
        loop {
            match transaction.status().await {
                Ok(Poll::Ready(val)) => {
                    result = Some(Ok(val));
                    break;
                }
                Ok(Poll::Pending) => {}
                Err(err) => {
                    result = Some(Err(err));
                }
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    };

    match timeout(timeout_s, loop_future).await {
        Ok(_) => match result {
            Some(result) => Ok(result?),
            None => anyhow::bail!("Transaction timed out without returning an error"),
        },
        Err(_) => anyhow::bail!("Loop timed out"),
    }
}
