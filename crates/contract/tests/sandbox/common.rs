use crate::sandbox::utils::{
    consts::{CURRENT_CONTRACT_DEPLOY_DEPOSIT, GAS_FOR_INIT, GAS_FOR_VOTE_UPDATE, PARTICIPANT_LEN},
    contract_build::current_contract,
    initializing_utils::{start_keygen_instance, vote_add_domains, vote_public_key},
    mpc_contract::{assert_running_return_threshold, get_state, submit_participant_info},
    shared_key_utils::{make_key_for_domain, DomainKey},
    sign_utils::{make_and_submit_requests, PendingSignRequest},
};
use digest::Digest;
use dtos::ProtocolContractState;
use k256::ecdsa::SigningKey;
use mpc_contract::{
    crypto_shared::types::PublicKeyExtended,
    primitives::{
        domain::{Curve, DomainConfig, DomainId, DomainPurpose},
        key_state::{AttemptId, EpochId, KeyForDomain, Keyset},
        participants::{ParticipantInfo, Participants},
        test_utils::{bogus_ed25519_near_public_key, infer_purpose_from_curve},
        thresholds::{Threshold, ThresholdParameters},
    },
    tee::tee_state::NodeId,
    update::{ProposeUpdateArgs, UpdateId},
};
use near_account_id::AccountId;
use near_mpc_bounded_collections::NonEmptyBTreeSet;
use near_mpc_contract_interface::{
    method_names,
    types::{
        self as dtos, Attestation, BitcoinExtractedValue, BitcoinExtractor, BitcoinRpcRequest,
        BitcoinTxId, BlockConfirmations, EvmExtractedValue, EvmExtractor, EvmFinality,
        EvmRpcRequest, EvmTxId, ForeignChainPolicy, ForeignTxSignPayload, ForeignTxSignPayloadV1,
        MockAttestation, RpcProvider, StarknetExtractedValue, StarknetExtractor, StarknetFelt,
        StarknetFinality, StarknetRpcRequest, StarknetTxId, VerifyForeignTransactionResponse,
    },
};
use near_mpc_sdk::foreign_chain::{ExtractedValue, ForeignChainRpcRequest, Hash256};
use near_workspaces::{network::Sandbox, result::ExecutionSuccess, Contract};
use near_workspaces::{result::Execution, Account, Worker};
use rand_core::CryptoRngCore;
use serde_json::json;
use signature::hazmat::PrehashSigner;
use std::collections::BTreeSet;
use std::time::Duration;
use tokio_util::time::FutureExt as _;

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
pub async fn gen_accounts(worker: &Worker<Sandbox>, amount: usize) -> (Vec<Account>, Participants) {
    let mut accounts = Vec::with_capacity(amount);
    let mut account_ids = Vec::with_capacity(amount);
    for _ in 0..amount {
        let (account, account_id) = gen_account(worker).await;
        accounts.push(account);
        account_ids.push(account_id);
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
        .call(method_names::INIT)
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
        .call(method_names::INIT_RUNNING)
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

pub struct SandboxTestSetup {
    pub worker: Worker<Sandbox>,
    pub contract: Contract,
    pub mpc_signer_accounts: Vec<Account>,
    pub keys: Vec<DomainKey>,
}

impl SandboxTestSetup {
    pub fn builder() -> SandboxTestSetupBuilder {
        SandboxTestSetupBuilder {
            curves: Vec::new(),
            foreign_tx: false,
            number_of_participants: PARTICIPANT_LEN,
            init_config: None,
        }
    }

    /// Returns the first key with `ForeignTx` purpose.
    pub fn foreign_tx_key(&self) -> &DomainKey {
        self.keys
            .iter()
            .find(|k| k.domain_config.purpose == DomainPurpose::ForeignTx)
            .expect("No ForeignTx domain in setup. Did you call .foreign_tx() on the builder?")
    }
}

pub struct SandboxTestSetupBuilder {
    curves: Vec<Curve>,
    foreign_tx: bool,
    number_of_participants: usize,
    init_config: Option<dtos::InitConfig>,
}

impl SandboxTestSetupBuilder {
    pub fn with_curves(mut self, curves: &[Curve]) -> Self {
        self.curves = curves.to_vec();
        self
    }

    pub fn with_number_of_participants(mut self, n: usize) -> Self {
        self.number_of_participants = n;
        self
    }

    pub fn with_init_config(mut self, config: dtos::InitConfig) -> Self {
        self.init_config = Some(config);
        self
    }

    pub fn with_foreign_tx_domain(mut self) -> Self {
        self.foreign_tx = true;
        self
    }

    pub async fn build(self) -> SandboxTestSetup {
        let (worker, contract) = init().await;
        let (accounts, participants) = gen_accounts(&worker, self.number_of_participants).await;
        let threshold_parameters = make_threshold_params(&participants);

        let mut keys = Vec::new();
        let mut domain_configs = Vec::new();
        let mut key_for_domains = Vec::new();
        let mut domain_id_counter = 0u64;

        // Sign-purpose domains from curves
        for curve in &self.curves {
            let (pk, sk) = make_key_for_domain(*curve);
            let purpose = infer_purpose_from_curve(*curve);
            let domain_id = DomainId(domain_id_counter);
            domain_id_counter += 2;

            let key: PublicKeyExtended = pk.try_into().unwrap();
            let config = DomainConfig {
                id: domain_id,
                curve: *curve,
                purpose,
            };
            keys.push(DomainKey {
                domain_config: config.clone(),
                domain_secret_key: sk,
                domain_public_key: key.clone(),
            });
            domain_configs.push(config);
            key_for_domains.push(KeyForDomain {
                attempt: AttemptId::new(),
                domain_id,
                key,
            });
        }

        // Optional ForeignTx domain
        if self.foreign_tx {
            let (pk, sk) = make_key_for_domain(Curve::Secp256k1);
            let domain_id = DomainId(domain_id_counter);
            domain_id_counter += 2;

            let key: PublicKeyExtended = pk.try_into().unwrap();
            let config = DomainConfig {
                id: domain_id,
                curve: Curve::Secp256k1,
                purpose: DomainPurpose::ForeignTx,
            };
            keys.push(DomainKey {
                domain_config: config.clone(),
                domain_secret_key: sk,
                domain_public_key: key.clone(),
            });
            domain_configs.push(config);
            key_for_domains.push(KeyForDomain {
                attempt: AttemptId::new(),
                domain_id,
                key,
            });
        }

        if !domain_configs.is_empty() {
            let next_domain_id = domain_id_counter;
            let keyset = Keyset::new(EpochId::new(5), key_for_domains);
            init_contract_running(
                &contract,
                domain_configs,
                next_domain_id,
                keyset,
                threshold_parameters,
            )
            .await;
        } else {
            init_contract(&contract, threshold_parameters, self.init_config).await;
        }

        submit_attestations(&contract, &accounts, &participants).await;

        SandboxTestSetup {
            worker,
            contract,
            mpc_signer_accounts: accounts,
            keys,
        }
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
        .call(contract.id(), method_names::PROPOSE_UPDATE)
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
        .call(contract.id(), method_names::STATE)
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
            .call(contract.id(), method_names::VOTE_UPDATE)
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
            &dtos::Ed25519PublicKey::try_from(&node_id.tls_public_key)
                .expect("expected ED25519 key"),
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
            let tls_key: dtos::Ed25519PublicKey =
                dtos::Ed25519PublicKey::try_from(&participant.sign_pk)
                    .expect("expected ED25519 key");
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
        let (public_key, shared_secret_key) = make_key_for_domain(domain.curve);

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
        .call(contract.id(), method_names::VOTE_NEW_PARAMETERS)
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
            curve: Curve::Edwards25519,
            purpose: DomainPurpose::Sign,
        },
        DomainConfig {
            id: 1.into(),
            curve: Curve::Secp256k1,
            purpose: DomainPurpose::Sign,
        },
        DomainConfig {
            id: 2.into(),
            curve: Curve::Edwards25519,
            purpose: DomainPurpose::Sign,
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

/// Build a [`ForeignChainPolicy`] that enables the given chain with a dummy RPC URL.
pub fn make_foreign_chain_policy(
    chain: &near_mpc_contract_interface::types::ForeignChain,
) -> near_mpc_contract_interface::types::ForeignChainPolicy {
    let mut chains = std::collections::BTreeMap::new();
    chains.insert(
        chain.clone(),
        NonEmptyBTreeSet::new(RpcProvider {
            rpc_url: format!("https://{chain:?}-rpc.example.com").to_lowercase(),
        }),
    );
    ForeignChainPolicy { chains }
}

/// Vote the given chain policy from all participants.
pub async fn vote_chain_policy(
    chain: &near_mpc_contract_interface::types::ForeignChain,
    contract: &Contract,
    accounts: &[Account],
) {
    let policy = make_foreign_chain_policy(chain);
    for account in accounts {
        let result = account
            .call(contract.id(), method_names::VOTE_FOREIGN_CHAIN_POLICY)
            .args_json(json!({ "policy": policy }))
            .transact()
            .await
            .unwrap()
            .into_result();
        assert!(result.is_ok(), "vote_foreign_chain_policy should succeed");
    }
}

/// Poll the contract until a pending foreign-tx request appears (or panic after timeout).
pub async fn await_pending_foreign_tx_request_observed_on_contract(
    contract: &Contract,
    request: &dtos::VerifyForeignTransactionRequest,
) {
    const TIMEOUT: Duration = Duration::from_secs(10);
    const POLL_INTERVAL: Duration = Duration::from_millis(100);

    async {
        let args = json!({ "request": request });

        loop {
            let result = contract
                .view(method_names::GET_PENDING_VERIFY_FOREIGN_TX_REQUEST)
                .args_json(&args)
                .await;
            if let Ok(view) = result {
                // The view returns Option<YieldIndex>; non-null means the request is pending.
                let value: serde_json::Value = view.json().unwrap();
                if !value.is_null() {
                    return;
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
    .timeout(TIMEOUT)
    .await
    .expect("Timed out waiting for pending foreign-tx request on-chain");
}

/// Sign a foreign-tx payload hash with the root secret key and return the
/// payload and contract-level response DTO.
pub fn sign_foreign_tx_response(
    request: &near_mpc_contract_interface::types::ForeignChainRpcRequest,
    extracted_values: Vec<near_mpc_contract_interface::types::ExtractedValue>,
    sk: &threshold_signatures::ecdsa::KeygenOutput,
) -> (
    near_mpc_contract_interface::types::ForeignTxSignPayload,
    near_mpc_contract_interface::types::VerifyForeignTransactionResponse,
) {
    let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
        request: request.clone(),
        values: extracted_values,
    });
    let payload_hash = payload.compute_msg_hash().unwrap();

    let signing_key = SigningKey::from_bytes(&sk.private_share.to_scalar().into()).unwrap();
    let (signature, recovery_id) = signing_key.sign_prehash(&payload_hash.0).unwrap();
    let signature_response = near_mpc_contract_interface::types::SignatureResponse::Secp256k1(
        near_mpc_contract_interface::types::K256Signature::from_ecdsa_recoverable(
            &signature,
            recovery_id,
        ),
    );

    let response = VerifyForeignTransactionResponse {
        payload_hash,
        signature: signature_response,
    };
    (payload, response)
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
        &dtos::Ed25519PublicKey::try_from(&new_participant.sign_pk).expect("expected ED25519 key"),
    )
    .await
    .expect("Attestation submission for new account must succeed.");
    assert!(result.is_success());
    (new_account, account_id, new_participant)
}

pub fn ethereum_evm_request() -> ForeignChainRpcRequest {
    ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
        tx_id: EvmTxId([0xbb; 32]),
        extractors: vec![EvmExtractor::BlockHash],
        finality: EvmFinality::Finalized,
    })
}

pub fn abstract_evm_request() -> ForeignChainRpcRequest {
    ForeignChainRpcRequest::Abstract(EvmRpcRequest {
        tx_id: EvmTxId([0xbb; 32]),
        extractors: vec![EvmExtractor::BlockHash],
        finality: EvmFinality::Finalized,
    })
}

pub fn bitcoin_request() -> ForeignChainRpcRequest {
    ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
        tx_id: BitcoinTxId([0xdd; 32]),
        confirmations: BlockConfirmations(6),
        extractors: vec![BitcoinExtractor::BlockHash],
    })
}

pub fn starknet_request() -> ForeignChainRpcRequest {
    ForeignChainRpcRequest::Starknet(StarknetRpcRequest {
        tx_id: StarknetTxId(StarknetFelt([0xee; 32])),
        finality: StarknetFinality::AcceptedOnL1,
        extractors: vec![StarknetExtractor::BlockHash],
    })
}

pub fn evm_block_hash_extracted_values() -> Vec<ExtractedValue> {
    vec![ExtractedValue::EvmExtractedValue(
        EvmExtractedValue::BlockHash(Hash256([0xaa; 32])),
    )]
}

pub fn bitcoin_extracted_values() -> Vec<ExtractedValue> {
    vec![ExtractedValue::BitcoinExtractedValue(
        BitcoinExtractedValue::BlockHash(Hash256([0xaa; 32])),
    )]
}

pub fn starknet_extracted_values() -> Vec<ExtractedValue> {
    vec![ExtractedValue::StarknetExtractedValue(
        StarknetExtractedValue::BlockHash(StarknetFelt([0xaa; 32])),
    )]
}

pub fn bnb_evm_request() -> ForeignChainRpcRequest {
    ForeignChainRpcRequest::Bnb(EvmRpcRequest {
        tx_id: EvmTxId([0xbb; 32]),
        extractors: vec![EvmExtractor::BlockHash],
        finality: EvmFinality::Finalized,
    })
}
