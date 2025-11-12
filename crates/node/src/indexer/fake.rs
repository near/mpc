use super::handler::{ChainBlockUpdate, SignatureRequestFromChain};
use super::migrations::ContractMigrationInfo;
use super::participants::ContractState;
use super::types::{
    ChainSendTransactionRequest, ChainSignatureRespondArgs, ConcludeNodeMigrationArgs,
};
use super::IndexerAPI;
use crate::config::{self, ParticipantsConfig};
use crate::indexer::handler::CKDRequestFromChain;
use crate::indexer::types::ChainCKDRespondArgs;
use crate::migration_service::types::MigrationInfo;
use crate::providers::PublicKeyConversion;
use crate::requests::recent_blocks_tracker::tests::TestBlockMaker;
use crate::tests::common::MockTransactionSender;
use crate::tracking::{AutoAbortTask, AutoAbortTaskCollection};
use crate::types::CKDId;
use crate::types::SignatureId;
use anyhow::Context;
use derive_more::From;
use ed25519_dalek::VerifyingKey;
use mpc_contract::config::Config;
use mpc_contract::node_migrations::NodeMigrations;
use mpc_contract::primitives::{
    domain::{DomainConfig, DomainRegistry},
    key_state::{EpochId, KeyEventId, Keyset},
    participants::{ParticipantId, ParticipantInfo, Participants},
    signature::Payload,
    thresholds::{Threshold, ThresholdParameters},
};
use mpc_contract::state::{
    initializing::InitializingContractState, key_event::tests::Environment, key_event::KeyEvent,
    resharing::ResharingContractState, running::RunningContractState, ProtocolContractState,
};
use near_sdk::AccountId;
use near_time::{Clock, Duration};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{atomic::AtomicBool, Arc};
use tokio::sync::{broadcast, mpsc, watch};

/// A simplification of the real MPC contract state for testing.
pub struct FakeMpcContractState {
    pub state: ProtocolContractState,
    config: Config,
    env: Environment,
    pub pending_signatures: BTreeMap<Payload, SignatureId>,
    pub pending_ckds: BTreeMap<AccountId, CKDId>,
    pub migration_service: NodeMigrations,
}

impl FakeMpcContractState {
    pub fn new() -> Self {
        let state = ProtocolContractState::NotInitialized;
        let config = Config {
            key_event_timeout_blocks: 10,
            ..Default::default()
        };
        let env = Environment::new(None, None, None);
        Self {
            state,
            config,
            env,
            pending_signatures: BTreeMap::new(),
            pending_ckds: BTreeMap::new(),
            migration_service: NodeMigrations::default(),
        }
    }

    pub fn initialize(&mut self, participants: ParticipantsConfig) {
        assert!(matches!(self.state, ProtocolContractState::NotInitialized));

        self.state = ProtocolContractState::Running(RunningContractState::new(
            DomainRegistry::default(),
            Keyset::new(EpochId::new(0), Vec::new()),
            participants_config_to_threshold_parameters(&participants),
        ));
    }

    pub fn add_domains(&mut self, domains: Vec<DomainConfig>) {
        let state = match &mut self.state {
            ProtocolContractState::Running(state) => state,
            _ => panic!("Cannot add domains to non-running state"),
        };
        let new_state = InitializingContractState {
            domains: state
                .domains
                .add_domains(domains.clone())
                .expect("Failed to add domains"),
            epoch_id: state.keyset.epoch_id,
            generated_keys: state.keyset.domains.clone(),
            generating_key: KeyEvent::new(
                state.keyset.epoch_id,
                domains[0].clone(),
                state.parameters.clone(),
            ),
            cancel_votes: BTreeSet::new(),
        };
        self.state = ProtocolContractState::Initializing(new_state);
    }

    pub fn start_resharing(&mut self, new_participants: ParticipantsConfig) {
        let (previous_running_state, prev_epoch_id) = match &self.state {
            ProtocolContractState::Running(state) => (state, state.keyset.epoch_id),
            ProtocolContractState::Resharing(state) => {
                (&state.previous_running_state, state.prospective_epoch_id())
            }
            _ => panic!("Cannot start resharing from non-running state"),
        };
        self.state = ProtocolContractState::Resharing(ResharingContractState {
            previous_running_state: RunningContractState::new(
                previous_running_state.domains.clone(),
                previous_running_state.keyset.clone(),
                previous_running_state.parameters.clone(),
            ),
            reshared_keys: Vec::new(),
            resharing_key: KeyEvent::new(
                prev_epoch_id.next(),
                previous_running_state
                    .domains
                    .get_domain_by_index(0)
                    .unwrap()
                    .clone(),
                participants_config_to_threshold_parameters(&new_participants),
            ),
            cancellation_requests: HashSet::new(),
        });
    }

    pub fn vote_pk(
        &mut self,
        account_id: AccountId,
        key_id: KeyEventId,
        dto_pk: contract_interface::types::PublicKey,
    ) {
        let contract_extended_pk = dto_pk.try_into().unwrap();

        match &mut self.state {
            ProtocolContractState::Initializing(state) => {
                self.env.set_signer(&account_id);
                let result = match state.vote_pk(key_id, contract_extended_pk) {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::info!("vote_pk transaction failed: {}", e);
                        return;
                    }
                };
                if let Some(new_state) = result {
                    self.state = ProtocolContractState::Running(new_state);
                }
            }
            _ => {
                tracing::info!(
                    "vote_pk transaction ignored because the contract is not in initializing state"
                );
            }
        }
    }

    pub fn vote_start_keygen(&mut self, account_id: AccountId, id: KeyEventId) {
        match &mut self.state {
            ProtocolContractState::Initializing(state) => {
                self.env.set_signer(&account_id);
                if let Err(e) = state.start(id, self.config.key_event_timeout_blocks) {
                    tracing::info!("vote_start_keygen transaction failed: {}", e);
                }
            }
            _ => {
                tracing::info!(
                    "vote_start_keygen transaction ignored because the contract is not in initializing state"
                );
            }
        }
    }

    pub fn vote_abort_key_event(&mut self, account_id: AccountId, id: KeyEventId) {
        self.env.set_signer(&account_id);
        match &mut self.state {
            ProtocolContractState::Initializing(state) => {
                if let Err(e) = state.vote_abort(id) {
                    tracing::info!("vote_abort_key_event transaction failed: {}", e);
                }
            }
            ProtocolContractState::Resharing(state) => {
                if let Err(e) = state.vote_abort(id) {
                    tracing::info!("vote_abort_key_event transaction failed: {}", e);
                }
            }
            _ => {
                tracing::info!(
                    "vote_abort_key_event transaction ignored because the contract is not in initializing or resharing state"
                );
            }
        }
    }

    pub fn vote_start_reshare(&mut self, account_id: AccountId, id: KeyEventId) {
        match &mut self.state {
            ProtocolContractState::Resharing(state) => {
                self.env.set_signer(&account_id);
                if let Err(e) = state.start(id, self.config.key_event_timeout_blocks) {
                    tracing::info!("vote_start_reshare transaction failed: {}", e);
                }
            }
            _ => {
                tracing::info!(
                    "vote_start_reshare transaction ignored because the contract is not in resharing state"
                );
            }
        }
    }

    pub fn vote_reshared(&mut self, account_id: AccountId, key_id: KeyEventId) {
        match &mut self.state {
            ProtocolContractState::Resharing(state) => {
                self.env.set_signer(&account_id);
                let result = match state.vote_reshared(key_id) {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::info!("vote_reshared transaction failed: {}", e);
                        return;
                    }
                };
                if let Some(new_state) = result {
                    self.state = ProtocolContractState::Running(new_state);
                }
            }
            _ => {
                tracing::info!(
                    "vote_reshared transaction ignored because the contract is not in resharing state"
                );
            }
        }
    }

    pub fn update_participant_info(
        &mut self,
        account_id: AccountId,
        participant_info: ParticipantInfo,
    ) {
        match &self.state {
            ProtocolContractState::Running(state) => {
                let mut new_participants = state.parameters.participants().clone();
                new_participants
                    .update_info(account_id, participant_info)
                    .unwrap();
                let new_parameters =
                    ThresholdParameters::new(new_participants, state.parameters.threshold())
                        .unwrap();
                let new_state = RunningContractState {
                    domains: state.domains.clone(),
                    keyset: state.keyset.clone(),
                    parameters: new_parameters,
                    parameters_votes: state.parameters_votes.clone(),
                    add_domains_votes: state.add_domains_votes.clone(),
                    previously_cancelled_resharing_epoch_id: state
                        .previously_cancelled_resharing_epoch_id,
                };
                self.state = ProtocolContractState::Running(new_state);
            }
            _ => {
                panic!(
                    "update_participant_info  ignored because the contract is not in running state"
                );
            }
        }
    }

    pub fn conclude_node_migration(
        &mut self,
        account_id: AccountId,
        args: ConcludeNodeMigrationArgs,
    ) {
        let (account_id, _, node) = self.migration_service.get_for_account(&account_id);
        let node_info = node.expect("expected node info");
        let ProtocolContractState::Running(running_state) = &self.state else {
            panic!("only allow calling this in `running_state`");
        };
        if running_state.keyset != args.keyset {
            panic!("keyset mismatch");
        }
        self.migration_service.remove_migration(&account_id);
        self.update_participant_info(account_id, node_info.destination_node_info);
    }
}

pub fn participant_info_from_config(info: &config::ParticipantInfo) -> ParticipantInfo {
    ParticipantInfo {
        sign_pk: info.p2p_public_key.to_near_sdk_public_key().unwrap(),
        url: format!("http://{}:{}", info.address, info.port),
    }
}

fn participants_config_to_threshold_parameters(
    participants_config: &ParticipantsConfig,
) -> ThresholdParameters {
    let mut participants = Participants::new();
    let mut infos = participants_config.participants.clone();
    infos.sort_by_key(|info| info.id);

    for info in infos {
        participants
            .insert_with_id(
                info.near_account_id.clone(),
                participant_info_from_config(&info),
                ParticipantId(info.id.raw()),
            )
            .expect("Failed to insert participant");
    }
    ThresholdParameters::new(participants, Threshold::new(participants_config.threshold)).unwrap()
}

/// Runs the fake indexer's shared state and logic. There's one instance of this per test.
struct FakeIndexerCore {
    clock: Clock,
    /// Delay (in number of blocks) from when a txn is submitted to when it affects the contract
    /// state.
    txn_delay_blocks: u64,
    /// A fake contract state to emulate the real MPC contract but with much less complexity.
    contract: Arc<tokio::sync::Mutex<FakeMpcContractState>>,
    /// Receives transactions sent via the APIs of each node.
    txn_receiver: mpsc::UnboundedReceiver<(ChainSendTransactionRequest, TestNodeUid)>,
    /// Receives signature requests from the FakeIndexerManager.
    signature_request_receiver: mpsc::UnboundedReceiver<SignatureRequestFromChain>,
    /// Receives ckd requests from the FakeIndexerManager.
    ckd_request_receiver: mpsc::UnboundedReceiver<CKDRequestFromChain>,
    /// Broadcasts the contract state to each node.
    state_change_sender: broadcast::Sender<ContractState>,
    /// Broadcasts block updates to each node.
    block_update_sender: broadcast::Sender<ChainBlockUpdate>,
    /// Broadcasts the contract state to each node.
    migration_change_sender: broadcast::Sender<ContractMigrationInfo>,

    /// When the core receives signature response txns, it processes them by sending them through
    /// this sender. The receiver end of this is in FakeIndexManager to be received by the test
    /// code.
    signature_response_sender: mpsc::UnboundedSender<ChainSignatureRespondArgs>,

    /// When the core receives ckd response txns, it processes them by sending them through
    /// this sender. The receiver end of this is in FakeIndexManager to be received by the test
    /// code.
    ckd_response_sender: mpsc::UnboundedSender<ChainCKDRespondArgs>,

    /// How long to wait before generating the next block.
    block_time: std::time::Duration,

    account_id_by_uid: Arc<std::sync::Mutex<HashMap<TestNodeUid, AccountId>>>,
}

impl FakeIndexerCore {
    pub async fn run(mut self) {
        let mut tasks = AutoAbortTaskCollection::new();
        let contract = self.contract.clone();
        tasks.spawn_with_tokio({
            let contract = contract.clone();
            let clock = self.clock.clone();
            let state_change_sender = self.state_change_sender.clone();
            let migration_state_sender = self.migration_change_sender.clone();
            async move {
                loop {
                    {
                        let state = contract.lock().await;
                        let config = ContractState::from_contract_state(
                            &state.state,
                            state.env.block_height,
                            None,
                        )
                        .expect("Failed to convert contract state");
                        state_change_sender.send(config).ok();
                        let migration_state = state.migration_service.get_all();
                        migration_state_sender.send(migration_state).ok();
                    }
                    clock.sleep(Duration::seconds(1)).await;
                }
            }
        });

        let block_maker = TestBlockMaker::new();
        let mut current_block = block_maker.block(1);
        let mut pending_transactions = VecDeque::new();
        loop {
            loop {
                match self.txn_receiver.try_recv() {
                    Ok((txn, account_id)) => {
                        pending_transactions.push_back((
                            current_block.height() + self.txn_delay_blocks,
                            txn,
                            account_id,
                        ));
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        return;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        break;
                    }
                }
            }

            let block = current_block.child(current_block.height() + 1);

            let mut transactions_to_process = Vec::new();
            while let Some((height, _, _)) = pending_transactions.front() {
                if *height <= block.height() {
                    let (_, txn, account_id) = pending_transactions.pop_front().unwrap();
                    transactions_to_process.push((txn, account_id));
                } else {
                    break;
                }
            }

            let mut signature_requests = Vec::new();
            loop {
                match self.signature_request_receiver.try_recv() {
                    Ok(request) => {
                        signature_requests.push(request);
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        return;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        break;
                    }
                }
            }

            for signature_request in &signature_requests {
                let mut contract = contract.lock().await;
                let signature_id = signature_request.signature_id;
                contract
                    .pending_signatures
                    .insert(signature_request.request.payload.clone(), signature_id);
            }

            let mut ckd_requests = Vec::new();
            loop {
                match self.ckd_request_receiver.try_recv() {
                    Ok(request) => {
                        ckd_requests.push(request);
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        return;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        break;
                    }
                }
            }

            for ckd_request in &ckd_requests {
                let mut contract = contract.lock().await;
                let ckd_id = ckd_request.ckd_id;
                contract
                    .pending_ckds
                    .insert(ckd_request.request.app_id.clone(), ckd_id);
            }

            let mut block_update = ChainBlockUpdate {
                block: block.to_block_view(),
                signature_requests,
                completed_signatures: Vec::new(),
                ckd_requests,
                completed_ckds: Vec::new(),
            };
            contract.lock().await.env.set_block_height(block.height());
            for (txn, uid) in transactions_to_process {
                let account_id = self
                    .account_id_by_uid
                    .lock()
                    .expect("expected lock")
                    .get(&uid)
                    .unwrap()
                    .clone();
                match txn {
                    ChainSendTransactionRequest::VotePk(vote_pk) => {
                        let mut contract = contract.lock().await;
                        contract.vote_pk(account_id, vote_pk.key_event_id, vote_pk.public_key);
                    }
                    ChainSendTransactionRequest::Respond(respond) => {
                        let mut contract = contract.lock().await;
                        let signature_id =
                            contract.pending_signatures.remove(&respond.request.payload);
                        if let Some(signature_id) = signature_id {
                            self.signature_response_sender
                                .send(respond.clone())
                                .unwrap();
                            block_update.completed_signatures.push(signature_id);
                        } else {
                            tracing::warn!(
                                "Ignoring respond transaction for unknown (possibly already-responded-to) signature: {:?}",
                                respond.request.payload
                            );
                        }
                    }
                    ChainSendTransactionRequest::CKDRespond(respond) => {
                        let mut contract = contract.lock().await;
                        let ckd_id = contract.pending_ckds.remove(&respond.request.app_id);
                        if let Some(ckd_id) = ckd_id {
                            self.ckd_response_sender.send(respond.clone()).unwrap();
                            block_update.completed_ckds.push(ckd_id);
                        } else {
                            tracing::warn!(
                                "Ignoring respond_ckd transaction for unknown (possibly already-responded-to) ckd: {:?}",
                                respond.request.app_id
                            );
                        }
                    }
                    ChainSendTransactionRequest::VoteReshared(reshared) => {
                        let mut contract = contract.lock().await;
                        contract.vote_reshared(account_id, reshared.key_event_id);
                    }
                    ChainSendTransactionRequest::StartKeygen(start) => {
                        // todo: timeout logic in fake indexer?
                        let mut contract = contract.lock().await;
                        contract.vote_start_keygen(account_id, start.key_event_id);
                    }
                    ChainSendTransactionRequest::StartReshare(start) => {
                        let mut contract = contract.lock().await;
                        contract.vote_start_reshare(account_id, start.key_event_id);
                    }
                    ChainSendTransactionRequest::VoteAbortKeyEventInstance(abort) => {
                        let mut contract = contract.lock().await;
                        contract.vote_abort_key_event(account_id, abort.key_event_id);
                    }
                    ChainSendTransactionRequest::VerifyTee() => {}
                    ChainSendTransactionRequest::SubmitParticipantInfo(_participant_info) => {
                        // TODO(#1203): Submitting participant info is not implemented for tests yet.
                    }
                    ChainSendTransactionRequest::ConcludeNodeMigration(conclude_migration_args) => {
                        let mut contract = contract.lock().await;
                        contract.conclude_node_migration(account_id, conclude_migration_args);
                    }
                }
            }
            self.block_update_sender.send(block_update).ok();
            current_block = block;
            tokio::time::sleep(self.block_time).await;
        }
    }
}

/// User-facing object for using the fake indexer for testing.
/// Create one of these for each test, and call `add_indexer_node` for each node.
pub struct FakeIndexerManager {
    /// Sends transactions to the core for processing. This is cloned to each node,
    /// so each node can send transactions (with its AccountId) to the core.
    core_txn_sender: mpsc::UnboundedSender<(ChainSendTransactionRequest, TestNodeUid)>,
    /// Used to call .subscribe() so that each node can receive changes to the
    /// contract state.
    core_state_change_sender: broadcast::Sender<ContractState>,
    /// Used to call .subscribe() so that each node can receive block updates.
    core_block_update_sender: broadcast::Sender<ChainBlockUpdate>,
    /// Used to call .subscribe() so that each node can receive migration change updates
    core_migration_change_sender: broadcast::Sender<ContractMigrationInfo>,
    /// Task that runs the core logic.
    _core_task: AutoAbortTask<()>,

    /// Collects signature responses from the core. When the core processes signature
    /// response transactions, it sends them to this receiver. See `next_response()`.
    signature_response_receiver: mpsc::UnboundedReceiver<ChainSignatureRespondArgs>,
    /// Used to send signature requests to the core.
    signature_request_sender: mpsc::UnboundedSender<SignatureRequestFromChain>,

    /// Collects signature responses from the core. When the core processes signature
    /// response transactions, it sends them to this receiver. See `next_response()`.
    ckd_response_receiver: mpsc::UnboundedReceiver<ChainCKDRespondArgs>,
    /// Used to send signature requests to the core.
    ckd_request_sender: mpsc::UnboundedSender<CKDRequestFromChain>,

    /// Allows nodes to be disabled during tests. See `disable()`.
    node_disabler: HashMap<TestNodeUid, NodeDisabler>,
    /// Allows nodes' indexers to be paused during tests.
    indexer_pauser: HashMap<TestNodeUid, IndexerPauser>,
    /// Allows modification of the contract.
    contract: Arc<tokio::sync::Mutex<FakeMpcContractState>>,

    account_id_by_uid: Arc<std::sync::Mutex<HashMap<TestNodeUid, AccountId>>>,
}

/// Allows a node to be disabled during tests.
struct NodeDisabler {
    disable: Arc<AtomicBool>,
    /// For querying whether the node is running the Invalid job,
    /// indicating it has been disabled.
    currently_running_job_name: Arc<std::sync::Mutex<String>>,
}

/// Allows a node's indexer to be paused.
struct IndexerPauser {
    indexer_suspended: watch::Sender<bool>,
}

/// While holding this, the node remains disabled.
pub struct DisabledNode {
    disable: Arc<AtomicBool>,
    currently_running_job_name: Arc<std::sync::Mutex<String>>,
}

/// While holding this, the node's indexer is paused.
pub struct PausedIndexer {
    indexer_suspended: watch::Sender<bool>,
}

impl DisabledNode {
    pub async fn reenable_and_wait_till_running(self) {
        self.disable
            .store(false, std::sync::atomic::Ordering::Relaxed);
        loop {
            {
                let name = self.currently_running_job_name.lock().unwrap();
                if &*name == "Running" {
                    break;
                }
                tracing::info!(
                    "Waiting for node to be reenabled and running; currently running job: {}",
                    *name
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

impl Drop for DisabledNode {
    fn drop(&mut self) {
        self.disable
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Drop for PausedIndexer {
    fn drop(&mut self) {
        self.indexer_suspended.send(false).unwrap();
    }
}

/// unique identifier for test nodes
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, From, Hash)]
pub struct TestNodeUid(usize);

/// Runs the fake indexer logic for one node.
struct FakeIndexerOneNode {
    /// Internal ID used to uniquely identify this node for tests
    uid: TestNodeUid,

    // The following are counterparts of the core channels.
    core_txn_sender: mpsc::UnboundedSender<(ChainSendTransactionRequest, TestNodeUid)>,
    core_state_change_receiver: broadcast::Receiver<ContractState>,
    core_migration_change_receiver: broadcast::Receiver<ContractMigrationInfo>,
    block_update_receiver: broadcast::Receiver<ChainBlockUpdate>,

    /// Whether the node should yield ContractState::Invalid to artificially simulate bringing the
    /// node down.
    disable: Arc<AtomicBool>,
    /// Whether the indexer shall be suspended.
    indexer_suspended: watch::Receiver<bool>,

    // The following are counterparts of the API channels.
    api_state_sender: watch::Sender<ContractState>,
    api_migration_info_sender: watch::Sender<MigrationInfo>,
    api_block_update_sender: mpsc::UnboundedSender<ChainBlockUpdate>,
    api_txn_receiver: mpsc::Receiver<ChainSendTransactionRequest>,
}

impl FakeIndexerOneNode {
    async fn run(self, account_id: AccountId, p2p_public_key: VerifyingKey) {
        let FakeIndexerOneNode {
            uid,
            core_txn_sender,
            mut core_state_change_receiver,
            mut core_migration_change_receiver,
            mut block_update_receiver,
            disable: shutdown,
            mut indexer_suspended,
            api_state_sender,
            api_migration_info_sender,
            api_block_update_sender,
            mut api_txn_receiver,
            ..
        } = self;
        let shutdown_clone = shutdown.clone();
        let monitor_state_changes = AutoAbortTask::from(tokio::spawn(async move {
            loop {
                let state = core_state_change_receiver.recv().await.unwrap();
                let state = if shutdown_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    ContractState::Invalid
                } else {
                    state
                };

                api_state_sender.send_if_modified(|watched_state| {
                    let state_changed = *watched_state != state;

                    if state_changed {
                        tracing::info!("State changed: {:?}", state);
                        *watched_state = state;
                        true
                    } else {
                        false
                    }
                });
            }
        }));
        let monitor_migration_state_changes = AutoAbortTask::from(tokio::spawn(async move {
            loop {
                let state = core_migration_change_receiver.recv().await.unwrap();
                let state =
                    MigrationInfo::from_contract_state(&account_id, &p2p_public_key, &state);

                api_migration_info_sender.send_if_modified(|watched_state| {
                    let state_changed = *watched_state != state;

                    if state_changed {
                        tracing::info!("State changed: {:?}", state);
                        *watched_state = state;
                        true
                    } else {
                        false
                    }
                });
            }
        }));
        let monitor_requests = AutoAbortTask::from(tokio::spawn(async move {
            loop {
                let request = block_update_receiver.recv().await.unwrap();
                indexer_suspended
                    .wait_for(|suspended| !suspended)
                    .await
                    .unwrap();
                api_block_update_sender.send(request).unwrap();
            }
        }));
        let forward_txn_requests = AutoAbortTask::from(tokio::spawn(async move {
            while let Some(txn) = api_txn_receiver.recv().await {
                core_txn_sender.send((txn, uid)).unwrap();
            }
        }));

        monitor_state_changes.await.unwrap();
        monitor_migration_state_changes.await.unwrap();
        monitor_requests.await.unwrap();
        forward_txn_requests.await.unwrap();
    }
}

impl FakeIndexerManager {
    /// Creates a new fake indexer whose contract state begins with WaitingForSync.
    pub fn new(clock: Clock, txn_delay_blocks: u64, block_time: std::time::Duration) -> Self {
        let (txn_sender, txn_receiver) = mpsc::unbounded_channel();
        let (state_change_sender, _) = broadcast::channel(1000);
        let (block_update_sender, _) = broadcast::channel(1000);
        let (migration_change_sender, _) = broadcast::channel(1000);
        let (signature_request_sender, signature_request_receiver) = mpsc::unbounded_channel();
        let (signature_response_sender, signature_response_receiver) = mpsc::unbounded_channel();
        let (ckd_request_sender, ckd_request_receiver) = mpsc::unbounded_channel();
        let (ckd_response_sender, ckd_response_receiver) = mpsc::unbounded_channel();
        let contract = Arc::new(tokio::sync::Mutex::new(FakeMpcContractState::new()));
        let account_id_by_uid = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let core = FakeIndexerCore {
            clock: clock.clone(),
            txn_delay_blocks,
            signature_request_receiver,
            ckd_request_receiver,
            contract: contract.clone(),
            txn_receiver,
            state_change_sender: state_change_sender.clone(),
            block_update_sender: block_update_sender.clone(),
            migration_change_sender: migration_change_sender.clone(),
            signature_response_sender,
            ckd_response_sender,
            block_time,
            account_id_by_uid: account_id_by_uid.clone(),
        };
        let core_task = AutoAbortTask::from(tokio::spawn(async move { core.run().await }));
        Self {
            core_txn_sender: txn_sender,
            core_state_change_sender: state_change_sender,
            core_block_update_sender: block_update_sender,
            core_migration_change_sender: migration_change_sender,
            _core_task: core_task,
            signature_response_receiver,
            ckd_response_receiver,
            signature_request_sender,
            ckd_request_sender,
            node_disabler: HashMap::new(),
            indexer_pauser: HashMap::new(),
            contract,
            account_id_by_uid,
        }
    }

    /// Waits for the next signature response submitted by any node.
    pub async fn next_response(&mut self) -> ChainSignatureRespondArgs {
        self.signature_response_receiver.recv().await.unwrap()
    }

    /// Waits for the next ckd response submitted by any node.
    pub async fn next_response_ckd(&mut self) -> ChainCKDRespondArgs {
        self.ckd_response_receiver.recv().await.unwrap()
    }

    /// Sends a signature request to the fake blockchain.
    pub fn request_signature(&self, request: SignatureRequestFromChain) {
        self.signature_request_sender.send(request).unwrap();
    }

    /// Sends a ckd request to the fake blockchain.
    pub fn request_ckd(&self, request: CKDRequestFromChain) {
        self.ckd_request_sender.send(request).unwrap();
    }

    /// Adds a new node to the fake indexer. Returns the API for the node, a task that
    /// runs the node's logic, and the running job name to passed to the coordinator.
    pub fn add_indexer_node(
        &mut self,
        uid: TestNodeUid,
        account_id: AccountId,
        p2p_public_key: VerifyingKey,
    ) -> (
        IndexerAPI<MockTransactionSender>,
        AutoAbortTask<()>,
        Arc<std::sync::Mutex<String>>,
    ) {
        let (api_state_sender, api_state_receiver) = watch::channel(ContractState::Invalid);
        let (api_signature_request_sender, api_signature_request_receiver) =
            mpsc::unbounded_channel();
        let (api_txn_sender, api_txn_receiver) = mpsc::channel(1000);
        let (_allowed_docker_images_sender, allowed_docker_images_receiver) =
            watch::channel(vec![]);
        let (_allowed_launcher_compose_sender, allowed_launcher_compose_receiver) =
            watch::channel(vec![]);

        let (my_migration_info_sender, my_migration_info_receiver) =
            watch::channel(MigrationInfo {
                backup_service_info: None,
                active_migration: false,
            });

        let mock_transaction_sender = MockTransactionSender {
            transaction_sender: api_txn_sender,
        };
        let indexer = IndexerAPI {
            contract_state_receiver: api_state_receiver,
            block_update_receiver: Arc::new(tokio::sync::Mutex::new(
                api_signature_request_receiver,
            )),
            txn_sender: mock_transaction_sender,
            allowed_docker_images_receiver,
            allowed_launcher_compose_receiver,
            attested_nodes_receiver: watch::channel(vec![]).1,
            my_migration_info_receiver,
        };

        let currently_running_job_name = Arc::new(std::sync::Mutex::new("".to_string()));
        let disabler = NodeDisabler {
            disable: Arc::new(AtomicBool::new(false)),
            currently_running_job_name: currently_running_job_name.clone(),
        };
        let (indexer_pauser_sender, indexer_pauser_receiver) = watch::channel(false);
        let indexer_pauser = IndexerPauser {
            indexer_suspended: indexer_pauser_sender,
        };
        let one_node = FakeIndexerOneNode {
            uid,
            core_txn_sender: self.core_txn_sender.clone(),
            core_state_change_receiver: self.core_state_change_sender.subscribe(),
            block_update_receiver: self.core_block_update_sender.subscribe(),
            core_migration_change_receiver: self.core_migration_change_sender.subscribe(),

            disable: disabler.disable.clone(),
            indexer_suspended: indexer_pauser_receiver,
            api_state_sender,
            api_block_update_sender: api_signature_request_sender,
            api_txn_receiver,
            api_migration_info_sender: my_migration_info_sender,
        };
        self.node_disabler.insert(uid, disabler);
        self.indexer_pauser.insert(uid, indexer_pauser);
        self.account_id_by_uid
            .lock()
            .expect("require mutex")
            .insert(uid, account_id.clone());
        (
            indexer,
            AutoAbortTask::from(tokio::spawn(one_node.run(account_id, p2p_public_key))),
            currently_running_job_name,
        )
    }

    async fn wait_for_state<T: Clone>(
        mut receiver: tokio::sync::broadcast::Receiver<T>,
        f: impl Fn(&T) -> bool,
        timeout_duration: tokio::time::Duration,
    ) -> anyhow::Result<()> {
        tokio::time::timeout(timeout_duration, async {
            loop {
                let state: T = receiver.recv().await.context("sender was dropped")?;
                if f(&state) {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("Timed out while waiting for contract state")??;
        Ok(())
    }

    pub async fn wait_for_migration_state(
        &mut self,
        f: impl Fn(&ContractMigrationInfo) -> bool,
        timeout_duration: tokio::time::Duration,
    ) -> anyhow::Result<()> {
        let state_change_receiver = self.core_migration_change_sender.subscribe();
        FakeIndexerManager::wait_for_state(state_change_receiver, f, timeout_duration).await
    }

    /// Waits for the contract state to satisfy the given predicate.
    pub async fn wait_for_contract_state(
        &mut self,
        f: impl Fn(&ContractState) -> bool,
        timeout_duration: tokio::time::Duration,
    ) -> anyhow::Result<()> {
        let state_change_receiver = self.core_state_change_sender.subscribe();
        FakeIndexerManager::wait_for_state(state_change_receiver, f, timeout_duration).await
    }

    /// Disables a node, in order to test resilience to node failures.
    pub async fn disable(&self, uid: TestNodeUid) -> DisabledNode {
        let NodeDisabler {
            disable,
            currently_running_job_name,
        } = self.node_disabler.get(&uid).unwrap();
        disable.store(true, std::sync::atomic::Ordering::Relaxed);
        loop {
            {
                let name = currently_running_job_name.lock().unwrap();
                if &*name == "Invalid" {
                    break;
                }
                tracing::info!(
                    "Waiting for node to be disabled; currently running job: {}",
                    *name
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        DisabledNode {
            disable: disable.clone(),
            currently_running_job_name: currently_running_job_name.clone(),
        }
    }

    /// Pauses a node's indexer, in order to test resilience to indexer being stuck.
    pub async fn pause_indexer(&self, uid: TestNodeUid) -> PausedIndexer {
        let indexer_pauser = self.indexer_pauser.get(&uid).unwrap();
        indexer_pauser.indexer_suspended.send(true).unwrap();
        PausedIndexer {
            indexer_suspended: indexer_pauser.indexer_suspended.clone(),
        }
    }

    pub async fn contract_mut(&self) -> tokio::sync::MutexGuard<'_, FakeMpcContractState> {
        self.contract.lock().await
    }
}
