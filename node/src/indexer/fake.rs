use super::handler::ChainSignatureRequest;
use super::participants::{
    ContractInitializingState, ContractResharingState, ContractRunningState, ContractState,
};
use super::response::{ChainRespondArgs, ChainSendTransactionRequest};
use super::IndexerAPI;
use crate::config::ParticipantsConfig;
use crate::tracking::{AutoAbortTask, AutoAbortTaskCollection};
use near_crypto::PublicKey;
use near_sdk::AccountId;
use near_time::{Clock, Duration};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, watch};

/// A simplification of the real MPC contract state for testing.
pub struct FakeMpcContractState {
    pub state: ContractState,
}

impl FakeMpcContractState {
    pub fn new() -> FakeMpcContractState {
        let config = ContractState::WaitingForSync;
        FakeMpcContractState { state: config }
    }

    pub fn initialize(&mut self, participants: ParticipantsConfig) {
        assert_eq!(self.state, ContractState::WaitingForSync);
        let state = ContractState::Initializing(ContractInitializingState {
            participants,
            pk_votes: BTreeMap::new(),
        });
        self.state = state;
    }

    pub fn start_resharing(&mut self, new_participants: ParticipantsConfig) {
        let running_state = match &self.state {
            ContractState::Running(state) => state,
            _ => panic!("Cannot start resharing from non-running state"),
        };
        let state = ContractState::Resharing(ContractResharingState {
            old_epoch: running_state.epoch,
            old_participants: running_state.participants.clone(),
            public_key: running_state.root_public_key.clone(),
            new_participants,
            finished_votes: HashSet::new(),
        });
        self.state = state;
    }

    pub fn vote_pk(&mut self, account_id: AccountId, pk: PublicKey) {
        if let ContractState::Initializing(config) = &mut self.state {
            config.pk_votes.entry(pk).or_default().insert(account_id);
            for (key, voters) in &config.pk_votes {
                if voters.len() >= config.participants.participants.len() {
                    let new_config = ContractState::Running(ContractRunningState {
                        epoch: 0,
                        participants: config.participants.clone(),
                        root_public_key: key.clone(),
                    });
                    self.state = new_config;
                    return;
                }
            }
        } else {
            tracing::warn!(
                "vote_pk transaction ignored because the contract is not in initializing state"
            );
        }
    }

    pub fn vote_reshared(&mut self, account_id: AccountId, new_epoch: u64) {
        if let ContractState::Resharing(config) = &mut self.state {
            assert_eq!(new_epoch, config.old_epoch + 1);
            if !config
                .new_participants
                .participants
                .iter()
                .any(|p| p.near_account_id == account_id)
            {
                panic!(
                    "vote_reshared received from account {} that is not a participant",
                    account_id
                );
            }
            config.finished_votes.insert(account_id);
            if config.finished_votes.len() == config.new_participants.participants.len() {
                let new_config = ContractState::Running(ContractRunningState {
                    epoch: config.old_epoch + 1,
                    participants: config.new_participants.clone(),
                    root_public_key: config.public_key.clone(),
                });
                self.state = new_config;
            }
        } else {
            tracing::warn!(
                "vote_reshared transaction ignored because the contract is not in resharing state"
            );
        }
    }
}

/// Runs the fake indexer's shared state and logic. There's one instance of this per test.
struct FakeIndexerCore {
    clock: Clock,
    /// Delay from when a txn is submitted to when it affects the contract state.
    txn_delay: Duration,
    /// A fake contract state to emulate the real MPC contract but with much less complexity.
    contract: Arc<tokio::sync::Mutex<FakeMpcContractState>>,
    /// Receives transactions sent via the APIs of each node.
    txn_receiver: mpsc::UnboundedReceiver<(ChainSendTransactionRequest, AccountId)>,
    /// Broadcasts the contract state to each node.
    state_change_sender: broadcast::Sender<ContractState>,

    /// When the core receives signature response txns, it processes them by sending them through
    /// this sender. The receiver end of this is in FakeIndexManager to be received by the test
    /// code.
    sign_response_sender: mpsc::UnboundedSender<ChainRespondArgs>,
}

impl FakeIndexerCore {
    pub async fn run(mut self) {
        let mut tasks = AutoAbortTaskCollection::new();
        let contract = self.contract.clone();
        tasks.spawn_with_tokio({
            let contract = contract.clone();
            let clock = self.clock.clone();
            let state_change_sender = self.state_change_sender.clone();
            async move {
                loop {
                    {
                        let state = contract.lock().await;
                        let config = state.state.clone();
                        state_change_sender.send(config).ok();
                    }
                    clock.sleep(Duration::seconds(1)).await;
                }
            }
        });

        loop {
            let txn = self.txn_receiver.recv().await;
            let Some((txn, account_id)) = txn else {
                break;
            };
            let clock = self.clock.clone();
            let txn_delay = self.txn_delay;
            let sign_response_sender = self.sign_response_sender.clone();
            let contract = contract.clone();
            tasks.spawn_with_tokio(async move {
                clock.sleep(txn_delay).await;
                match txn {
                    ChainSendTransactionRequest::VotePk(vote_pk) => {
                        let mut contract = contract.lock().await;
                        contract.vote_pk(account_id, vote_pk.public_key);
                    }
                    ChainSendTransactionRequest::Respond(respond) => {
                        sign_response_sender.send(respond).unwrap();
                    }
                    ChainSendTransactionRequest::VoteReshared(reshared) => {
                        let mut contract = contract.lock().await;
                        contract.vote_reshared(account_id, reshared.epoch);
                    }
                    _ => {
                        panic!("Unexpected txn: {:?}", txn);
                    }
                }
            });
        }
    }
}

/// User-facing object for using the fake indexer for testing.
/// Create one of these for each test, and call `add_indexer_node` for each node.
pub struct FakeIndexerManager {
    /// Sends transactions to the core for processing. This is cloned to each node,
    /// so each node can send transactions (with its AccountId) to the core.
    core_txn_sender: mpsc::UnboundedSender<(ChainSendTransactionRequest, AccountId)>,
    /// Used to call .subscribe() so that each node can receive changes to the
    /// contract state.
    core_state_change_sender: broadcast::Sender<ContractState>,
    /// Task that runs the core logic.
    _core_task: AutoAbortTask<()>,

    /// Collects signature responses from the core. When the core processes signature
    /// response transactions, it sends them to this receiver. See `next_response()`.
    response_receiver: mpsc::UnboundedReceiver<ChainRespondArgs>,
    /// Used to call .subscribe() so that each node can receive signature requests
    /// sent by the core.
    signature_request_sender: broadcast::Sender<ChainSignatureRequest>,

    /// Allows nodes to be disabled during tests. See `disable()`.
    node_disabler: HashMap<AccountId, NodeDisabler>,
    /// Allows modification of the contract.
    contract: Arc<tokio::sync::Mutex<FakeMpcContractState>>,
}

/// Allows a node to be disabled during tests.
struct NodeDisabler {
    disable: Arc<AtomicBool>,
    /// When the node is running it would grab a mutex of the signature receiver
    /// in order to process signatures. So, while the node is disabled, we grab a
    /// lock of this to ensure that the node is indeed not able to process
    /// signatures.
    mutex: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<ChainSignatureRequest>>>,
}

/// While holding this, the node remains disabled.
pub struct DisabledNode {
    disable: Arc<AtomicBool>,
    _guard: tokio::sync::OwnedMutexGuard<mpsc::UnboundedReceiver<ChainSignatureRequest>>,
}

impl Drop for DisabledNode {
    fn drop(&mut self) {
        self.disable
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Runs the fake indexer logic for one node.
struct FakeIndexerOneNode {
    /// Account under which transactions by this node are originated.
    account_id: AccountId,

    // The following are counterparts of the core channels.
    core_txn_sender: mpsc::UnboundedSender<(ChainSendTransactionRequest, AccountId)>,
    core_state_change_receiver: broadcast::Receiver<ContractState>,
    signature_request_receiver: broadcast::Receiver<ChainSignatureRequest>,

    /// Whether the node should yield ContractState::Invalid to artificially simulate bringing the
    /// node down.
    disable: Arc<AtomicBool>,

    // The following are counterparts of the API channels.
    api_state_sender: watch::Sender<ContractState>,
    api_signature_request_sender: mpsc::UnboundedSender<ChainSignatureRequest>,
    api_txn_receiver: mpsc::Receiver<ChainSendTransactionRequest>,
}

impl FakeIndexerOneNode {
    async fn run(self) {
        let FakeIndexerOneNode {
            account_id,
            core_txn_sender,
            mut core_state_change_receiver,
            mut signature_request_receiver,
            disable: shutdown,
            api_state_sender,
            api_signature_request_sender,
            mut api_txn_receiver,
        } = self;
        let monitor_state_changes = AutoAbortTask::from(tokio::spawn(async move {
            let mut last_state = ContractState::WaitingForSync;
            loop {
                let state = core_state_change_receiver.recv().await.unwrap();
                let state = if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    ContractState::Invalid
                } else {
                    state
                };
                if state != last_state {
                    tracing::info!("State changed: {:?}", state);
                    api_state_sender.send(state.clone()).unwrap();
                    last_state = state;
                }
            }
        }));
        let monitor_signature_requests = AutoAbortTask::from(tokio::spawn(async move {
            loop {
                let request = signature_request_receiver.recv().await.unwrap();
                api_signature_request_sender.send(request).unwrap();
            }
        }));
        let forward_txn_requests = AutoAbortTask::from(tokio::spawn(async move {
            while let Some(txn) = api_txn_receiver.recv().await {
                core_txn_sender.send((txn, account_id.clone())).unwrap();
            }
        }));
        monitor_state_changes.await.unwrap();
        monitor_signature_requests.await.unwrap();
        forward_txn_requests.await.unwrap();
    }
}

impl FakeIndexerManager {
    /// Creates a new fake indexer whose contract state begins with WaitingForSync.
    pub fn new(clock: Clock, txn_delay: Duration) -> Self {
        let (txn_sender, txn_receiver) = mpsc::unbounded_channel();
        let (state_change_sender, _) = broadcast::channel(1000);
        let (signature_request_sender, _) = broadcast::channel(1000);
        let (sign_response_sender, response_receiver) = mpsc::unbounded_channel();
        let contract = Arc::new(tokio::sync::Mutex::new(FakeMpcContractState::new()));
        let core = FakeIndexerCore {
            clock: clock.clone(),
            txn_delay,
            contract: contract.clone(),
            txn_receiver,
            state_change_sender: state_change_sender.clone(),
            sign_response_sender,
        };
        let core_task = AutoAbortTask::from(tokio::spawn(async move { core.run().await }));
        Self {
            core_txn_sender: txn_sender,
            core_state_change_sender: state_change_sender,
            _core_task: core_task,
            response_receiver,
            signature_request_sender,
            node_disabler: HashMap::new(),
            contract,
        }
    }

    /// Waits for the next signature response submitted by any node.
    pub async fn next_response(&mut self) -> ChainRespondArgs {
        self.response_receiver.recv().await.unwrap()
    }

    /// Sends a signature request to the fake blockchain.
    pub fn request_signature(&self, request: ChainSignatureRequest) {
        self.signature_request_sender.send(request).ok();
    }

    /// Adds a new node to the fake indexer. Returns the API for the node and a task that
    /// runs the node's logic.
    pub fn add_indexer_node(&mut self, account_id: AccountId) -> (IndexerAPI, AutoAbortTask<()>) {
        let (api_state_sender, api_state_receiver) = watch::channel(ContractState::WaitingForSync);
        let (api_signature_request_sender, api_signature_request_receiver) =
            mpsc::unbounded_channel();
        let (api_txn_sender, api_txn_receiver) = mpsc::channel(1000);
        let indexer = IndexerAPI {
            contract_state_receiver: api_state_receiver,
            sign_request_receiver: Arc::new(tokio::sync::Mutex::new(
                api_signature_request_receiver,
            )),
            txn_sender: api_txn_sender,
        };
        let disabler = NodeDisabler {
            disable: Arc::new(AtomicBool::new(false)),
            mutex: indexer.sign_request_receiver.clone(),
        };
        let one_node = FakeIndexerOneNode {
            account_id: account_id.clone(),
            core_txn_sender: self.core_txn_sender.clone(),
            core_state_change_receiver: self.core_state_change_sender.subscribe(),
            signature_request_receiver: self.signature_request_sender.subscribe(),
            disable: disabler.disable.clone(),
            api_state_sender,
            api_signature_request_sender,
            api_txn_receiver,
        };
        self.node_disabler.insert(account_id, disabler);
        (indexer, AutoAbortTask::from(tokio::spawn(one_node.run())))
    }

    /// Waits for the contract state to satisfy the given predicate.
    pub async fn wait_for_contract_state(&mut self, f: impl Fn(&ContractState) -> bool) {
        let mut state_change_receiver = self.core_state_change_sender.subscribe();
        loop {
            let state = state_change_receiver.recv().await.unwrap();
            if f(&state) {
                break;
            }
        }
    }

    /// Disables a node, in order to test resilience to node failures.
    pub async fn disable(&self, account_id: AccountId) -> DisabledNode {
        let NodeDisabler { disable, mutex } = self.node_disabler.get(&account_id).unwrap();
        disable.store(true, std::sync::atomic::Ordering::Relaxed);
        DisabledNode {
            disable: disable.clone(),
            _guard: mutex.clone().lock_owned().await,
        }
    }

    pub async fn contract_mut(&self) -> tokio::sync::MutexGuard<'_, FakeMpcContractState> {
        self.contract.lock().await
    }
}
