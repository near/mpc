use super::handler::ChainSignatureRequest;
use super::participants::{ConfigFromChain, InitializingConfigFromChain, RunningConfigFromChain};
use super::response::{ChainRespondArgs, ChainSendTransactionRequest};
use super::IndexerAPI;
use crate::config::ParticipantsConfig;
use crate::tracking::{AutoAbortTask, AutoAbortTaskCollection};
use near_crypto::PublicKey;
use near_sdk::AccountId;
use near_time::{Clock, Duration};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, watch};

pub struct FakeMpcContractState {
    pub config: ConfigFromChain,
}

impl FakeMpcContractState {
    pub fn new_initializing(participants: ParticipantsConfig) -> FakeMpcContractState {
        let config = ConfigFromChain::Initializing(InitializingConfigFromChain {
            participants,
            pk_votes: BTreeMap::new(),
        });
        FakeMpcContractState { config }
    }

    // TODO(#43): Add manual transition to resharing state.

    pub fn vote_pk(&mut self, account_id: AccountId, pk: PublicKey) {
        if let ConfigFromChain::Initializing(config) = &mut self.config {
            config.pk_votes.entry(pk).or_default().insert(account_id);
            for (key, voters) in &config.pk_votes {
                if voters.len() >= config.participants.participants.len() {
                    let new_config = ConfigFromChain::Running(RunningConfigFromChain {
                        epoch: 0,
                        participants: config.participants.clone(),
                        root_public_key: key.clone(),
                    });
                    self.config = new_config;
                    return;
                }
            }
        } else {
            tracing::warn!(
                "vote_pk transaction ignored because the contract is not in initializing state"
            );
            return;
        }
    }
}

struct FakeIndexerCore {
    clock: Clock,
    txn_delay: Duration,
    contract: FakeMpcContractState,
    txn_receiver: mpsc::UnboundedReceiver<(ChainSendTransactionRequest, AccountId)>,
    state_change_sender: broadcast::Sender<ConfigFromChain>,

    sign_response_sender: mpsc::UnboundedSender<ChainRespondArgs>,
}

impl FakeIndexerCore {
    pub async fn run(mut self) {
        let mut tasks = AutoAbortTaskCollection::new();
        let contract = Arc::new(tokio::sync::Mutex::new(self.contract));
        tasks.spawn_with_tokio({
            let contract = contract.clone();
            let clock = self.clock.clone();
            let state_change_sender = self.state_change_sender.clone();
            async move {
                loop {
                    {
                        let state = contract.lock().await;
                        let config = state.config.clone();
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
                    _ => {
                        panic!("Unexpected txn: {:?}", txn);
                    }
                }
            });
        }
    }
}

pub struct FakeIndexerManager {
    core_txn_sender: mpsc::UnboundedSender<(ChainSendTransactionRequest, AccountId)>,
    core_state_change_sender: broadcast::Sender<ConfigFromChain>,
    _core_task: AutoAbortTask<()>,

    response_receiver: mpsc::UnboundedReceiver<ChainRespondArgs>,
    signature_request_sender: broadcast::Sender<ChainSignatureRequest>,
}

impl FakeIndexerManager {
    pub async fn next_response(&mut self) -> ChainRespondArgs {
        self.response_receiver.recv().await.unwrap()
    }

    pub fn request_signature(&self, request: ChainSignatureRequest) {
        self.signature_request_sender.send(request).ok();
    }

    pub fn indexer_for_node(&self, account_id: AccountId) -> (IndexerAPI, AutoAbortTask<()>) {
        let (api_state_sender, api_state_receiver) =
            watch::channel(ConfigFromChain::WaitingForSync);
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
        let one_node = FakeIndexerOneNode {
            account_id,
            core_txn_sender: self.core_txn_sender.clone(),
            core_state_change_receiver: self.core_state_change_sender.subscribe(),
            signature_request_receiver: self.signature_request_sender.subscribe(),
            api_state_sender,
            api_signature_request_sender,
            api_txn_receiver,
        };
        (indexer, AutoAbortTask::from(tokio::spawn(one_node.run())))
    }
}

struct FakeIndexerOneNode {
    account_id: AccountId,

    core_txn_sender: mpsc::UnboundedSender<(ChainSendTransactionRequest, AccountId)>,
    core_state_change_receiver: broadcast::Receiver<ConfigFromChain>,
    signature_request_receiver: broadcast::Receiver<ChainSignatureRequest>,

    api_state_sender: watch::Sender<ConfigFromChain>,
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
            api_state_sender,
            api_signature_request_sender,
            mut api_txn_receiver,
        } = self;
        let monitor_state_changes = AutoAbortTask::from(tokio::spawn(async move {
            let mut last_state = ConfigFromChain::WaitingForSync;
            loop {
                let state = core_state_change_receiver.recv().await.unwrap();
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
    pub fn new(clock: Clock, participants: ParticipantsConfig, txn_delay: Duration) -> Self {
        let (txn_sender, txn_receiver) = mpsc::unbounded_channel();
        let (state_change_sender, _) = broadcast::channel(1000);
        let (signature_request_sender, _) = broadcast::channel(1000);
        let (sign_response_sender, response_receiver) = mpsc::unbounded_channel();
        let contract = FakeMpcContractState::new_initializing(participants);
        let core = FakeIndexerCore {
            clock: clock.clone(),
            txn_delay,
            contract,
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
        }
    }
}
