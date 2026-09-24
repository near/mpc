pub mod computation;
pub mod conn;
pub mod constants;
pub mod handshake;
pub mod indexer_heights;
pub mod wire_format;

use crate::metrics::networking_metrics;
use crate::network::indexer_heights::IndexerHeightTracker;
use crate::network::wire_format::{MpcMessageKind, MpcTaskId};
use crate::primitives::{
    ChannelId, IndexerHeightMessage, MpcMessage, MpcPeerMessage, MpcStartMessage, ParticipantId,
    PeerMessage, UniqueId,
};
use crate::protocol_version::{CURRENT_PROTOCOL_VERSION, NetworkProtocolVersion};
use crate::requests::queue::NetworkAPIForRequests;
use crate::tracking::{self, AutoAbortTask};
use anyhow::Context as _;
use conn::{ConnectionVersion, NodeConnectivityInterface};
use lru::LruCache;
use rand::prelude::IteratorRandom;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::option::Option;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// Abstraction of the networking layer, from the view of one client, the sender side.
/// For a running node, there should be only one such instance that handles all
/// p2p network communication. This is thread safe; it's expected that there would be
/// many references to this object via Arc.
#[async_trait::async_trait]
pub trait MeshNetworkTransportSender: Send + Sync + 'static {
    /// Returns the participant ID of the current node.
    fn my_participant_id(&self) -> ParticipantId;
    /// Returns the participant IDs of all nodes in the network, including the current node.
    fn all_participant_ids(&self) -> Vec<ParticipantId>;
    /// Returns a connectivity interface for the given other participant.
    ///
    /// `participant_id` must be one of [`Self::all_participant_ids`] and not our own; the
    /// implementation only tracks connectivity for those, and may panic for any other id.
    fn connectivity(&self, participant_id: ParticipantId) -> Arc<dyn NodeConnectivityInterface>;
    /// Sends a message to the specified recipient.
    ///
    /// For messages M = [m_0, m_1, m_2, ..., m_n] sent via this method to the same recipient
    /// for which this method returned Ok, it is guaranteed that the recipient will receive
    /// M[0..i] for some 0 <= i <= n.
    ///
    /// The connection_version is used to detect if the connection is broken, in which case
    /// such a guarantee is no longer possible.
    fn send(
        &self,
        recipient_id: ParticipantId,
        message: MpcMessage,
        connection_version: ConnectionVersion,
    ) -> anyhow::Result<()>;
    /// Sends a message to everyone on a best-effort basis about the current height of our indexer.
    fn send_indexer_height(&self, height: IndexerHeightMessage);

    /// Waits for `required_ready_count` number of connections (a freebie is included for the node itself)
    /// to the given `peers` to be bidirectionally established at the same time.
    async fn wait_for_ready(
        &self,
        required_ready_count: usize,
        peers_to_consider: &[ParticipantId],
    ) -> anyhow::Result<()>;
}

/// The receiving side of the networking layer. It is expected that the node will run
/// a loop that calls receive(), and then immediately hand off the message to another
/// tokio task to process it.
#[async_trait::async_trait]
pub trait MeshNetworkTransportReceiver: Send + 'static {
    async fn receive(&mut self) -> anyhow::Result<PeerMessage>;
}

/// Concrete logic for a client based on the networking layer.
/// Manages a collection of MPC tasks so that they can be multiplexed onto the
/// networking layer underneath.
pub struct MeshNetworkClient {
    transport_sender: Arc<dyn MeshNetworkTransportSender>,
    channels: Arc<Mutex<NetworkTaskChannelManager>>,
    indexer_heights: Arc<IndexerHeightTracker>,
    /// Helper data to ensure [`ChannelId`] uniqueness.
    last_id: Arc<Mutex<UniqueId>>,
}

impl NetworkAPIForRequests for MeshNetworkClient {
    fn alive_participants(&self) -> HashSet<ParticipantId> {
        self.all_alive_participant_ids().into_iter().collect()
    }

    fn indexer_heights(&self) -> HashMap<ParticipantId, u64> {
        self.get_indexer_heights()
    }
}

/// Manages currently active channels as well as buffering messages for channels that are waiting
/// for the Start message.
struct NetworkTaskChannelManager {
    senders: HashMap<ChannelId, mpsc::UnboundedSender<MpcPeerMessage>>,
    channels_waiting_for_start: LruCache<ChannelId, IncompleteNetworkTaskChannel>,
}

impl NetworkTaskChannelManager {
    fn new() -> Self {
        Self {
            senders: HashMap::new(),
            channels_waiting_for_start: LruCache::new(LRU_CAPACITY.try_into().unwrap()),
        }
    }
}

const LRU_CAPACITY: usize = 10000;

impl MeshNetworkClient {
    fn new(
        transport_sender: Arc<dyn MeshNetworkTransportSender>,
        channels: Arc<Mutex<NetworkTaskChannelManager>>,
        indexer_heights: Arc<IndexerHeightTracker>,
    ) -> Self {
        let last_id = Arc::new(Mutex::new(UniqueId::generate(
            transport_sender.my_participant_id(),
        )));
        Self {
            transport_sender,
            channels,
            indexer_heights,
            last_id,
        }
    }

    fn generate_unique_channel_id(&self) -> ChannelId {
        let mut last_id = self.last_id.lock().unwrap();
        let new = last_id.pick_new_after();
        *last_id = new;
        ChannelId(new)
    }

    /// Primary functionality for the MeshNetworkClient: returns a channel for the given
    /// new MPC task. It is expected that the caller is the leader of this MPC task.
    /// There may be two tasks with the same [`MpcTaskId`] (e.g. EdDSA retry computation),
    /// but they would have different channel ids.
    pub fn new_channel_for_task(
        &self,
        task_id: impl Into<MpcTaskId>,
        participants: Vec<ParticipantId>,
    ) -> anyhow::Result<NetworkTaskChannel> {
        let task_id: MpcTaskId = task_id.into();
        tracing::debug!(
            target: "network",
            "[{}] Creating new channel for task {:?}",
            self.my_participant_id(),
            task_id
        );
        let channel_id = self.generate_unique_channel_id();
        let start_message = MpcStartMessage {
            task_id,
            participants: participants.clone(),
        };
        let SenderOrNewChannel::NewChannel(channel) =
            self.sender_for(channel_id, Some(&start_message), self.my_participant_id())?
        else {
            anyhow::bail!("Channel already exists");
        };
        for participant in &participants {
            if participant == &self.my_participant_id() {
                continue;
            }
            channel.sender.send_raw(
                *participant,
                MpcMessage {
                    channel_id,
                    kind: MpcMessageKind::Start(start_message.clone()),
                },
            )?;
        }
        Ok(channel)
    }

    pub fn my_participant_id(&self) -> ParticipantId {
        self.transport_sender.my_participant_id()
    }

    pub fn all_participant_ids(&self) -> Vec<ParticipantId> {
        self.transport_sender.all_participant_ids()
    }

    pub fn peer_network_protocol_version(
        &self,
        participant: ParticipantId,
    ) -> Option<NetworkProtocolVersion> {
        if participant == self.my_participant_id() {
            Some(CURRENT_PROTOCOL_VERSION)
        } else {
            self.transport_sender
                .connectivity(participant)
                .peer_network_protocol_version()
        }
    }

    /// Requires a bidirectional connection, but ignores indexer height, so it is still not a full
    /// liveness check: intersect with [`Self::all_alive_participant_ids`] when picking a
    /// participant set.
    // TODO(#4399): drop the attribute, the online-presign leader selects participants with this.
    #[cfg_attr(not(test), expect(dead_code))]
    pub fn participants_supporting(&self, required: NetworkProtocolVersion) -> Vec<ParticipantId> {
        self.all_participant_ids()
            .into_iter()
            .filter(|participant| {
                self.peer_network_protocol_version(*participant)
                    .is_some_and(|version| version.supports(required))
            })
            .collect()
    }

    /// Returns the participant IDs of all nodes in the network that are currently alive.
    /// This is a subset of all_participant_ids, and includes our own participant ID.
    pub fn all_alive_participant_ids(&self) -> Vec<ParticipantId> {
        let mut result = Vec::new();
        let indexer_heights = self.get_indexer_heights();
        let my_height = *indexer_heights.get(&self.my_participant_id()).unwrap_or(&0);
        for participant in self.all_participant_ids() {
            if participant == self.my_participant_id() {
                continue;
            }
            let peer_height = *indexer_heights.get(&participant).unwrap_or(&0);
            if my_height <= peer_height + mpc_node_config::MAX_INDEXER_HEIGHT_DIFF
                && self
                    .transport_sender
                    .connectivity(participant)
                    .is_bidirectionally_connected()
            {
                result.push(participant);
            }
        }
        result.push(self.my_participant_id());
        result.sort();
        result
    }

    pub fn select_random_active_participants_including_me(
        &self,
        total: usize,
        peers_to_consider: &[ParticipantId],
    ) -> anyhow::Result<Vec<ParticipantId>> {
        let me = self.my_participant_id();
        let participants = self.all_alive_participant_ids();
        anyhow::ensure!(
            participants.contains(&me),
            "There's no `me` in active participants"
        );

        let mut res = participants
            .into_iter()
            .filter(|p| {
                let peer_is_not_me = p != &me;
                let peer_is_considered = peers_to_consider.contains(p);
                peer_is_not_me && peer_is_considered
            })
            .choose_multiple(&mut rand::thread_rng(), total - 1);
        res.push(me);

        anyhow::ensure!(
            res.len() == total,
            "Not enough active participants: need {}, got {}",
            total,
            res.len()
        );

        Ok(res)
    }

    /// Returns once all participants in the network are simultaneously connected to us.
    /// Internally, this calls `wait_for_ready(total_num_participants)` on the underlying
    /// `transport_sender`.
    pub async fn leader_wait_for_all_connected(&self) -> anyhow::Result<()> {
        self.transport_sender
            .wait_for_ready(
                self.all_participant_ids().len(),
                &self.all_participant_ids(),
            )
            .await
    }

    /// Internal function to either return a new channel or a sender for the existing channel.
    /// A new channel is created only when the Start message is received for the first time.
    /// Otherwise, returns a Sender that'll send to the existing channel, or, if we receive
    /// a message for a task before its Start message, we'll still return a Sender that will
    /// buffer the messages and deliver them to the channel, once a Start message is received.
    ///
    /// Fails with [`InvalidChannelId`] for a channel id `originator` may not open, or
    /// [`InvalidStartMessage`] for a participant set we cannot join; no channel state is created.
    fn sender_for(
        &self,
        channel_id: ChannelId,
        start: Option<&MpcStartMessage>,
        originator: ParticipantId,
    ) -> anyhow::Result<SenderOrNewChannel> {
        let owner = channel_id.0.participant_id();
        if let Some(start) = start {
            if owner != originator {
                return Err(InvalidChannelId::NotOwnedByOriginator { owner, originator }.into());
            }
            self.validate_start_participants(&start.participants, originator)?;
        }
        // INVARIANT: For each key in the `senders` map, exactly one of the following is true:
        //  - It is in the channels_waiting_for_start LruCache.
        //    - This is maintained when we insert an entry into the LruCache, where if an
        //      entry is evicted, we also remove the corresponding entry from the senders map.
        //  - There is a NetworkTaskChannel object alive for this MpcTaskId.
        //    - This is maintained by the drop_fn we give to NetworkTaskChannel, which is called
        //      when the NetworkTaskChannel is destroyed.
        let mut channels = self.channels.lock().unwrap();
        let sender = match channels.senders.entry(channel_id) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                if owner == self.my_participant_id() && originator != self.my_participant_id() {
                    return Err(InvalidChannelId::NoOpenChannel(channel_id).into());
                }
                let (sender, receiver) = mpsc::unbounded_channel();
                entry.insert(sender.clone());
                let incomplete_channel = IncompleteNetworkTaskChannel { receiver };
                if let Some((k, _)) = channels
                    .channels_waiting_for_start
                    .push(channel_id, incomplete_channel)
                {
                    // If k != task_id, that means the LruCache evicted some other entry.
                    // That means that other channel never received Start and is old enough,
                    // so we also remove it from the senders map. See the above invariant.
                    if k != channel_id {
                        channels.senders.remove(&k);
                    }
                }
                sender
            }
        };
        if let Some(start) = start {
            // Note: It's possible that the channel is NOT in channels_waiting_for_start:
            //  - It's possible the channel was buffered but the Start message arrived way too late.
            //    In this case, we unfortunately never start the channel, but that is OK.
            //  - It's possible that we received Start message twice. That's erroneous, but we'll
            //    just deliver the second Start message to the channel, where the channel handling
            //    code will fail.
            if let Some(incomplete_channel) = channels.channels_waiting_for_start.pop(&channel_id) {
                drop(channels); // release lock
                let drop_fn = {
                    let channels = self.channels.clone();
                    move || {
                        channels.lock().unwrap().senders.remove(&channel_id);
                    }
                };
                let channel = NetworkTaskChannel {
                    sender: Arc::new(NetworkTaskChannelSender {
                        channel_id,
                        task_id: start.task_id,
                        leader: originator,
                        my_participant_id: self.my_participant_id(),
                        participants: start.participants.clone(),
                        connection_versions: start
                            .participants
                            .iter()
                            .filter(|id| **id != self.my_participant_id())
                            .map(|id| {
                                (
                                    *id,
                                    self.transport_sender.connectivity(*id).connection_version(),
                                )
                            })
                            .collect(),
                        transport_sender: self.transport_sender.clone(),
                    }),
                    successful_participants: HashSet::new(),
                    receiver: incomplete_channel.receiver,
                    drop: Some(Box::new(drop_fn)),
                };
                return Ok(SenderOrNewChannel::NewChannel(channel));
            }
        }
        Ok(SenderOrNewChannel::Sender(sender))
    }

    /// Validates the participant set of a Start message, which is chosen by the originator of the
    /// computation and therefore untrusted. The transport layer only knows the local participant
    /// set, so a participant outside it has no connectivity to look up.
    fn validate_start_participants(
        &self,
        participants: &[ParticipantId],
        originator: ParticipantId,
    ) -> Result<(), InvalidStartMessage> {
        let known = self.all_participant_ids();
        let mut unique = HashSet::new();
        for &participant in participants {
            if !known.contains(&participant) {
                return Err(InvalidStartMessage::UnknownParticipant(participant));
            }
            if !unique.insert(participant) {
                return Err(InvalidStartMessage::DuplicateParticipant(participant));
            }
        }
        if !unique.contains(&self.my_participant_id()) {
            return Err(InvalidStartMessage::SelfNotIncluded);
        }
        if !unique.contains(&originator) {
            return Err(InvalidStartMessage::OriginatorNotIncluded(originator));
        }
        Ok(())
    }

    /// Emit network metrics through Prometheus counters
    pub fn emit_metrics(&self) {
        let my_participant_id = self.my_participant_id();
        networking_metrics::NETWORK_LIVE_CONNECTIONS.reset();

        for id in self.all_participant_ids() {
            let metric = networking_metrics::NETWORK_LIVE_CONNECTIONS
                .with_label_values(&[&my_participant_id.to_string(), &id.to_string()]);
            if id == my_participant_id {
                metric.set(1);
            } else {
                let is_live_participant = self
                    .transport_sender
                    .connectivity(id)
                    .is_bidirectionally_connected();
                metric.set(is_live_participant.into());
            }
        }
    }

    pub fn update_indexer_height(&self, height: u64) {
        self.indexer_heights
            .set_height(self.my_participant_id(), height);
        self.transport_sender
            .send_indexer_height(IndexerHeightMessage { height });
    }

    pub fn get_indexer_heights(&self) -> HashMap<ParticipantId, u64> {
        self.indexer_heights.get_heights()
    }
}

struct IncompleteNetworkTaskChannel {
    receiver: mpsc::UnboundedReceiver<MpcPeerMessage>,
}

enum SenderOrNewChannel {
    Sender(mpsc::UnboundedSender<MpcPeerMessage>),
    NewChannel(NetworkTaskChannel),
}

/// Reason why a message may not open channel state under its [`ChannelId`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InvalidChannelId {
    #[error("channel id is owned by {owner}, not by the originator {originator}")]
    NotOwnedByOriginator {
        owner: ParticipantId,
        originator: ParticipantId,
    },
    #[error("no open channel {0:?} under our participant id")]
    NoOpenChannel(ChannelId),
}

/// Reason why the participant set of an [`MpcStartMessage`] was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InvalidStartMessage {
    #[error("participant {0} is not in our participant set")]
    UnknownParticipant(ParticipantId),
    #[error("participant {0} is listed more than once")]
    DuplicateParticipant(ParticipantId),
    #[error("we are not among the participants")]
    SelfNotIncluded,
    #[error("the originator {0} is not among the participants")]
    OriginatorNotIncluded(ParticipantId),
}

async fn run_receive_message(
    client: Arc<MeshNetworkClient>,
    receiver: &mut Box<dyn MeshNetworkTransportReceiver>,
    new_channel_sender: &mpsc::UnboundedSender<NetworkTaskChannel>,
    indexer_heights: Arc<IndexerHeightTracker>,
) -> anyhow::Result<()> {
    let message = receiver.receive().await?;
    match message {
        PeerMessage::Mpc(message) => {
            let from = message.from;
            let channel_id = message.message.channel_id;
            let start_msg = match &message.message.kind {
                MpcMessageKind::Start(start_msg) => Some(start_msg),
                _ => None,
            };
            match client
                .sender_for(channel_id, start_msg, from)
                .with_context(|| format!("Rejecting message from participant {from}"))?
            {
                SenderOrNewChannel::Sender(sender) => {
                    sender.send(message)?;
                }
                SenderOrNewChannel::NewChannel(channel) => {
                    new_channel_sender.send(channel)?;
                }
            }
        }
        PeerMessage::IndexerHeight(message) => {
            indexer_heights.set_height(message.from, message.message.height);
        }
    }
    Ok(())
}

/// Runs the loop of receiving messages from the transport and dispatching them to the
/// appropriate MPC task channels. Any new MPC tasks that are triggered due to receiving
/// a message for an unknown MPC task would be notified via `new_channel_sender`.
async fn run_receive_messages_loop(
    client: Arc<MeshNetworkClient>,
    mut receiver: Box<dyn MeshNetworkTransportReceiver>,
    new_channel_sender: mpsc::UnboundedSender<NetworkTaskChannel>,
    indexer_heights: Arc<IndexerHeightTracker>,
) {
    loop {
        if let Err(err) = run_receive_message(
            client.clone(),
            &mut receiver,
            &new_channel_sender,
            indexer_heights.clone(),
        )
        .await
        {
            tracing::warn!("run_receive_message failed with error: {err:#}");
        }
    }
}

/// The main entry point for the networking layer. Spawns a tokio task that runs the message
/// receiving loop, and returns a client that can be used to create new MPC tasks, as well as a
/// receiver for triggering new MPC tasks that the node should passively participate in.
pub fn run_network_client(
    transport_sender: Arc<dyn MeshNetworkTransportSender>,
    transport_receiver: Box<dyn MeshNetworkTransportReceiver>,
) -> (
    Arc<MeshNetworkClient>,
    mpsc::UnboundedReceiver<NetworkTaskChannel>,
    AutoAbortTask<()>,
) {
    let indexer_heights = Arc::new(IndexerHeightTracker::new(
        &transport_sender.all_participant_ids(),
    ));
    let client = Arc::new(MeshNetworkClient::new(
        transport_sender,
        Arc::new(Mutex::new(NetworkTaskChannelManager::new())),
        indexer_heights.clone(),
    ));
    let (new_channel_sender, new_channel_receiver) = mpsc::unbounded_channel();
    let handle = tracking::spawn(
        "Network receive message loop",
        run_receive_messages_loop(
            client.clone(),
            transport_receiver,
            new_channel_sender,
            indexer_heights,
        ),
    );
    (client, new_channel_receiver, handle)
}

/// Channel for a specific MPC task that allows sending and receiving messages in order to compute
/// the MPC task. There is one such object for each MPC task.
///
/// If the MPC task times out or aborts for any reason, this object must be dropped to ensure
/// proper cleanup of the associated resources.
pub struct NetworkTaskChannel {
    sender: Arc<NetworkTaskChannelSender>,
    /// Used for calling receive(&mut self).
    receiver: mpsc::UnboundedReceiver<MpcPeerMessage>,
    /// The set of participants who sent us a Success message; for leader only.
    successful_participants: HashSet<ParticipantId>,
    /// Function to clean up relevant data structures in the network transport implementation.
    drop: Option<Box<dyn FnOnce() + Send + Sync>>,
}

/// A subset of the NetworkTaskChannel that doesn't include the mutable parts.
pub struct NetworkTaskChannelSender {
    /// Unique channel ID across participants.
    /// It is needed as `task_id` might not be globally unique.
    channel_id: ChannelId,
    /// The task ID associated with the computation.
    task_id: MpcTaskId,
    /// The leader of the computation; there is exactly one leader for each computation.
    leader: ParticipantId,
    /// The participant ID of our node.
    my_participant_id: ParticipantId,
    /// The participant IDs of all participants in the computation, including our own.
    participants: Vec<ParticipantId>,
    /// The version of the connection we have with each other participant.
    /// This is used to detect dropped connections. See ConnectionVersion for details.
    connection_versions: HashMap<ParticipantId, ConnectionVersion>,
    /// The underlying transport layer.
    transport_sender: Arc<dyn MeshNetworkTransportSender>,
}

/// A computation data message received from a participant.
pub struct TaskChannelComputationData {
    pub from: ParticipantId,
    pub data: Vec<Vec<u8>>,
}

impl Drop for NetworkTaskChannel {
    fn drop(&mut self) {
        if let Some(drop) = self.drop.take() {
            drop();
        }
    }
}

impl NetworkTaskChannelSender {
    /// Sends a raw MpcMessage to the participant over the network.
    /// It fails if the connection is not established to the participant, or if the connection is
    /// a different one from the original when the channel was created.
    fn send_raw(&self, recipient_id: ParticipantId, message: MpcMessage) -> anyhow::Result<()> {
        self.transport_sender.send(
            recipient_id,
            message,
            self.connection_versions
                .get(&recipient_id)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("No connection version for recipient"))?,
        )?;
        Ok(())
    }

    /// Sends a message to another participant in the MPC task.
    /// Returns an error only if there is something seriously wrong with the networking layer so
    /// that there's no meaningful way for the MPC task to proceed.
    ///
    /// This does not guarantee that the message will be received by the recipient. However, it
    /// does guarantee that any messages sent via this channel would be received in the same order,
    /// if they would be received at all. This implies that the underlying persistent connection is
    /// reset, future sends will fail as we cannot ensure that previous messages were received.
    ///
    /// The implementation of this function will guarantee that all messages sent are encrypted,
    /// i.e. can only be decrypted by the recipient.
    pub fn send(&self, recipient_id: ParticipantId, data: Vec<Vec<u8>>) -> anyhow::Result<()> {
        self.send_raw(
            recipient_id,
            MpcMessage {
                channel_id: self.channel_id,
                kind: MpcMessageKind::Computation(data),
            },
        )
    }

    pub fn is_leader(&self) -> bool {
        self.my_participant_id == self.leader
    }

    pub fn get_leader(&self) -> ParticipantId {
        self.leader
    }

    /// Waits for each participant involved in this task to be bidirectionally connected to us
    /// at least once. This way, the connection version for each participant is properly established
    /// and when we send messages to any participant we can rely on that connection version.
    /// It is possible after this that some participant is no longer connected to us (with the
    /// original connection), in which case the sending would then fail (due to outdated connection
    /// version) immediately.
    ///
    /// The wait for each participant is bounded by `PARTICIPANT_CONNECTION_WAIT_TIMEOUT`, which
    /// is ishort and independent of the overall computation timeout. This is to prevent further
    /// waiting on the full computation when say the leader is connected to participants,
    /// but some participants are not connected to each other. This will produce a specific
    /// error earlier on in the process.
    ///
    /// This should be called at the beginning of the computation if:
    ///  - This is a leader-centric computation, and we are a follower.
    ///    (Rationale: the leader already determined that the participants are online. We wait
    ///    for connections because even though the leader has connected to everyone, it is
    ///    possible we have yet to establish connections to everyone. We assume that if the
    ///    leader can connect to two nodes B and C, then B and C can also connect to each other.
    ///    If it happens that a node is actually unavailable, then the leader would realize that
    ///    too, and abort the computation.)
    ///
    /// This should NOT be called if:
    ///  - We are the leader. This is redundant because the leader already queried the alive
    ///    participants when making the choice of participants to use in the computation. And in
    ///    fact, if we have the leader also call this, then the leader may get stuck waiting
    ///    forever (and having to rely on timeouts), because just because a participant was alive
    ///    when the leader determines the participant list, doesn't mean that the participant is
    ///    still alive by the time the computation is started. By not calling this at the leader,
    ///    if a participant is disconnected, the leader will be able to abort when carrying out the
    ///    computation.
    async fn initialize_all_participants_connections(&self) -> anyhow::Result<()> {
        for &participant in &self.participants {
            if participant == self.my_participant_id {
                continue;
            }
            tracking::set_progress(&format!("Waiting for connection to {}", participant));
            let connectivity = self.transport_sender.connectivity(participant);
            tokio::time::timeout(
                mpc_node_config::PARTICIPANT_CONNECTION_WAIT_TIMEOUT,
                connectivity.wait_for_connection(self.connection_versions[&participant]),
            )
            .await
            .map_err(|_| {
                tracing::warn!(
                    target: "network",
                    "[{}] [Task {:?}] Not connected to participant {} \
                     after {:?}, cannot continue",
                    self.my_participant_id,
                    self.task_id,
                    participant,
                    mpc_node_config::PARTICIPANT_CONNECTION_WAIT_TIMEOUT,
                );
                anyhow::anyhow!(
                    "Not connected to participant {} after {:?}, cannot continue",
                    participant,
                    mpc_node_config::PARTICIPANT_CONNECTION_WAIT_TIMEOUT,
                )
            })??;
        }
        tracking::set_progress("All participants connected");
        Ok(())
    }

    /// Communicates the success result to the leader of the computation.
    fn communicate_success(&self) -> anyhow::Result<()> {
        if self.is_leader() {
            anyhow::bail!("Only followers can communicate success");
        }
        self.send_raw(
            self.leader,
            MpcMessage {
                channel_id: self.channel_id,
                kind: MpcMessageKind::Success,
            },
        )?;
        Ok(())
    }

    /// Sends an Abort message to other parties in the computation. For leader, this is
    /// communicated to all followers; for a follower, this is communicated only to the leader.
    fn communicate_failure(&self, err: &anyhow::Error) {
        let err_msg = err.to_string();
        if self.is_leader() {
            for participant in &self.participants {
                if participant == &self.my_participant_id {
                    continue;
                }

                tracing::debug!(
                    target: "network",
                    "[{}] [Task {:?}] Sending Abort message to participant {}",
                    self.my_participant_id,
                    self.task_id,
                    participant
                );
                // Don't fail just because we cannot send an abort message.
                let _ = self.send_raw(
                    *participant,
                    MpcMessage {
                        channel_id: self.channel_id,
                        kind: MpcMessageKind::Abort(err_msg.clone()),
                    },
                );
            }
        } else {
            tracing::debug!(
                target: "network",
                "[{}] [Task {:?}] Sending Abort message to leader {}",
                self.my_participant_id,
                self.task_id,
                self.leader
            );
            // Don't fail just because we cannot send an abort message.
            let _ = self.send_raw(
                self.leader,
                MpcMessage {
                    channel_id: self.channel_id,
                    kind: MpcMessageKind::Abort(err_msg),
                },
            );
        }
    }
}

impl NetworkTaskChannel {
    /// Returns a sender to be used to send a message to another participant in the MPC task.
    pub fn sender(&self) -> Arc<NetworkTaskChannelSender> {
        self.sender.clone()
    }

    pub fn task_id(&self) -> MpcTaskId {
        self.sender.task_id
    }

    pub fn participants(&self) -> &[ParticipantId] {
        &self.sender.participants
    }

    pub fn my_participant_id(&self) -> ParticipantId {
        self.sender.my_participant_id
    }

    pub fn leader(&self) -> ParticipantId {
        self.sender.leader
    }

    /// Receives a single MPC message from any participant from the network, without processing it.
    /// This will return error early if any connection is broken.
    async fn receive_raw(&mut self) -> anyhow::Result<MpcPeerMessage> {
        let received = loop {
            let timer = tokio::time::sleep(Duration::from_secs(1));

            tokio::select! {
                _ = timer => {
                    if self.sender.connection_versions.iter().any(|(id, version)| {
                        self.sender.transport_sender.connectivity(*id).was_connection_interrupted(*version)
                    }) {
                        anyhow::bail!("Computation cannot succeed as not all participants are alive anymore");
                    }
                }
                received = self.receiver.recv() => {
                    let Some(received) = received else {
                        anyhow::bail!("Channel closed");
                    };
                    break received;
                }
            }
        };

        tracing::debug!(
            target: "network",
            "[{}] [Task {:?}] Received message: {:?}",
            self.sender.my_participant_id, self.sender.task_id, received
        );
        Ok(received)
    }

    /// Receives one message from the network and process it; that message may or may not be a
    /// computation message.
    ///
    /// A message from outside the channel's participant set is dropped rather than turned into an
    /// error: letting it fail the computation would hand any excluded node the power to abort a
    /// computation (and burn its presignature) with a single message.
    async fn receive_one(&mut self) -> anyhow::Result<Option<TaskChannelComputationData>> {
        let message = self.receive_raw().await?;
        if !self.sender.participants.contains(&message.from) {
            tracing::warn!(
                target: "network",
                "[{}] [Task {:?}] Dropping {} from participant {} (channel {:?}): not in participant set",
                self.sender.my_participant_id,
                self.sender.task_id,
                message.message.kind.variant_name(),
                message.from,
                message.message.channel_id,
            );
            return Ok(None);
        }
        match message.message.kind {
            MpcMessageKind::Computation(data) => {
                return Ok(Some(TaskChannelComputationData {
                    from: message.from,
                    data,
                }));
            }
            MpcMessageKind::Abort(err) => {
                tracing::debug!(
                    target: "network",
                    "[{}] [Task {:?}] Received abort from participant {}: {}",
                    self.sender.my_participant_id,
                    self.sender.task_id,
                    message.from,
                    err
                );
                if self.sender.is_leader() {
                    anyhow::bail!("Aborted by participant {}: {}", message.from, err);
                } else {
                    anyhow::bail!("Aborted by leader: {}", err);
                }
            }
            MpcMessageKind::Success => {
                tracing::debug!(
                    target: "network",
                    "[{}] [Task {:?}] Received success from participant {}",
                    self.sender.my_participant_id,
                    self.sender.task_id,
                    message.from
                );
                if self.sender.is_leader() {
                    self.successful_participants.insert(message.from);
                } else {
                    anyhow::bail!("Received unexpected Success message when we are not the leader");
                }
            }
            MpcMessageKind::Start(mpc_start_message) => {
                // `Self` was created upon receiving `MpcMessageKind::Start`, further we don't expect
                // any `Start` messages.
                anyhow::bail!("Unexpected Start message: {:?}", mpc_start_message);
            }
        }
        Ok(None)
    }

    /// Receives a computation message from another participant.
    /// Blocks until a message is received, but will return early if:
    ///   - Any connection to any participant is broken.
    ///   - The computation is aborted by a follower (if we're the leader) or the leader
    ///     (if we're a follower).
    pub async fn receive(&mut self) -> anyhow::Result<TaskChannelComputationData> {
        loop {
            if let Some(data) = self.receive_one().await? {
                return Ok(data);
            }
        }
    }

    /// The leader may call this to wait for all followers to succeed.
    /// This will return error if any connection is broken, or if any follower ends up
    /// sending the leader an Abort message instead.
    async fn wait_for_followers_to_succeed(&mut self) -> anyhow::Result<()> {
        if !self.sender.is_leader() {
            anyhow::bail!("Only the leader can wait for others to succeed");
        }
        while self.successful_participants.len() < self.sender.participants.len() - 1 {
            tracking::set_progress(&format!(
                "Waiting for followers to succeed: {} out of {}",
                self.successful_participants.len(),
                self.sender.participants.len() - 1
            ));
            let _ = self.receive_one().await?;
        }
        tracking::set_progress("All followers succeeded");
        Ok(())
    }
}

#[cfg(test)]
pub mod testing {
    use super::conn::{ConnectionVersion, NodeConnectivityInterface};
    use super::indexer_heights::IndexerHeightTracker;
    use super::{
        ChannelId, MeshNetworkTransportSender, NetworkTaskChannel, NetworkTaskChannelSender,
    };
    use crate::network::wire_format::MpcTaskId;
    use crate::primitives::{MpcPeerMessage, ParticipantId, PeerMessage, UniqueId};
    use crate::protocol_version::{CURRENT_PROTOCOL_VERSION, NetworkProtocolVersion};
    use crate::tracking;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    pub struct TestMeshTransport {
        participant_ids: Vec<ParticipantId>,
        senders: HashMap<ParticipantId, mpsc::UnboundedSender<PeerMessage>>,
        protocol_versions: HashMap<ParticipantId, NetworkProtocolVersion>,
        // Used to simulate a network partition
        blocked_pairs: HashSet<(ParticipantId, ParticipantId)>,
    }

    impl TestMeshTransport {
        fn is_blocked(&self, a: ParticipantId, b: ParticipantId) -> bool {
            self.blocked_pairs.contains(&(a, b)) || self.blocked_pairs.contains(&(b, a))
        }
    }

    /// Every participant reported to run the current protocol version.
    pub fn current_protocol_versions(
        participants: &[ParticipantId],
    ) -> HashMap<ParticipantId, NetworkProtocolVersion> {
        participants
            .iter()
            .map(|participant| (*participant, CURRENT_PROTOCOL_VERSION))
            .collect()
    }

    pub struct TestMeshTransportSender {
        transport: Arc<TestMeshTransport>,
        my_participant_id: ParticipantId,
    }

    pub struct TestMeshTransportReceiver {
        receiver: mpsc::UnboundedReceiver<PeerMessage>,
    }

    pub struct TestConnectivityInterface {
        connected: bool,
        protocol_version: Option<NetworkProtocolVersion>,
    }

    #[async_trait::async_trait]
    impl NodeConnectivityInterface for TestConnectivityInterface {
        fn connection_version(&self) -> ConnectionVersion {
            ConnectionVersion::default()
        }
        fn peer_network_protocol_version(&self) -> Option<NetworkProtocolVersion> {
            self.protocol_version
        }

        fn was_connection_interrupted(&self, _connection_version: ConnectionVersion) -> bool {
            false
        }

        async fn wait_for_connection(
            &self,
            _connection_version: ConnectionVersion,
        ) -> anyhow::Result<()> {
            if self.connected {
                Ok(())
            } else {
                std::future::pending().await
            }
        }

        fn is_bidirectionally_connected(&self) -> bool {
            self.connected
        }
    }

    #[async_trait::async_trait]
    impl MeshNetworkTransportSender for TestMeshTransportSender {
        fn my_participant_id(&self) -> ParticipantId {
            self.my_participant_id
        }

        fn all_participant_ids(&self) -> Vec<ParticipantId> {
            self.transport.participant_ids.clone()
        }

        fn connectivity(
            &self,
            participant_id: ParticipantId,
        ) -> Arc<dyn NodeConnectivityInterface> {
            Arc::new(TestConnectivityInterface {
                connected: !self
                    .transport
                    .is_blocked(self.my_participant_id, participant_id),
                protocol_version: self
                    .transport
                    .protocol_versions
                    .get(&participant_id)
                    .copied(),
            })
        }

        fn send(
            &self,
            recipient_id: ParticipantId,
            message: crate::primitives::MpcMessage,
            _connection_version: ConnectionVersion,
        ) -> anyhow::Result<()> {
            anyhow::ensure!(
                !self
                    .transport
                    .is_blocked(self.my_participant_id, recipient_id),
                "no connection to {} (blocked in test partition)",
                recipient_id
            );
            self.transport
                .senders
                .get(&recipient_id)
                .ok_or_else(|| anyhow::anyhow!("Unknown recipient"))?
                .send(PeerMessage::Mpc(MpcPeerMessage {
                    from: self.my_participant_id,
                    message,
                }))?;
            Ok(())
        }

        // TODO(#2753): add test coverage
        fn send_indexer_height(&self, _height: crate::primitives::IndexerHeightMessage) {}

        async fn wait_for_ready(
            &self,
            _required_ready_count: usize,
            _peers_to_consider: &[ParticipantId],
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl super::MeshNetworkTransportReceiver for TestMeshTransportReceiver {
        async fn receive(&mut self) -> anyhow::Result<PeerMessage> {
            self.receiver
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("Channel closed"))
        }
    }

    pub fn new_test_transports(
        participants: Vec<ParticipantId>,
    ) -> Vec<(Arc<TestMeshTransportSender>, Box<TestMeshTransportReceiver>)> {
        new_test_transports_with_partition(participants, &[])
    }

    pub fn new_test_transports_with_partition(
        participants: Vec<ParticipantId>,
        blocked_pairs: &[(ParticipantId, ParticipantId)],
    ) -> Vec<(Arc<TestMeshTransportSender>, Box<TestMeshTransportReceiver>)> {
        let mut sender_by_participant_id = HashMap::new();
        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        for participant_id in &participants {
            let (sender, receiver) = mpsc::unbounded_channel();
            sender_by_participant_id.insert(*participant_id, sender.clone());
            senders.push(sender);
            receivers.push(receiver);
        }

        let transport = Arc::new(TestMeshTransport {
            participant_ids: participants.clone(),
            senders: sender_by_participant_id,
            blocked_pairs: blocked_pairs.iter().copied().collect(),
            protocol_versions: current_protocol_versions(&participants),
        });

        let mut transports = Vec::new();
        for (i, receiver) in receivers.into_iter().enumerate() {
            let participant_id = participants[i];
            let transport = transport.clone();
            let sender = Arc::new(TestMeshTransportSender {
                transport,
                my_participant_id: participant_id,
            });
            let receiver = Box::new(TestMeshTransportReceiver { receiver });
            transports.push((sender, receiver));
        }

        transports
    }

    /// Synchronous [`MeshNetworkClient`] for unit tests. All participants are reported alive
    /// and on the current protocol version.
    pub fn new_test_client(
        participants: Vec<ParticipantId>,
        my_participant_id: ParticipantId,
    ) -> Arc<super::MeshNetworkClient> {
        let protocol_versions = current_protocol_versions(&participants);
        new_test_client_with_versions(participants, my_participant_id, protocol_versions)
    }

    /// Like [`new_test_client`], with the protocol version each peer is reported to run.
    pub fn new_test_client_with_versions(
        participants: Vec<ParticipantId>,
        my_participant_id: ParticipantId,
        protocol_versions: HashMap<ParticipantId, NetworkProtocolVersion>,
    ) -> Arc<super::MeshNetworkClient> {
        let transport = Arc::new(TestMeshTransportSender {
            transport: Arc::new(TestMeshTransport {
                participant_ids: participants.clone(),
                senders: HashMap::new(),
                protocol_versions,
                blocked_pairs: HashSet::new(),
            }),
            my_participant_id,
        });
        let channels = Arc::new(std::sync::Mutex::new(
            super::NetworkTaskChannelManager::new(),
        ));
        let indexer_heights = Arc::new(IndexerHeightTracker::new(&participants));
        Arc::new(super::MeshNetworkClient::new(
            transport,
            channels,
            indexer_heights,
        ))
    }

    /// Builds a channel over the given participant set, returning the raw inbound sender so
    /// tests can inject arbitrary [`MpcPeerMessage`]s, including ones from outside the set.
    pub fn new_task_channel_for_test(
        task_id: MpcTaskId,
        leader: ParticipantId,
        my_participant_id: ParticipantId,
        participants: Vec<ParticipantId>,
    ) -> (NetworkTaskChannel, mpsc::UnboundedSender<MpcPeerMessage>) {
        let (raw_sender, receiver) = mpsc::unbounded_channel();
        let transport = Arc::new(TestMeshTransport {
            participant_ids: participants.clone(),
            senders: HashMap::new(),
            blocked_pairs: HashSet::new(),
            protocol_versions: current_protocol_versions(&participants),
        });
        let transport_sender = Arc::new(TestMeshTransportSender {
            transport,
            my_participant_id,
        });
        let connection_versions = participants
            .iter()
            .filter(|id| **id != my_participant_id)
            .map(|id| (*id, transport_sender.connectivity(*id).connection_version()))
            .collect();
        let channel = NetworkTaskChannel {
            sender: Arc::new(NetworkTaskChannelSender {
                channel_id: ChannelId(UniqueId::generate(leader)),
                task_id,
                leader,
                my_participant_id,
                participants,
                connection_versions,
                transport_sender,
            }),
            successful_participants: HashSet::new(),
            receiver,
            drop: None,
        };
        (channel, raw_sender)
    }

    pub async fn run_test_clients<T: 'static + Send, F, FR>(
        participants: Vec<ParticipantId>,
        client_runner: F,
    ) -> anyhow::Result<Vec<T>>
    where
        F: Fn(Arc<super::MeshNetworkClient>, mpsc::UnboundedReceiver<NetworkTaskChannel>) -> FR,
        FR: Future<Output = anyhow::Result<T>> + Send + 'static,
    {
        run_test_clients_with_partition(participants, &[], client_runner).await
    }

    pub async fn run_test_clients_with_partition<T: 'static + Send, F, FR>(
        participants: Vec<ParticipantId>,
        blocked_pairs: &[(ParticipantId, ParticipantId)],
        client_runner: F,
    ) -> anyhow::Result<Vec<T>>
    where
        F: Fn(Arc<super::MeshNetworkClient>, mpsc::UnboundedReceiver<NetworkTaskChannel>) -> FR,
        FR: Future<Output = anyhow::Result<T>> + Send + 'static,
    {
        let transports = new_test_transports_with_partition(participants.clone(), blocked_pairs);
        let join_handles = transports
            .into_iter()
            .enumerate()
            .map(|(i, (sender, receiver))| {
                let (client, new_channel_receiver, task) =
                    super::run_network_client(sender, receiver);
                let client_runner_future = client_runner(client, new_channel_receiver);
                tracking::spawn(&format!("client {}", i), async move {
                    let _task = task;
                    client_runner_future.await
                })
            })
            .collect::<Vec<_>>();
        futures::future::join_all(join_handles)
            .await
            .into_iter()
            .collect::<Result<_, _>>()?
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::computation::MpcLeaderCentricComputation;
    use super::conn::ConnectionVersion;
    use super::{
        InvalidChannelId, InvalidStartMessage, MeshNetworkClient, MeshNetworkTransportReceiver,
        MeshNetworkTransportSender, NetworkTaskChannel, NetworkTaskChannelManager,
        run_receive_message,
    };
    use crate::network::indexer_heights::IndexerHeightTracker;
    use crate::network::testing::{
        TestMeshTransportSender, new_test_client_with_versions, new_test_transports,
        run_test_clients,
    };
    use crate::network::wire_format::{EcdsaTaskId, MpcMessageKind, MpcTaskId};
    use crate::primitives::{ChannelId, MpcMessage, MpcStartMessage, ParticipantId, UniqueId};
    use crate::protocol_version::NetworkProtocolVersion;
    use crate::tests::into_participant_ids;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use crate::tracking::{self, AutoAbortTaskCollection};
    use borsh::{BorshDeserialize, BorshSerialize};
    use rstest::rstest;
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use threshold_signatures::test_utils::generate_participants;
    use tokio::sync::mpsc;

    /// Just some big prime number
    static MOD: u64 = 1_000_000_007;

    #[tokio::test]
    async fn participants_supporting__should_include_self_and_peers_at_or_above_version() {
        // Given
        let me = ParticipantId::from_raw(1);
        let peers = [2, 3, 4].map(ParticipantId::from_raw);
        let participants = vec![me, peers[0], peers[1], peers[2]];
        let versions = HashMap::from([
            (peers[0], NetworkProtocolVersion::Jan2026),
            (peers[1], NetworkProtocolVersion::Dec2025),
        ]);
        let client = new_test_client_with_versions(participants, me, versions);

        // When
        let supporting = client.participants_supporting(NetworkProtocolVersion::Jan2026);

        // Then
        assert_eq!(supporting, vec![me, peers[0]]);
    }

    #[tokio::test]
    async fn test_network_basic() {
        start_root_task_with_periodic_dump(async move {
            run_test_clients(
                into_participant_ids(&generate_participants(4)),
                run_test_client,
            )
            .await
            .unwrap();
        })
        .await;
    }

    async fn run_test_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
    ) -> anyhow::Result<()> {
        let _passive_handle = tracking::spawn("monitor passive channels", async move {
            let mut tasks = AutoAbortTaskCollection::new();
            loop {
                let Some(channel) = channel_receiver.recv().await else {
                    break;
                };
                tasks.spawn_checked(
                    &format!("passive task {:?}", channel.task_id()),
                    TaskFollower.perform_leader_centric_computation(
                        channel,
                        std::time::Duration::from_secs(10),
                    ),
                );
            }
        });

        let participant_id = client.my_participant_id();
        let other_participant_ids = client
            .all_participant_ids()
            .into_iter()
            .filter(|id| id != &participant_id)
            .collect::<Vec<_>>();

        let mut handles = Vec::new();
        let mut expected_results = Vec::new();
        for seed in 0..5 {
            let channel = client.new_channel_for_task(
                EcdsaTaskId::ManyTriples {
                    start: UniqueId::new(participant_id, seed, 0),
                    count: 1,
                },
                client.all_participant_ids(),
            )?;
            handles.push(tracking::spawn(
                &format!("task {}", seed),
                TaskLeader { seed }.perform_leader_centric_computation(
                    channel,
                    std::time::Duration::from_secs(10),
                ),
            ));

            let expected_total: u64 = other_participant_ids
                .iter()
                .map(|id| {
                    let input = id.raw() as u64 + seed;
                    (input * input) % MOD
                })
                .sum();
            expected_results.push(expected_total);
        }
        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await??);
        }
        println!("Results: {:?}", results);
        assert_eq!(results, expected_results);

        Ok(())
    }

    struct TaskLeader {
        seed: u64,
    }

    #[async_trait::async_trait]
    impl MpcLeaderCentricComputation<u64> for TaskLeader {
        async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<u64> {
            for other_participant_id in channel.participants() {
                if other_participant_id == &channel.my_participant_id() {
                    continue;
                }
                channel.sender().send(
                    *other_participant_id,
                    vec![
                        borsh::to_vec(&TestTripleMessage {
                            data: other_participant_id.raw() as u64 + self.seed,
                        })
                        .unwrap(),
                    ],
                )?;
            }
            let mut total = 0;
            let mut heard_from = HashSet::new();
            for _ in 1..channel.participants().len() {
                let msg = channel.receive().await?;
                assert!(heard_from.insert(msg.from));
                let inner: TestTripleMessage = borsh::from_slice(&msg.data[0])?;
                total += inner.data;
            }
            Ok(total)
        }

        fn leader_waits_for_success(&self) -> bool {
            true
        }
    }

    struct TaskFollower;

    #[async_trait::async_trait]
    impl MpcLeaderCentricComputation<()> for TaskFollower {
        async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
            match channel.task_id() {
                MpcTaskId::EcdsaTaskId(EcdsaTaskId::ManyTriples { .. }) => {
                    let msg = channel.receive().await?;
                    let inner: TestTripleMessage = borsh::from_slice(&msg.data[0])?;
                    channel.sender().send(
                        msg.from,
                        vec![
                            borsh::to_vec(&TestTripleMessage {
                                data: (inner.data * inner.data) % MOD,
                            })
                            .unwrap(),
                        ],
                    )?;
                }
                _ => unreachable!(),
            }
            Ok(())
        }

        fn leader_waits_for_success(&self) -> bool {
            true
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    struct TestTripleMessage {
        data: u64,
    }

    #[test]
    fn select_random_active_participants_including_me_should_return_not_enough_active_participants_when_peers_to_consider_is_empty()
     {
        let num_participants = 4;
        let participant_ids = into_participant_ids(&generate_participants(num_participants));
        let transports = new_test_transports(participant_ids.clone());
        let indexer_heights = {
            let heights = participant_ids
                .iter()
                .map(|id| (*id, AtomicU64::new(0)))
                .collect::<HashMap<_, _>>();
            Arc::new(IndexerHeightTracker { heights })
        };
        let channels = Arc::new(Mutex::new(NetworkTaskChannelManager::new()));
        let mesh_network_client = MeshNetworkClient::new(
            transports[0].0.clone(),
            channels.clone(),
            indexer_heights.clone(),
        );

        let err = mesh_network_client
            .select_random_active_participants_including_me(num_participants, &[])
            .unwrap_err();

        let err_msg = err.to_string();
        assert!(
            err_msg.starts_with("Not enough active participants"),
            "unexpected error message: {}",
            err_msg
        );
    }

    #[rstest]
    #[case::unknown_participant(
        vec![ME, ORIGINATOR, ParticipantId::from_raw(42)],
        InvalidStartMessage::UnknownParticipant(ParticipantId::from_raw(42))
    )]
    #[case::duplicate_participant(
        vec![ME, ORIGINATOR, ORIGINATOR],
        InvalidStartMessage::DuplicateParticipant(ORIGINATOR)
    )]
    #[case::without_us(vec![ORIGINATOR, THIRD_PARTY], InvalidStartMessage::SelfNotIncluded)]
    #[case::empty(vec![], InvalidStartMessage::SelfNotIncluded)]
    #[case::without_the_originator(
        vec![ME, THIRD_PARTY],
        InvalidStartMessage::OriginatorNotIncluded(ORIGINATOR)
    )]
    #[tokio::test]
    async fn run_receive_message__should_reject_start_message_with_invalid_participant_set(
        #[case] start_participants: Vec<ParticipantId>,
        #[case] expected_error: InvalidStartMessage,
    ) {
        // Given
        let start_message = start_message_with(start_participants);

        // When
        let (result, new_channel) = receive_message_from_originator(start_message).await;

        // Then
        let error = result.expect_err("the Start message should be rejected");
        assert_eq!(
            error.downcast_ref::<InvalidStartMessage>(),
            Some(&expected_error)
        );
        assert!(new_channel.is_none());
    }

    #[tokio::test]
    async fn run_receive_message__should_create_channel_for_start_message_with_known_participants()
    {
        // Given
        let start_message = start_message_with(vec![ME, ORIGINATOR]);

        // When
        let (result, new_channel) = receive_message_from_originator(start_message).await;

        // Then
        result.unwrap();
        let channel = new_channel.expect("a channel should have been created");
        assert_eq!(channel.participants(), [ME, ORIGINATOR].as_slice());
        assert_eq!(channel.sender().get_leader(), ORIGINATOR);
    }

    #[tokio::test]
    async fn network_task_channel__should_ignore_buffered_message_from_non_participant() {
        // Given
        let mut node = ReceivingNode::new();
        let channel_id = ChannelId(UniqueId::new(ORIGINATOR, 1, 0));
        node.receive(THIRD_PARTY, computation_message(channel_id, 1))
            .await
            .unwrap();
        node.receive(ORIGINATOR, start_message_with(vec![ME, ORIGINATOR]))
            .await
            .unwrap();
        let mut channel = node
            .new_channel()
            .expect("a channel should have been created");
        node.receive(ORIGINATOR, computation_message(channel_id, 2))
            .await
            .unwrap();

        // When
        let received = tokio::time::timeout(Duration::from_secs(5), channel.receive())
            .await
            .expect("the buffered out-of-set message must not stall the channel")
            .expect("the buffered out-of-set message must not abort the channel");

        // Then
        assert_eq!(received.from, ORIGINATOR);
        assert_eq!(received.data, vec![vec![2u8]]);
    }

    #[rstest]
    #[case::owned_by_a_third_party(THIRD_PARTY)]
    #[case::owned_by_us(ME)]
    #[tokio::test]
    async fn run_receive_message__should_reject_start_message_for_a_channel_id_the_originator_does_not_own(
        #[case] owner: ParticipantId,
    ) {
        // Given
        let start_message = MpcMessage {
            channel_id: ChannelId(UniqueId::new(owner, 1, 0)),
            ..start_message_with(vec![ME, ORIGINATOR])
        };
        let mut node = ReceivingNode::new();

        // When
        let result = node.receive(ORIGINATOR, start_message).await;

        // Then
        let error = result.expect_err("the Start message should be rejected");
        assert_eq!(
            error.downcast_ref::<InvalidChannelId>(),
            Some(&InvalidChannelId::NotOwnedByOriginator {
                owner,
                originator: ORIGINATOR,
            })
        );
        assert!(node.new_channel().is_none());
        assert!(node.channel_ids_in_use().is_empty());
    }

    #[tokio::test]
    async fn run_receive_message__should_reject_message_for_a_channel_id_we_own_but_never_opened() {
        // Given
        let mut node = ReceivingNode::new();
        let ours = ChannelId(UniqueId::new(ME, 1, 0));

        // When
        let result = node.receive(ORIGINATOR, computation_message(ours, 1)).await;

        // Then
        let error = result.expect_err("the message should be rejected");
        assert_eq!(
            error.downcast_ref::<InvalidChannelId>(),
            Some(&InvalidChannelId::NoOpenChannel(ours))
        );
        assert!(node.channel_ids_in_use().is_empty());
    }

    #[tokio::test]
    async fn network_task_channel__should_deliver_message_buffered_before_the_start_message() {
        // Given
        let mut node = ReceivingNode::new();
        let channel_id = ChannelId(UniqueId::new(ORIGINATOR, 1, 0));
        node.receive(THIRD_PARTY, computation_message(channel_id, 1))
            .await
            .unwrap();
        node.receive(
            ORIGINATOR,
            start_message_with(vec![ME, ORIGINATOR, THIRD_PARTY]),
        )
        .await
        .unwrap();
        let mut channel = node
            .new_channel()
            .expect("a channel should have been created");

        // When
        let received = tokio::time::timeout(Duration::from_secs(5), channel.receive())
            .await
            .expect("the buffered message must not stall the channel")
            .expect("the buffered message must not abort the channel");

        // Then
        assert_eq!(received.from, THIRD_PARTY);
        assert_eq!(received.data, vec![vec![1u8]]);
    }

    const ME: ParticipantId = ParticipantId::from_raw(0);
    const ORIGINATOR: ParticipantId = ParticipantId::from_raw(1);
    const THIRD_PARTY: ParticipantId = ParticipantId::from_raw(2);

    fn start_of(leader: ParticipantId, participants: Vec<ParticipantId>) -> MpcStartMessage {
        MpcStartMessage {
            task_id: MpcTaskId::EcdsaTaskId(EcdsaTaskId::ManyTriples {
                start: UniqueId::new(leader, 1, 0),
                count: 1,
            }),
            participants,
        }
    }

    fn start_message_with(participants: Vec<ParticipantId>) -> MpcMessage {
        MpcMessage {
            channel_id: ChannelId(UniqueId::new(ORIGINATOR, 1, 0)),
            kind: MpcMessageKind::Start(start_of(ORIGINATOR, participants)),
        }
    }

    fn computation_message(channel_id: ChannelId, payload: u8) -> MpcMessage {
        MpcMessage {
            channel_id,
            kind: MpcMessageKind::Computation(vec![vec![payload]]),
        }
    }

    async fn receive_message_from_originator(
        message: MpcMessage,
    ) -> (anyhow::Result<()>, Option<NetworkTaskChannel>) {
        let mut node = ReceivingNode::new();
        let result = node.receive(ORIGINATOR, message).await;
        (result, node.new_channel())
    }

    /// The inbound message handling of the node `ME`, whose participant set is `ME`, `ORIGINATOR`
    /// and `THIRD_PARTY`.
    struct ReceivingNode {
        client: Arc<MeshNetworkClient>,
        my_receiver: Box<dyn MeshNetworkTransportReceiver>,
        peer_senders: HashMap<ParticipantId, Arc<TestMeshTransportSender>>,
        indexer_heights: Arc<IndexerHeightTracker>,
        new_channel_sender: mpsc::UnboundedSender<NetworkTaskChannel>,
        new_channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
    }

    impl ReceivingNode {
        fn new() -> Self {
            let participants = vec![ME, ORIGINATOR, THIRD_PARTY];
            let mut transports = new_test_transports(participants.clone());
            let (my_transport_sender, my_receiver) = transports.remove(0);
            let indexer_heights = Arc::new(IndexerHeightTracker::new(&participants));
            let client = Arc::new(MeshNetworkClient::new(
                my_transport_sender,
                Arc::new(Mutex::new(NetworkTaskChannelManager::new())),
                indexer_heights.clone(),
            ));
            let (new_channel_sender, new_channel_receiver) = mpsc::unbounded_channel();
            Self {
                client,
                my_receiver,
                peer_senders: [ORIGINATOR, THIRD_PARTY]
                    .into_iter()
                    .zip(transports.into_iter().map(|(sender, _)| sender))
                    .collect(),
                indexer_heights,
                new_channel_sender,
                new_channel_receiver,
            }
        }

        async fn receive(
            &mut self,
            from: ParticipantId,
            message: MpcMessage,
        ) -> anyhow::Result<()> {
            self.peer_senders[&from]
                .send(ME, message, ConnectionVersion::default())
                .unwrap();
            run_receive_message(
                self.client.clone(),
                &mut self.my_receiver,
                &self.new_channel_sender,
                self.indexer_heights.clone(),
            )
            .await
        }

        fn new_channel(&mut self) -> Option<NetworkTaskChannel> {
            self.new_channel_receiver.try_recv().ok()
        }

        fn channel_ids_in_use(&self) -> Vec<ChannelId> {
            self.client
                .channels
                .lock()
                .unwrap()
                .senders
                .keys()
                .copied()
                .collect()
        }
    }
}

#[cfg(test)]
mod participant_connection_wait_tests {
    use super::conn::{ConnectionVersion, NodeConnectivityInterface};
    use super::{ChannelId, MeshNetworkTransportSender, NetworkTaskChannelSender};
    use crate::network::wire_format::{EcdsaTaskId, MpcTaskId};
    use crate::primitives::{IndexerHeightMessage, MpcMessage, ParticipantId, UniqueId};
    use crate::protocol_version::{CURRENT_PROTOCOL_VERSION, NetworkProtocolVersion};
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// A connectivity mock, returns immediately if `connected` is true,
    /// and otherwise never resolves.
    struct MockConnectivity {
        connected: bool,
        protocol_version: Option<NetworkProtocolVersion>,
    }

    #[async_trait::async_trait]
    impl NodeConnectivityInterface for MockConnectivity {
        fn connection_version(&self) -> ConnectionVersion {
            ConnectionVersion::default()
        }
        fn was_connection_interrupted(&self, _version: ConnectionVersion) -> bool {
            false
        }
        async fn wait_for_connection(&self, _version: ConnectionVersion) -> anyhow::Result<()> {
            if self.connected {
                Ok(())
            } else {
                std::future::pending().await
            }
        }
        fn is_bidirectionally_connected(&self) -> bool {
            self.connected
        }

        fn peer_network_protocol_version(&self) -> Option<NetworkProtocolVersion> {
            self.protocol_version
        }
    }

    struct MockTransportSender {
        my_participant_id: ParticipantId,
        all_participant_ids: Vec<ParticipantId>,
        unreachable_participant_id: ParticipantId,
    }

    #[async_trait::async_trait]
    impl MeshNetworkTransportSender for MockTransportSender {
        fn my_participant_id(&self) -> ParticipantId {
            self.my_participant_id
        }
        fn all_participant_ids(&self) -> Vec<ParticipantId> {
            self.all_participant_ids.clone()
        }
        fn connectivity(
            &self,
            participant_id: ParticipantId,
        ) -> Arc<dyn NodeConnectivityInterface> {
            Arc::new(MockConnectivity {
                connected: participant_id != self.unreachable_participant_id,
                protocol_version: Some(CURRENT_PROTOCOL_VERSION),
            })
        }
        fn send(
            &self,
            _recipient_id: ParticipantId,
            _message: MpcMessage,
            _connection_version: ConnectionVersion,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        fn send_indexer_height(&self, _height: IndexerHeightMessage) {}
        async fn wait_for_ready(
            &self,
            _required_ready_count: usize,
            _peers_to_consider: &[ParticipantId],
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }
    #[tokio::test(start_paused = true)]
    async fn rejects_quickly_when_a_participant_is_unreachable() {
        let me = ParticipantId::from_raw(0);
        let leader = ParticipantId::from_raw(1);
        let unreachable = ParticipantId::from_raw(2);
        let participants = vec![me, leader, unreachable];

        let transport_sender = Arc::new(MockTransportSender {
            my_participant_id: me,
            all_participant_ids: participants.clone(),
            unreachable_participant_id: unreachable,
        });

        let connection_versions: HashMap<ParticipantId, ConnectionVersion> = participants
            .iter()
            .filter(|&&p| p != me)
            .map(|&p| (p, transport_sender.connectivity(p).connection_version()))
            .collect();

        let sender = NetworkTaskChannelSender {
            channel_id: ChannelId(UniqueId::new(me, 0, 0)),
            task_id: MpcTaskId::EcdsaTaskId(EcdsaTaskId::ManyTriples {
                start: UniqueId::new(me, 0, 0),
                count: 1,
            }),
            leader,
            my_participant_id: me,
            participants,
            connection_versions,
            transport_sender,
        };

        let (start, result) = start_root_task_with_periodic_dump(async move {
            let start = tokio::time::Instant::now();
            let result = sender.initialize_all_participants_connections().await;
            (start, result)
        })
        .await;
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains(&format!("Not connected to participant {}", unreachable)),
            "Not connected to participant {}",
            err
        );
        assert_eq!(
            start.elapsed(),
            mpc_node_config::PARTICIPANT_CONNECTION_WAIT_TIMEOUT,
            "reject at PARTICIPANT_CONNECTION_WAIT_TIMEOUT, instead of computation timeout"
        );
    }
}

#[cfg(test)]
mod fault_handling_tests {
    use super::computation::MpcLeaderCentricComputation;
    use super::{MeshNetworkClient, NetworkTaskChannel};
    use crate::network::testing::run_test_clients;
    use crate::network::wire_format::EcdsaTaskId;
    use crate::primitives::{ParticipantId, UniqueId};
    use crate::tests::into_participant_ids;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use std::sync::Arc;
    use threshold_signatures::test_utils::generate_participants;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    #[test_log::test]
    async fn test_network_fault_handling() {
        let test_cases = vec![
            FaultTestCase::NoFault,
            FaultTestCase::Crash(ParticipantId::from_raw(0)),
            FaultTestCase::Crash(ParticipantId::from_raw(2)),
            FaultTestCase::Slow(ParticipantId::from_raw(0), CancellationToken::new()),
            FaultTestCase::Slow(ParticipantId::from_raw(3), CancellationToken::new()),
            FaultTestCase::SlowNoWaitSuccess(ParticipantId::from_raw(1), CancellationToken::new()),
            FaultTestCase::Timeout(ParticipantId::from_raw(0)),
            FaultTestCase::Timeout(ParticipantId::from_raw(3)),
            FaultTestCase::AllTimeout,
        ];
        for test_case in test_cases {
            tracing::info!("Running test case: {:?}", test_case);
            let test_case = Arc::new(test_case);
            start_root_task_with_periodic_dump(async move {
                run_test_clients(
                    into_participant_ids(&generate_participants(4)),
                    move |client, channel_receiver| {
                        let test_case = test_case.clone();
                        async move {
                            run_fault_handling_test_client(client, channel_receiver, test_case)
                                .await
                        }
                    },
                )
                .await
                .unwrap();
            })
            .await;
        }
    }

    #[derive(Debug)]
    enum FaultTestCase {
        /// All parties succeed.
        NoFault,
        /// One party crashes.
        Crash(ParticipantId),
        /// One party is slow in the computation.
        Slow(ParticipantId, CancellationToken),
        /// One party is slow, but the leader does not wait for successes.
        SlowNoWaitSuccess(ParticipantId, CancellationToken),
        /// One party times out before the others (contrived case).
        Timeout(ParticipantId),
        /// All parties time out at the same time.
        AllTimeout,
    }

    async fn run_fault_handling_test_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
        test_case: Arc<FaultTestCase>,
    ) -> anyhow::Result<()> {
        let me = client.my_participant_id();

        let is_leader = client.my_participant_id().raw() == 0;
        let channel = if is_leader {
            client.new_channel_for_task(
                EcdsaTaskId::ManyTriples {
                    start: UniqueId::new(me, 0, 0),
                    count: 1,
                },
                client.all_participant_ids(),
            )?
        } else {
            channel_receiver.recv().await.unwrap()
        };

        let timeout = match test_case.as_ref() {
            FaultTestCase::Timeout(participant_id) if me == *participant_id => {
                std::time::Duration::from_secs(1)
            }
            FaultTestCase::AllTimeout => std::time::Duration::from_secs(1),
            _ => std::time::Duration::from_secs(10),
        };
        let result = Task {
            test_case: test_case.clone(),
        }
        .perform_leader_centric_computation(channel, timeout)
        .await;

        match test_case.as_ref() {
            FaultTestCase::NoFault => {
                result.expect("No-fault case should complete successfully");
            }
            FaultTestCase::Crash(participant_id) => {
                let err_string = result
                    .expect_err("Crash case should return an error")
                    .to_string();
                assert!(err_string.contains("Crashed"), "{}", err_string);
                if participant_id == &client.my_participant_id() {
                } else if me.raw() == 0 {
                    assert!(
                        err_string.contains(&format!("Aborted by participant {}", participant_id)),
                        "{}",
                        err_string
                    );
                } else {
                    assert!(err_string.contains("Aborted by leader"), "{}", err_string);
                }
            }
            FaultTestCase::Slow(participant_id, cancellation_token) => {
                result.expect("Slow case should still complete successfully");
                if is_leader || *participant_id == client.my_participant_id() {
                    assert!(cancellation_token.is_cancelled());
                } else {
                    assert!(!cancellation_token.is_cancelled());
                }
            }
            FaultTestCase::SlowNoWaitSuccess(participant_id, cancellation_token) => {
                result.expect("SlowNoWaitSuccess should complete successfully");
                if *participant_id == client.my_participant_id() {
                    assert!(cancellation_token.is_cancelled());
                } else {
                    assert!(!cancellation_token.is_cancelled());
                }
            }
            FaultTestCase::Timeout(participant_id) => {
                let err_string = result
                    .expect_err("Timeout case should return an error")
                    .to_string();
                assert!(err_string.contains("Timeout"), "{}", err_string);
                if participant_id == &client.my_participant_id() {
                } else if me.raw() == 0 {
                    assert!(
                        err_string.contains(&format!("Aborted by participant {}", participant_id)),
                        "{}",
                        err_string
                    );
                } else {
                    assert!(err_string.contains("Aborted by leader"), "{}", err_string);
                }
            }
            FaultTestCase::AllTimeout => {
                let err_string = result
                    .expect_err("AllTimeout case should return an error")
                    .to_string();
                assert!(err_string.contains("Timeout"), "{}", err_string);
            }
        }
        Ok(())
    }

    async fn send_recv_all(channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
        let participants = channel.participants();
        for participant in participants {
            if participant == &channel.my_participant_id() {
                continue;
            }
            channel.sender().send(*participant, vec![vec![]])?;
        }
        for _ in 1..participants.len() {
            channel.receive().await?;
        }
        Ok(())
    }

    struct Task {
        test_case: Arc<FaultTestCase>,
    }

    #[async_trait::async_trait]
    impl MpcLeaderCentricComputation<()> for Task {
        async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
            match self.test_case.as_ref() {
                FaultTestCase::NoFault => {
                    send_recv_all(channel).await?;
                }
                FaultTestCase::Crash(participant_id) => {
                    if channel.my_participant_id() == *participant_id {
                        anyhow::bail!("Crashed");
                    } else {
                        send_recv_all(channel).await?;
                    }
                }
                FaultTestCase::Slow(participant_id, cancellation_token)
                | FaultTestCase::SlowNoWaitSuccess(participant_id, cancellation_token) => {
                    send_recv_all(channel).await?;
                    if channel.my_participant_id() == *participant_id {
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        cancellation_token.cancel();
                    }
                }
                FaultTestCase::Timeout(participant_id) => {
                    if channel.my_participant_id() == *participant_id {
                        // This will timeout (the timeout is set at 1 sec).
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                        // Shouldn't be reached.
                        send_recv_all(channel).await?;
                    } else {
                        send_recv_all(channel).await?;
                    }
                }
                FaultTestCase::AllTimeout => {
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                }
            }
            Ok(())
        }

        fn leader_waits_for_success(&self) -> bool {
            !matches!(
                self.test_case.as_ref(),
                FaultTestCase::SlowNoWaitSuccess(_, _)
            )
        }
    }
}

#[cfg(test)]
mod partition_fault_handling_tests {
    use super::computation::MpcLeaderCentricComputation;
    use super::{MeshNetworkClient, NetworkTaskChannel};
    use crate::network::testing::run_test_clients_with_partition;
    use crate::network::wire_format::EcdsaTaskId;
    use crate::primitives::UniqueId;
    use crate::tests::into_participant_ids;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use std::sync::Arc;
    use std::time::Duration;
    use threshold_signatures::test_utils::generate_participants;
    use tokio::sync::mpsc;

    const COMPUTATION_TIMEOUT: Duration = Duration::from_secs(10);
    const FAST_FAILURE_BOUND: Duration = Duration::from_secs(5);

    struct NoOpLeader;
    struct NoOpFollower;

    #[async_trait::async_trait]
    impl MpcLeaderCentricComputation<()> for NoOpLeader {
        async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
            channel.receive().await?;
            Ok(())
        }
        fn leader_waits_for_success(&self) -> bool {
            false
        }
    }

    #[async_trait::async_trait]
    impl MpcLeaderCentricComputation<()> for NoOpFollower {
        async fn compute(self, _channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
            unreachable!("follower should reject before reaching compute()")
        }
        fn leader_waits_for_success(&self) -> bool {
            false
        }
    }

    async fn run_partition_test_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
    ) -> anyhow::Result<()> {
        let me = client.my_participant_id();
        let is_leader = me.raw() == 0;
        let channel = if is_leader {
            client.new_channel_for_task(
                EcdsaTaskId::ManyTriples {
                    start: UniqueId::new(me, 0, 0),
                    count: 1,
                },
                client.all_participant_ids(),
            )?
        } else {
            channel_receiver.recv().await.unwrap()
        };
        let start = tokio::time::Instant::now();
        let result = if is_leader {
            NoOpLeader
                .perform_leader_centric_computation(channel, COMPUTATION_TIMEOUT)
                .await
        } else {
            NoOpFollower
                .perform_leader_centric_computation(channel, COMPUTATION_TIMEOUT)
                .await
        };
        let elapsed = start.elapsed();
        assert!(
            elapsed < FAST_FAILURE_BOUND,
            "[{}] took {:?} to fail, expected well under the {:?} computation timeout",
            me,
            elapsed,
            COMPUTATION_TIMEOUT,
        );
        let err_string = result.unwrap_err().to_string();
        if is_leader {
            assert!(
                err_string.contains("Aborted by participant"),
                "[{}] expected to receive failure, got: {}",
                me,
                err_string
            );
        } else {
            let other_follower = client
                .all_participant_ids()
                .into_iter()
                .find(|&p| p != me && p.raw() != 0)
                .unwrap();
            assert!(
                err_string.contains("Not connected to participant")
                    && err_string.contains(&other_follower.to_string()),
                "[{}] the unreachable peer {}, got: {}",
                me,
                other_follower,
                err_string
            );
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn leader_learns_quickly_when_two_followers_cannot_reach_each_other() {
        let participants = into_participant_ids(&generate_participants(3));
        let a = *participants.iter().find(|p| p.raw() == 1).unwrap();
        let b = *participants.iter().find(|p| p.raw() == 2).unwrap();
        start_root_task_with_periodic_dump(async move {
            // Assertions are evaluated within the task
            run_test_clients_with_partition(participants, &[(a, b)], run_partition_test_client)
                .await
                .unwrap();
        })
        .await;
    }
}
