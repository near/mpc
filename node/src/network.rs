use crate::primitives::{MpcMessage, MpcPeerMessage, MpcTaskId, ParticipantId};
use crate::tracking;
use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Abstraction of the networking layer, from the view of one client, the sender side.
/// For a running node, there should be only one such instance that handles all
/// p2p network communication. This is thread safe; it's expected that there would be
/// many references to this object via Arc.
///
/// TODO(#15): Is this the best API?
#[async_trait::async_trait]
pub trait MeshNetworkTransportSender: Send + Sync + 'static {
    /// Returns the participant ID of the current node.
    fn my_participant_id(&self) -> ParticipantId;
    /// Returns the participant IDs of all nodes in the network, including the current node.
    fn all_participant_ids(&self) -> Vec<ParticipantId>;
    /// Sends a message to the specified recipient.
    /// It is not expected to really block. It's only async because messages may be congested.
    /// Returns an error if something serious goes wrong so that the task that expects the
    /// message to be sent has no meaningful way to proceed. Otherwise, just because the
    /// message is sent doesn't guarantee that the recipient will receive it; that is up to
    /// the user of the networking layer to deal with.
    async fn send(&self, recipient_id: ParticipantId, message: MpcMessage) -> anyhow::Result<()>;
    /// Waits until all nodes in the network have been connected to initially.
    async fn wait_for_ready(&self) -> anyhow::Result<()>;
}

/// The receiving side of the networking layer. It is expected that the node will run
/// a loop that calls receive(), and then immediately hand off the message to another
/// tokio task to process it.
#[async_trait::async_trait]
pub trait MeshNetworkTransportReceiver: Send + 'static {
    async fn receive(&mut self) -> anyhow::Result<MpcPeerMessage>;
}

/// Concrete logic for a client based on the networking layer.
/// Manages a collection of MPC tasks so that they can be multiplexed onto the
/// networking layer underneath.
#[derive(Clone)]
pub struct MeshNetworkClient {
    transport_sender: Arc<dyn MeshNetworkTransportSender>,
    senders_for_tasks: Arc<Mutex<HashMap<MpcTaskId, mpsc::Sender<MpcPeerMessage>>>>,
}

impl MeshNetworkClient {
    /// Primary functionality for the MeshNetworkClient: returns a channel for the given
    /// new MPC task. It is expected that the caller is the leader of this MPC task, and that the
    /// way the MPC task IDs are assigned ensures that no two participants would initiate
    /// tasks with the same MPC task ID.
    pub fn new_channel_for_task(&self, task_id: MpcTaskId) -> anyhow::Result<NetworkTaskChannel> {
        tracing::debug!(
            target: "network",
            "[{}] Creating new channel for task {:?}",
            self.my_participant_id(),
            task_id
        );
        match self.sender_for(task_id) {
            SenderOrNewChannel::Existing(_) => anyhow::bail!("Channel already exists"),
            SenderOrNewChannel::NewChannel { channel, .. } => Ok(channel),
        }
    }

    pub fn my_participant_id(&self) -> ParticipantId {
        self.transport_sender.my_participant_id()
    }

    pub fn all_participant_ids(&self) -> Vec<ParticipantId> {
        self.transport_sender.all_participant_ids()
    }

    /// Internal function shared between new_channel_for_task and MeshNetworkClientDriver::run.
    /// Returns an existing sender for the MPC task, or creates a new one if it doesn't exist.
    /// This is used to determine whether an incoming network message belongs to an existing
    /// MPC task, or if it should trigger the creation of a new MPC task that this node passively
    /// participates in.
    fn sender_for(&self, task_id: MpcTaskId) -> SenderOrNewChannel {
        let mut senders_for_tasks = self.senders_for_tasks.lock().unwrap();
        match senders_for_tasks.entry(task_id) {
            Entry::Occupied(entry) => SenderOrNewChannel::Existing(entry.get().clone()),
            Entry::Vacant(entry) => {
                let (sender, receiver) = mpsc::channel(1000);
                entry.insert(sender.clone());
                drop(senders_for_tasks); // release lock

                let senders_for_tasks = self.senders_for_tasks.clone();
                let drop_fn = move || {
                    senders_for_tasks.lock().unwrap().remove(&task_id);
                };

                let transport_sender = self.transport_sender.clone();
                let send_fn: SendFnForTaskChannel = Box::new(move |recipient_id, message| {
                    let transport_sender = transport_sender.clone();
                    async move {
                        transport_sender
                            .send(
                                recipient_id,
                                MpcMessage {
                                    task_id,
                                    data: message,
                                },
                            )
                            .await?;
                        Ok(())
                    }
                    .boxed()
                });

                SenderOrNewChannel::NewChannel {
                    sender,
                    channel: NetworkTaskChannel {
                        task_id,
                        my_participant_id: self.my_participant_id(),
                        sender: send_fn,
                        receiver,
                        drop: Some(Box::new(drop_fn)),
                    },
                }
            }
        }
    }
}

enum SenderOrNewChannel {
    Existing(mpsc::Sender<MpcPeerMessage>),
    NewChannel {
        sender: mpsc::Sender<MpcPeerMessage>,
        channel: NetworkTaskChannel,
    },
}

/// Runs the loop of receiving messages from the transport and dispatching them to the
/// appropriate MPC task channels. Any new MPC tasks that are triggered due to receiving
/// a message for an unknown MPC task would be notified via `new_channel_sender`.
async fn run_receive_messages_loop(
    client: Arc<MeshNetworkClient>,
    mut receiver: Box<dyn MeshNetworkTransportReceiver>,
    new_channel_sender: mpsc::Sender<NetworkTaskChannel>,
) -> anyhow::Result<()> {
    loop {
        let message = receiver.receive().await?;
        let task_id = message.message.task_id;
        let channel = client.sender_for(task_id);
        match channel {
            SenderOrNewChannel::Existing(sender) => {
                // Should we try_send in case the channel is full?
                sender.send(message).await?;
            }
            SenderOrNewChannel::NewChannel { channel, sender } => {
                sender.send(message).await?;
                tracing::debug!(
                    target: "network",
                    "[{}] [Task {:?}] Passively created new channel for task",
                    client.my_participant_id(),
                    task_id
                );
                new_channel_sender.send(channel).await?;
            }
        }
    }
}

/// The main entry point for the networking layer. Spawns a tokio task that runs the message
/// receiving loop, and returns a client that can be used to create new MPC tasks, as well as a
/// receiver for triggering new MPC tasks that the node should passively participate in.
pub fn run_network_client(
    transport_sender: Arc<dyn MeshNetworkTransportSender>,
    transport_receiver: Box<dyn MeshNetworkTransportReceiver>,
) -> (Arc<MeshNetworkClient>, mpsc::Receiver<NetworkTaskChannel>) {
    let client = Arc::new(MeshNetworkClient {
        transport_sender,
        senders_for_tasks: Arc::new(Mutex::new(HashMap::new())),
    });
    let (new_channel_sender, new_channel_receiver) = mpsc::channel(1000);
    tracking::spawn_checked(
        "Network receive message loop",
        run_receive_messages_loop(client.clone(), transport_receiver, new_channel_sender),
    );
    (client, new_channel_receiver)
}

/// Channel for a specific MPC task that allows sending and receiving messages in order to compute
/// the MPC task. There is one such object for each MPC task.
///
/// If the MPC task times out or aborts for any reason, this object must be dropped to ensure
/// proper cleanup of the associated resources.
pub struct NetworkTaskChannel {
    pub task_id: MpcTaskId,
    my_participant_id: ParticipantId, // for debugging
    sender: SendFnForTaskChannel,
    receiver: tokio::sync::mpsc::Receiver<MpcPeerMessage>,
    drop: Option<Box<dyn FnOnce() + Send + Sync>>,
}

type SendFnForTaskChannel =
    Box<dyn Fn(ParticipantId, Vec<u8>) -> BoxFuture<'static, anyhow::Result<()>> + Send + Sync>;

impl Drop for NetworkTaskChannel {
    fn drop(&mut self) {
        if let Some(drop) = self.drop.take() {
            drop();
        }
    }
}

impl NetworkTaskChannel {
    /// Sends a message to another participant in the MPC task.
    /// Returns an error only if there is something seriously wrong with the networking layer so
    /// that there's no meaningful way for the MPC task to proceed.
    ///
    /// This does not guarantee that the message will be received by the recipient. Although the
    /// communication layer uses a persistent QUIC connection, there can be disconnects, node
    /// restarts, etc. and there API does not provide an application-layer acknowledgment or retry
    /// mechanism. The MPC task's implementation shall not assume reliable message passing, and
    /// should instead have an appropriate timeout or retry mechanism.
    ///
    /// Even multiple messages sent to the same recipient may be received in a different order.
    /// However, the messages will be received in whole, i.e. they will never be split or combined.
    ///
    /// The implementation of this function will guarantee that all messages sent are encrypted,
    /// i.e. can only be decrypted by the recipient.
    pub async fn send(&self, recipient_id: ParticipantId, message: Vec<u8>) -> anyhow::Result<()> {
        tracing::debug!(
            target: "network",
            "[{}] [Task {:?}] Sending message to {:?}: {}",
            self.my_participant_id,
            self.task_id,
            recipient_id,
            hex::encode(&message)
        );
        (self.sender)(recipient_id, message).await
    }

    /// Receives a message from another participant in the MPC task.
    ///
    /// If there are multiple messages available, they may be received in arbitrary order, even if
    /// they were sent from the same participant. However, any message that is received will always
    /// be received in whole, exactly as they were sent, never split or combined.
    ///
    /// Returns an error if the networking client is dropped (during node shutdown).
    ///
    /// This future may never resolve if the MPC computation fails to progress (i.e. all clients
    /// decide they need to receive a message before sending one). It is up to the caller to
    /// implement a timeout mechanism.
    pub async fn receive(&mut self) -> anyhow::Result<MpcPeerMessage> {
        let result = self
            .receiver
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Channel closed"));
        tracing::debug!(
            target: "network",
            "[{}] [Task {:?}] Received message: {:?}",
            self.my_participant_id, self.task_id, result
        );
        result
    }
}

#[cfg(test)]
pub mod testing {
    use super::MeshNetworkTransportSender;
    use crate::primitives::{MpcPeerMessage, ParticipantId};
    use crate::tracking;
    use std::collections::HashMap;
    use std::sync::Arc;

    pub struct TestMeshTransport {
        participant_ids: Vec<ParticipantId>,
        senders: HashMap<ParticipantId, tokio::sync::mpsc::UnboundedSender<MpcPeerMessage>>,
    }

    pub struct TestMeshTransportSender {
        transport: Arc<TestMeshTransport>,
        my_participant_id: ParticipantId,
    }

    pub struct TestMeshTransportReceiver {
        receiver: tokio::sync::mpsc::UnboundedReceiver<MpcPeerMessage>,
    }

    #[async_trait::async_trait]
    impl MeshNetworkTransportSender for TestMeshTransportSender {
        fn my_participant_id(&self) -> ParticipantId {
            self.my_participant_id
        }

        fn all_participant_ids(&self) -> Vec<ParticipantId> {
            self.transport.participant_ids.clone()
        }

        async fn send(
            &self,
            recipient_id: ParticipantId,
            message: crate::primitives::MpcMessage,
        ) -> anyhow::Result<()> {
            self.transport
                .senders
                .get(&recipient_id)
                .ok_or_else(|| anyhow::anyhow!("Unknown recipient"))?
                .send(MpcPeerMessage {
                    from: self.my_participant_id,
                    message,
                })?;
            Ok(())
        }

        async fn wait_for_ready(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl super::MeshNetworkTransportReceiver for TestMeshTransportReceiver {
        async fn receive(&mut self) -> anyhow::Result<MpcPeerMessage> {
            self.receiver
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("Channel closed"))
        }
    }

    pub fn new_test_transports(
        participants: Vec<ParticipantId>,
    ) -> Vec<(Arc<TestMeshTransportSender>, Box<TestMeshTransportReceiver>)> {
        let mut sender_by_participant_id = HashMap::new();
        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        for participant_id in &participants {
            let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
            sender_by_participant_id.insert(*participant_id, sender.clone());
            senders.push(sender);
            receivers.push(receiver);
        }

        let transport = Arc::new(TestMeshTransport {
            participant_ids: participants.clone(),
            senders: sender_by_participant_id,
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

    pub async fn run_test_clients<T: 'static + Send, F, FR>(
        num_participants: usize,
        client_runner: F,
    ) -> anyhow::Result<Vec<T>>
    where
        F: Fn(
            Arc<super::MeshNetworkClient>,
            tokio::sync::mpsc::Receiver<super::NetworkTaskChannel>,
        ) -> FR,
        FR: std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
    {
        let participants = (0..num_participants)
            .map(|id| ParticipantId(id as u32))
            .collect::<Vec<_>>();
        let transports = new_test_transports(participants.clone());
        let join_handles = transports
            .into_iter()
            .enumerate()
            .map(|(i, (sender, receiver))| {
                let (client, new_channel_receiver) = super::run_network_client(sender, receiver);
                tracking::spawn(
                    &format!("client {}", i),
                    client_runner(client, new_channel_receiver),
                )
            })
            .collect::<Vec<_>>();
        futures::future::join_all(join_handles)
            .await
            .into_iter()
            .collect::<Result<_, _>>()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::{MeshNetworkClient, NetworkTaskChannel};
    use crate::network::testing::run_test_clients;
    use crate::primitives::{MpcTaskId, ParticipantId};
    use crate::tracking;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use borsh::{BorshDeserialize, BorshSerialize};
    use std::collections::HashSet;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_network_basic() {
        start_root_task_with_periodic_dump(async move {
            run_test_clients(4, run_test_client).await.unwrap();
        })
        .await;
    }

    async fn run_test_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
    ) -> anyhow::Result<()> {
        tracking::spawn("monitor passive channels", async move {
            loop {
                let Some(channel) = channel_receiver.recv().await else {
                    break;
                };
                tracking::spawn_checked(
                    &format!("passive task {:?}", channel.task_id),
                    task_follower(channel),
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
            let channel = client
                .new_channel_for_task(MpcTaskId::Triple(100 * participant_id.0 as u64 + seed))?;
            handles.push(tracking::spawn_checked(
                &format!("task {}", seed),
                task_leader(channel, other_participant_ids.clone(), seed),
            ));

            let expected_total: u64 = other_participant_ids
                .iter()
                .map(|id| {
                    let input = id.0 as u64 + seed;
                    input * input
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

    async fn task_leader(
        mut channel: NetworkTaskChannel,
        participants: Vec<ParticipantId>,
        seed: u64,
    ) -> anyhow::Result<u64> {
        for other_participant_id in &participants {
            channel
                .send(
                    *other_participant_id,
                    borsh::to_vec(&TestTripleMessage {
                        data: other_participant_id.0 as u64 + seed,
                    })
                    .unwrap(),
                )
                .await?;
        }
        let mut total = 0;
        let mut heard_from = HashSet::new();
        for _ in 0..participants.len() {
            let msg = channel.receive().await?;
            assert!(heard_from.insert(msg.from));
            let inner: TestTripleMessage = borsh::from_slice(&msg.message.data)?;
            total += inner.data;
        }
        Ok(total)
    }

    async fn task_follower(mut channel: NetworkTaskChannel) -> anyhow::Result<()> {
        println!("Task follower started: task id: {:?}", channel.task_id);
        match channel.task_id {
            MpcTaskId::Triple(id) => {
                let message = channel.receive().await?;
                assert_eq!(message.message.task_id, MpcTaskId::Triple(id));

                let inner: TestTripleMessage = borsh::from_slice(&message.message.data)?;
                channel
                    .send(
                        message.from,
                        borsh::to_vec(&TestTripleMessage {
                            data: inner.data * inner.data,
                        })
                        .unwrap(),
                    )
                    .await?;

                Ok(())
            }
            _ => unreachable!(),
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    struct TestTripleMessage {
        data: u64,
    }
}
