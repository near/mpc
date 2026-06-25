use crate::primitives::{BatchedMessages, ParticipantId};
use crate::tracking;
use crate::{network::NetworkTaskChannel, tracking::TaskHandle};
use futures::TryFutureExt;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, atomic::AtomicUsize};
use threshold_signatures::protocol::{Action, Protocol};
use tokio::sync::mpsc;

/// Runs any cait-sith protocol, returning the result. Exports tracking progress
/// describing how many messages are sent and received to each participant.
pub async fn run_protocol<T>(
    name: &'static str,
    channel: &mut NetworkTaskChannel,
    mut protocol: impl Protocol<Output = T>,
) -> anyhow::Result<T> {
    let counters = Arc::new(MessageCounters::new(
        name.to_string(),
        channel.participants(),
    ));
    let mut queue_senders: HashMap<ParticipantId, mpsc::UnboundedSender<BatchedMessages>> =
        HashMap::new();
    let mut queue_receivers: HashMap<ParticipantId, mpsc::UnboundedReceiver<BatchedMessages>> =
        HashMap::new();

    for p in channel.participants() {
        let (send, recv) = mpsc::unbounded_channel();
        queue_senders.insert(*p, send);
        queue_receivers.insert(*p, recv);
    }

    // We split the protocol into two tasks: one dedicated to sending messages, and one dedicated
    // to computation and receiving messages. There are two reasons for this:
    //  - If we just used a loop to poke the protocol, and send messages whenever the protocol asks
    //    us to, then we can run into a situation where the protocol is asking us to send 1000
    //    messages to participant 1, but because of bandwidth limitations, the sending blocks on
    //    waiting for enough outgoing buffer to hold the messages. Even though the protocol, at this
    //    moment, may have more messages to send to other participants, we don't get a chance to
    //    send any of that until we've sent all 1000 messages to participant 1. This is very
    //    inefficient, so instead we put messages into queues, indexed by the recipient, and have
    //    a parallel task for each recipient that sends the messages.
    //  - We need the sending task to be a separate spawn from the computation task because while
    //    we're computing, we would not be able to cooperatively run any other tasks (computation
    //    only yields at the protocol's explicit yield points), and that can unnecessarily block
    //    sending. It is OK to have the receiving side blocked by computation, because on the
    //    receiving side, the network channel already provides us with a buffer dedicated to our
    //    task.
    let sending_handle = {
        let counters = counters.clone();
        let sender = channel.sender();
        tracking::spawn_checked("message senders for all participants", async move {
            // One future for each recipient. For the same recipient it is OK to send messages
            // serially, but for multiple recipients we want them to not block each other.
            // These futures are IO-bound, so we don't have to spawn them separately.
            let futures = queue_receivers
                .into_iter()
                .map(move |(participant_id, mut receiver)| {
                    let sender = sender.clone();
                    let counters = counters.clone();
                    async move {
                        while let Some(messages) = receiver.recv().await {
                            let num_messages = messages.len();
                            sender.send(participant_id, messages)?;
                            counters.sent(participant_id, num_messages);
                        }
                        anyhow::Ok(())
                    }
                });
            futures::future::try_join_all(futures).await?;
            anyhow::Ok(())
        })
        .map_err(anyhow::Error::from)
    };

    let participants = channel.participants().to_vec();
    let my_participant_id = channel.my_participant_id();
    let computation_handle = async move {
        /// How a poke burst ended, deciding what to do after flushing messages.
        enum PokeOutcome<T> {
            Wait,
            Yield,
            Return(T),
        }

        loop {
            let mut messages_to_send: HashMap<ParticipantId, _> = HashMap::new();
            let outcome = loop {
                match protocol.poke()? {
                    Action::Wait => break PokeOutcome::Wait,
                    // Flush the accumulated messages before yielding, so peers can make
                    // progress while we give other tasks a chance to run.
                    Action::Yield => break PokeOutcome::Yield,
                    Action::SendMany(vec) => {
                        for participant in &participants {
                            if participant == &my_participant_id {
                                continue;
                            }
                            messages_to_send
                                .entry(*participant)
                                .or_insert(Vec::new())
                                .push(vec.clone());
                        }
                    }
                    Action::SendPrivate(participant, vec) => {
                        messages_to_send
                            .entry(From::from(participant))
                            .or_insert(Vec::new())
                            .push(vec.clone());
                    }
                    Action::Return(result) => {
                        // Warning: we cannot return immediately!! There may be some important
                        // messages to send to others to enable others to complete their computation.
                        break PokeOutcome::Return(result);
                    }
                }
            };

            // Batch-send the messages. This is a useful optimization as cait-sith tends to ask us
            // to send many messages at once to the same recipient.
            // TODO(#2752): reduce message count upstream (https://github.com/Near-One/cait-sith/issues/4)
            for (p, messages) in messages_to_send {
                if messages.is_empty() {
                    continue;
                }
                counters.queue_send(p, messages.len());
                // There's a chance this sending can fail, because the sending task can return early
                // if the connection to some other participant is broken. In that case, the
                // computation task should also just fail.
                queue_senders.get(&p).unwrap().send(messages)?;
            }

            match outcome {
                PokeOutcome::Return(result) => return anyhow::Ok(result),
                // Unlike the Wait arm below, don't block on channel.receive(): the protocol
                // said it can keep poking without a new message.
                PokeOutcome::Yield => tokio::task::yield_now().await,
                PokeOutcome::Wait => {
                    counters.set_receiving();

                    let msg = channel.receive().await?;
                    counters.received(msg.from, msg.data.len());

                    for one_msg in msg.data {
                        protocol.message(msg.from.into(), one_msg)?;
                    }
                }
            }
        }
    };
    let (computation_result, _) = futures::try_join!(computation_handle, sending_handle)?;
    Ok(computation_result)
}

/// Debugging counters to be used to export progress for tracking::set_progress, while
/// the computation is happening.
struct MessageCounters {
    name: String,
    task: Arc<TaskHandle>,
    counters: BTreeMap<ParticipantId, PerParticipantCounters>,
    current_action: AtomicUsize, // 1 = receiving, 0 = computing
}

struct PerParticipantCounters {
    sent: AtomicUsize,
    in_flight: AtomicUsize,
    received: AtomicUsize,
}

impl MessageCounters {
    pub fn new(name: String, participants: &[ParticipantId]) -> Self {
        Self {
            name,
            task: tracking::current_task(),
            counters: participants
                .iter()
                .map(|p| {
                    (
                        *p,
                        PerParticipantCounters {
                            sent: AtomicUsize::new(0),
                            in_flight: AtomicUsize::new(0),
                            received: AtomicUsize::new(0),
                        },
                    )
                })
                .collect(),
            current_action: AtomicUsize::new(0),
        }
    }

    pub fn queue_send(&self, participant: ParticipantId, num_messages: usize) {
        let Some(counters) = self.counters.get(&participant) else {
            self.warn_unknown_participant(participant);
            return;
        };
        counters
            .in_flight
            .fetch_add(num_messages, std::sync::atomic::Ordering::Relaxed);
        self.report_progress();
    }

    pub fn sent(&self, participant: ParticipantId, num_messages: usize) {
        let Some(counters) = self.counters.get(&participant) else {
            self.warn_unknown_participant(participant);
            return;
        };
        counters
            .sent
            .fetch_add(num_messages, std::sync::atomic::Ordering::Relaxed);
        counters
            .in_flight
            .fetch_sub(num_messages, std::sync::atomic::Ordering::Relaxed);
        self.report_progress();
    }

    pub fn received(&self, participant: ParticipantId, num_messages: usize) {
        if let Some(counters) = self.counters.get(&participant) {
            counters
                .received
                .fetch_add(num_messages, std::sync::atomic::Ordering::Relaxed);
        } else {
            self.warn_unknown_participant(participant);
        }
        self.current_action
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Counters are keyed by the task's participant set, so a missing participant is unexpected.
    fn warn_unknown_participant(&self, participant: ParticipantId) {
        tracing::warn!(
            target: "network",
            "[{}] counter update for participant {} not in participant set",
            self.name,
            participant,
        );
    }

    pub fn set_receiving(&self) {
        self.current_action
            .store(1, std::sync::atomic::Ordering::Relaxed);
        self.report_progress();
    }

    fn report_progress(&self) {
        self.task.set_progress(&format!(
            "{}: parties: {:?}, sent {:?} (inflight [{:?}]), received [{:?}] ({})",
            self.name,
            self.counters.keys().collect::<Vec<_>>(),
            self.counters
                .values()
                .map(|c| c.sent.load(std::sync::atomic::Ordering::Relaxed))
                .collect::<Vec<_>>(),
            self.counters
                .values()
                .map(|c| c.in_flight.load(std::sync::atomic::Ordering::Relaxed))
                .collect::<Vec<_>>(),
            self.counters
                .values()
                .map(|c| c.received.load(std::sync::atomic::Ordering::Relaxed))
                .collect::<Vec<_>>(),
            if self
                .current_action
                .load(std::sync::atomic::Ordering::Relaxed)
                == 1
            {
                "receiving"
            } else {
                "computing"
            },
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::{MessageCounters, run_protocol};
    use crate::network::testing::{new_task_channel_for_test, run_test_clients};
    use crate::network::{MeshNetworkClient, NetworkTaskChannel, ParticipantNotInChannelError};
    use crate::primitives::{ChannelId, MpcMessage, MpcMessageKind, MpcPeerMessage, UniqueId};
    use crate::providers::ecdsa::EcdsaTaskId;
    use crate::tests::into_participant_ids;
    use crate::tracking;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::time::Duration;
    use threshold_signatures::errors::{MessageError, ProtocolError};
    use threshold_signatures::participants::Participant;
    use threshold_signatures::protocol::{Action, MessageData, Protocol};
    use threshold_signatures::test_utils::generate_participants;
    use tokio::sync::mpsc;

    /// Protocol stub that replays a fixed sequence of actions.
    struct ScriptedProtocol {
        script: VecDeque<Action<u32>>,
    }

    impl Protocol for ScriptedProtocol {
        type Output = u32;

        fn poke(&mut self) -> Result<Action<u32>, ProtocolError> {
            Ok(self.script.pop_front().unwrap_or(Action::Wait))
        }

        fn message(&mut self, _from: Participant, _data: MessageData) -> Result<(), MessageError> {
            Ok(())
        }
    }

    /// The leader's protocol yields twice and then returns without ever needing
    /// a message; `run_protocol` must keep poking after `Action::Yield` to let it
    /// complete. If a yield were treated like a wait, the leader would hang.
    #[test_log::test(tokio::test)]
    #[expect(non_snake_case)]
    async fn run_protocol__should_keep_poking_after_yield() {
        tracking::testing::start_root_task_with_periodic_dump(async {
            // Given
            let participants = into_participant_ids(&generate_participants(2));

            // When
            let results = run_test_clients(participants, run_one_client)
                .await
                .unwrap();

            // Then
            assert!(results.contains(&Some(42)));
        })
        .await;
    }

    /// A `Computation` from outside the participant set must error, not crash the node.
    #[test_log::test(tokio::test)]
    #[expect(non_snake_case)]
    async fn run_protocol__should_reject_computation_from_non_participant() {
        tracking::testing::start_root_task_with_periodic_dump(async {
            // Given
            let ids = into_participant_ids(&generate_participants(3));
            let participants = vec![ids[0], ids[1]];
            let outsider = ids[2];
            let task_id = EcdsaTaskId::ManyTriples {
                start: UniqueId::new(ids[0], 0, 0),
                count: 2,
            };
            let (mut channel, raw_sender) =
                new_task_channel_for_test(task_id.into(), ids[0], ids[0], participants);
            raw_sender
                .send(MpcPeerMessage {
                    from: outsider,
                    message: MpcMessage {
                        channel_id: ChannelId(UniqueId::new(outsider, 0, 0)),
                        kind: MpcMessageKind::Computation(vec![vec![1u8]]),
                    },
                })
                .unwrap();
            let protocol = ScriptedProtocol {
                script: [Action::Wait].into(),
            };

            // When
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                run_protocol("scripted", &mut channel, protocol),
            )
            .await
            .expect("run_protocol must return an error, not hang or panic");

            // Then
            let err = result.expect_err("out-of-set Computation must be rejected");
            assert!(
                err.downcast_ref::<ParticipantNotInChannelError>().is_some(),
                "expected ParticipantNotInChannelError, got: {err:#}"
            );
        })
        .await;
    }

    /// Counter updates for an untracked participant must be ignored, not panic.
    #[test_log::test(tokio::test)]
    #[expect(non_snake_case)]
    async fn message_counters__should_ignore_unknown_participant() {
        tracking::testing::start_root_task_with_periodic_dump(async {
            // Given
            let ids = into_participant_ids(&generate_participants(2));
            let counters = MessageCounters::new("test".to_string(), &[ids[0]]);
            let unknown = ids[1];

            // When / Then
            counters.queue_send(unknown, 1);
            counters.sent(unknown, 1);
            counters.received(unknown, 1);
        })
        .await;
    }

    async fn run_one_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
    ) -> anyhow::Result<Option<u32>> {
        let my_id = client.my_participant_id();
        let mut ids = client.all_participant_ids();
        ids.sort();
        if my_id == ids[0] {
            let task_id = EcdsaTaskId::ManyTriples {
                start: UniqueId::new(my_id, 0, 0),
                count: 2,
            };
            let mut channel = client.new_channel_for_task(task_id, ids)?;
            let protocol = ScriptedProtocol {
                script: [Action::Yield, Action::Yield, Action::Return(42)].into(),
            };

            // The deadline turns a hang into a test failure rather than a timeout.
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                run_protocol("scripted", &mut channel, protocol),
            )
            .await
            .expect("run_protocol must keep poking after Action::Yield, not wait for a message")?;
            Ok(Some(result))
        } else {
            // Accept the leader's channel so its Start message has a destination.
            let _channel = channel_receiver.recv().await;
            Ok(None)
        }
    }
}
