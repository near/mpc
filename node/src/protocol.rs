use std::sync::{atomic::AtomicUsize, Arc};

use crate::primitives::{BatchedMessages, ParticipantId};
use crate::tracking;
use crate::{network::NetworkTaskChannel, tracking::TaskHandle};
use cait_sith::protocol::{Action, Protocol};
use futures::TryFutureExt;
use tokio::sync::mpsc;

/// Runs any cait-sith protocol, returning the result. Exports tracking progress
/// describing how many messages are sent and received to each participant.
pub async fn run_protocol<T>(
    name: &'static str,
    mut channel: NetworkTaskChannel,
    participants: Vec<ParticipantId>,
    me: ParticipantId,
    mut protocol: impl Protocol<Output = T>,
) -> anyhow::Result<T> {
    let counters = Arc::new(MessageCounters::new(name.to_string(), participants.len()));
    let mut queue_senders: Vec<mpsc::UnboundedSender<BatchedMessages>> = Vec::new();
    let mut queue_receivers: Vec<mpsc::UnboundedReceiver<BatchedMessages>> = Vec::new();

    for _ in 0..participants.len() {
        let (send, recv) = mpsc::unbounded_channel();
        queue_senders.push(send);
        queue_receivers.push(recv);
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
    //    we're computing, we would not be able to cooperatively run any other tasks, and that can
    //    unnecessarily block sending. It is OK to have the receiving side blocked by computation,
    //    because on the receiving side, the network channel already provides us with a buffer
    //    dedicated to our task.
    let sending_handle = {
        let counters = counters.clone();
        let sender = channel.sender();
        let participants = participants.clone();
        tracking::spawn_checked("send messages", async move {
            // One future for each recipient. For the same recipient it is OK to send messages
            // serially, but for multiple recipients we want them to not block each other.
            // These futures are IO-bound, so we don't have to spawn them separately.
            let futures = queue_receivers
                .into_iter()
                .enumerate()
                .map(move |(i, mut receiver)| {
                    let participant_id = participants[i];
                    let sender = sender.clone();
                    let counters = counters.clone();
                    async move {
                        while let Some(messages) = receiver.recv().await {
                            let num_messages = messages.len();
                            sender(participant_id, messages).await?;
                            counters.sent(i, num_messages);
                        }
                        anyhow::Ok(())
                    }
                });
            futures::future::try_join_all(futures).await?;
            anyhow::Ok(())
        })
        .map_err(anyhow::Error::from)
    };

    let computation_handle = async move {
        loop {
            let mut messages_to_send = (0..participants.len())
                .map(|_| Vec::new())
                .collect::<Vec<_>>();
            let done = loop {
                match protocol.poke()? {
                    Action::Wait => break None,
                    Action::SendMany(vec) => {
                        for participant in &participants {
                            if participant == &me {
                                continue;
                            }
                            messages_to_send[participant.0 as usize].push(vec.clone());
                        }
                    }
                    Action::SendPrivate(participant, vec) => {
                        messages_to_send[u32::from(participant) as usize].push(vec);
                    }
                    Action::Return(result) => {
                        // Warning: we cannot return immediately!! There may be some important
                        // messages to send to others to enable others to complete their computation.
                        break Some(result);
                    }
                }
            };

            // Batch-send the messages. This is a useful optimization as cait-sith tends to ask us
            // to send many messages at once to the same recipient.
            // TODO(#21): maybe we can fix the cait-sith protocol to not ask us to send so many
            // messages in the first place.
            for (i, messages) in messages_to_send.into_iter().enumerate() {
                if messages.is_empty() {
                    continue;
                }
                counters.queue_send(i, messages.len());
                queue_senders[i].send(messages).unwrap();
            }

            if let Some(result) = done {
                return anyhow::Ok(result);
            }

            counters.set_receiving();

            let msg = channel.receive().await?;
            counters.received(msg.from.0 as usize, msg.message.data.len());

            for one_msg in msg.message.data {
                protocol.message(msg.from.into(), one_msg);
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
    sent: Vec<AtomicUsize>,
    in_flight: Vec<AtomicUsize>,
    received: Vec<AtomicUsize>,
    current_action: AtomicUsize, // 1 = receiving, 0 = computing
}

impl MessageCounters {
    pub fn new(name: String, participants: usize) -> Self {
        Self {
            name,
            task: tracking::current_task(),
            sent: (0..participants)
                .map(|_| AtomicUsize::new(0))
                .collect::<Vec<_>>(),
            in_flight: (0..participants)
                .map(|_| AtomicUsize::new(0))
                .collect::<Vec<_>>(),
            received: (0..participants)
                .map(|_| AtomicUsize::new(0))
                .collect::<Vec<_>>(),
            current_action: AtomicUsize::new(0),
        }
    }

    pub fn queue_send(&self, participant: usize, num_messages: usize) {
        self.in_flight[participant].fetch_add(num_messages, std::sync::atomic::Ordering::Relaxed);
        self.report_progress();
    }

    pub fn sent(&self, participant: usize, num_messages: usize) {
        self.sent[participant].fetch_add(num_messages, std::sync::atomic::Ordering::Relaxed);
        self.in_flight[participant].fetch_sub(num_messages, std::sync::atomic::Ordering::Relaxed);
        self.report_progress();
    }

    pub fn received(&self, participant: usize, num_messages: usize) {
        self.received[participant].fetch_add(num_messages, std::sync::atomic::Ordering::Relaxed);
        self.current_action
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn set_receiving(&self) {
        self.current_action
            .store(1, std::sync::atomic::Ordering::Relaxed);
        self.report_progress();
    }

    fn report_progress(&self) {
        self.task.set_progress(&format!(
            "{}: sent {:?} (inflight {:?}), received {:?} ({})",
            self.name,
            self.sent
                .iter()
                .map(|a| a.load(std::sync::atomic::Ordering::Relaxed))
                .collect::<Vec<_>>(),
            self.in_flight
                .iter()
                .map(|a| a.load(std::sync::atomic::Ordering::Relaxed))
                .collect::<Vec<_>>(),
            self.received
                .iter()
                .map(|a| a.load(std::sync::atomic::Ordering::Relaxed))
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
