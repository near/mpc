//! Carries the signed node outcomes of V2 foreign tx attempts over a channel.

use super::{MeshNetworkClient, NetworkTaskChannel, NetworkTaskChannelSender, ReceivedMessage};
use crate::network::wire_format::MpcMessageKind;
use crate::primitives::{ChannelId, MpcMessage, MpcPeerMessage, ParticipantId};
use crate::providers::verify_foreign_tx::attempt_evidence::AttemptEvidence;
use crate::providers::verify_foreign_tx::node_outcome_statement::{AttemptId, SignedNodeOutcome};
use std::sync::Arc;

/// The node outcomes one participant sent in a single message.
#[derive(Debug)]
pub(crate) struct PeerNodeOutcomes {
    pub(crate) from: ParticipantId,
    pub(crate) outcomes: Vec<SignedNodeOutcome>,
}

impl MeshNetworkClient {
    /// The node outcomes of the V2 attempts this node leads.
    pub(crate) fn attempt_evidence(&self) -> &Arc<AttemptEvidence> {
        &self.attempt_evidence
    }

    /// Keeps node outcomes for a channel this node owns in [`AttemptEvidence`] as they arrive,
    /// and then hands them to the channel while it is open. Followers report even after an
    /// attempt ends, so an outcome counts as evidence while its channel runs and after.
    /// Returns every other message.
    pub(crate) fn route_node_outcomes(&self, message: MpcPeerMessage) -> Option<MpcPeerMessage> {
        let MpcPeerMessage {
            from,
            message: MpcMessage { channel_id, kind },
        } = message;
        let outcomes = match kind {
            MpcMessageKind::NodeOutcomes(outcomes)
                if channel_id.0.participant_id() == self.my_participant_id() =>
            {
                outcomes
            }
            kind => {
                return Some(MpcPeerMessage {
                    from,
                    message: MpcMessage { channel_id, kind },
                });
            }
        };
        if let Err(err) =
            self.attempt_evidence
                .record_received(from, AttemptId(channel_id), outcomes.clone())
        {
            tracing::debug!(%from, ?channel_id, %err, "node outcomes not kept as evidence");
        }
        let channels = self.channels.lock().unwrap();
        if let Some(sender) = channels.senders.get(&channel_id) {
            let message = MpcPeerMessage {
                from,
                message: MpcMessage {
                    channel_id,
                    kind: MpcMessageKind::NodeOutcomes(outcomes),
                },
            };
            if sender.send(message).is_err() {
                tracing::debug!(%from, ?channel_id, "dropping node outcomes for a closing channel");
            }
        }
        None
    }
}

impl NetworkTaskChannel {
    pub(crate) fn channel_id(&self) -> ChannelId {
        self.sender.channel_id
    }

    /// Receives the next node outcomes. Computation messages that arrive first are kept for
    /// [`Self::receive`], in order.
    pub(crate) async fn receive_node_outcomes(&mut self) -> anyhow::Result<PeerNodeOutcomes> {
        loop {
            match self.receive_one().await? {
                Some(ReceivedMessage::NodeOutcomes(outcomes)) => return Ok(outcomes),
                Some(ReceivedMessage::Computation(data)) => {
                    self.deferred_computations.push_back(data);
                }
                None => {}
            }
        }
    }
}

impl NetworkTaskChannelSender {
    /// Sends this follower's node outcome to the leader. It does not need the channel to be
    /// open, so a follower can report after the attempt ended.
    pub(crate) fn send_node_outcome(&self, outcome: SignedNodeOutcome) -> anyhow::Result<()> {
        self.send_raw(
            self.leader,
            MpcMessage {
                channel_id: self.channel_id,
                kind: MpcMessageKind::NodeOutcomes(vec![outcome]),
            },
        )
    }

    /// Ends the computation with the network abort.
    pub(crate) fn abort(&self, err: &anyhow::Error) {
        self.communicate_failure(err);
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::network::testing::new_task_channel_for_test;
    use crate::network::wire_format::VerifyForeignTxTaskId;
    use crate::primitives::UniqueId;
    use near_indexer_primitives::CryptoHash;
    use std::time::Duration;

    const LEADER: ParticipantId = ParticipantId::from_raw(0);
    const FOLLOWER: ParticipantId = ParticipantId::from_raw(1);
    const OTHER_FOLLOWER: ParticipantId = ParticipantId::from_raw(2);

    fn message(from: ParticipantId, kind: MpcMessageKind) -> MpcPeerMessage {
        MpcPeerMessage {
            from,
            message: MpcMessage {
                channel_id: ChannelId(UniqueId::new(LEADER, 1, 0)),
                kind,
            },
        }
    }

    #[tokio::test]
    async fn network_task_channel_receive__should_replay_computations_that_arrived_before_the_node_outcomes()
     {
        // Given
        let (mut channel, sender) = new_task_channel_for_test(
            VerifyForeignTxTaskId::VerifyForeignTxV2 {
                id: CryptoHash::default(),
                paired_triple_id: UniqueId::new(LEADER, 1, 1),
            }
            .into(),
            LEADER,
            LEADER,
            vec![LEADER, FOLLOWER, OTHER_FOLLOWER],
        );
        sender
            .send(message(
                FOLLOWER,
                MpcMessageKind::Computation(vec![vec![1]]),
            ))
            .unwrap();
        sender
            .send(message(
                OTHER_FOLLOWER,
                MpcMessageKind::NodeOutcomes(vec![]),
            ))
            .unwrap();
        sender
            .send(message(
                OTHER_FOLLOWER,
                MpcMessageKind::Computation(vec![vec![2]]),
            ))
            .unwrap();

        // When
        let (outcomes, first, second) = tokio::time::timeout(Duration::from_secs(5), async {
            let outcomes = channel.receive_node_outcomes().await.unwrap();
            let first = channel.receive().await.unwrap();
            let second = channel.receive().await.unwrap();
            (outcomes, first, second)
        })
        .await
        .unwrap();

        // Then
        assert_eq!(outcomes.from, OTHER_FOLLOWER);
        assert_eq!((first.from, first.data), (FOLLOWER, vec![vec![1]]));
        assert_eq!((second.from, second.data), (OTHER_FOLLOWER, vec![vec![2]]));
    }
}
