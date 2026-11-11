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

    /// Delivers node outcomes for a channel this node owns: to the channel while it is open, and
    /// to [`AttemptEvidence`] once it closed, since followers report even after an attempt ends.
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
            return None;
        }
        drop(channels);
        if let Err(err) = self
            .attempt_evidence
            .record_late(from, AttemptId(channel_id), outcomes)
        {
            tracing::warn!(%from, ?channel_id, %err, "rejecting late node outcomes");
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
