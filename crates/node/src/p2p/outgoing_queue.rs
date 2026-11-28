use crate::network::wire_format::Packet;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

/// Enqueues packets for one peer; the connection's sender task drains them through
/// [`OutgoingQueueReceiver`] and writes them to the TLS stream.
///
/// Control packets (pings, indexer heights, connected-peers info. liveness) skip ahead of queued MPC
/// messages. Peers decide whether we are alive from our indexer height, so a backlog of
/// computation traffic must not delay it. Packets in the same lane keep their order.
#[derive(Clone)]
pub(super) struct OutgoingQueue {
    control: UnboundedSender<Packet>,
    mpc: UnboundedSender<Packet>,
}

pub(super) struct OutgoingQueueReceiver {
    control: UnboundedReceiver<Packet>,
    mpc: UnboundedReceiver<Packet>,
}

impl OutgoingQueue {
    pub(super) fn new() -> (Self, OutgoingQueueReceiver) {
        let (control, control_receiver) = mpsc::unbounded_channel();
        let (mpc, mpc_receiver) = mpsc::unbounded_channel();
        (
            Self { control, mpc },
            OutgoingQueueReceiver {
                control: control_receiver,
                mpc: mpc_receiver,
            },
        )
    }

    pub(super) fn send(&self, packet: Packet) -> Result<(), ConnectionClosed> {
        let lane = match &packet {
            Packet::Ping
            | Packet::IndexerHeight(_)
            | Packet::ConnectedPeersInfo(_)
            | Packet::Echo(_)
            | Packet::EchoAck(_) => &self.control,
            Packet::MpcMessage(_) => &self.mpc,
        };
        lane.send(packet).map_err(|_| ConnectionClosed)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("the outgoing connection is closed")]
pub(super) struct ConnectionClosed;

impl OutgoingQueueReceiver {
    /// Returns the next packet, control packets first, or `None` once every [`OutgoingQueue`]
    /// is dropped and both lanes are drained. Cancel safe.
    pub(super) async fn recv(&mut self) -> Option<Packet> {
        tokio::select! {
            biased;
            Some(packet) = self.control.recv() => Some(packet),
            Some(packet) = self.mpc.recv() => Some(packet),
            else => None,
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::OutgoingQueue;
    use crate::network::wire_format::{MpcMessageKind, Packet};
    use crate::primitives::{ChannelId, IndexerHeightMessage, MpcMessage, ParticipantId, UniqueId};

    fn mpc_packet(counter: u32) -> Packet {
        Packet::MpcMessage(MpcMessage {
            channel_id: ChannelId(UniqueId::new(ParticipantId::from_raw(0), 0, counter)),
            kind: MpcMessageKind::Success,
        })
    }

    fn height_packet(height: u64) -> Packet {
        Packet::IndexerHeight(IndexerHeightMessage { height })
    }

    fn encoded(packets: &[Packet]) -> Vec<Vec<u8>> {
        packets
            .iter()
            .map(|packet| borsh::to_vec(packet).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn outgoing_queue__should_deliver_control_packets_before_queued_mpc_messages() {
        // Given
        let (queue, mut receiver) = OutgoingQueue::new();
        for counter in 0..3 {
            queue.send(mpc_packet(counter)).unwrap();
        }
        queue.send(height_packet(42)).unwrap();

        // When
        let mut received = Vec::new();
        for _ in 0..4 {
            received.push(receiver.recv().await.unwrap());
        }

        // Then
        let expected = [
            height_packet(42),
            mpc_packet(0),
            mpc_packet(1),
            mpc_packet(2),
        ];
        assert_eq!(encoded(&received), encoded(&expected));
    }

    #[tokio::test]
    async fn outgoing_queue__should_end_when_all_senders_are_dropped() {
        // Given
        let (queue, mut receiver) = OutgoingQueue::new();
        let clone = queue.clone();

        // When
        drop((queue, clone));

        // Then
        assert!(receiver.recv().await.is_none());
    }
}
