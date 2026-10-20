use crate::primitives::ParticipantId;
use crate::protocol_version::NetworkProtocolVersion;
use std::time::Duration;

/// Handshake protocol version that introduced
/// [`Packet::ConnectedPeersInfo`](crate::network::wire_format::Packet::ConnectedPeersInfo).
pub const CONNECTED_PEERS_MIN_PROTOCOL_VERSION: NetworkProtocolVersion =
    NetworkProtocolVersion::Oct2026;

pub const CONNECTED_PEERS_BROADCAST_INTERVAL: Duration = Duration::from_secs(1);

/// Why a [`ConnectedPeersInfo`](crate::primitives::ConnectedPeersInfo) was not sent.
#[derive(Debug, thiserror::Error)]
pub enum ConnectedPeersNotSent {
    #[error("no outgoing connection to {0}")]
    PeerNotConnected(ParticipantId),
    #[error("{peer} negotiated {version}, which cannot parse the message")]
    PeerNotSupportingMessage {
        peer: ParticipantId,
        version: NetworkProtocolVersion,
    },
}
