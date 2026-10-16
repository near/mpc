use crate::protocol_version::NetworkProtocolVersion;
use std::time::Duration;

/// Handshake protocol version that introduced
/// [`Packet::ConnectedPeers`](crate::network::wire_format::Packet::ConnectedPeers).
pub const CONNECTED_PEERS_MIN_PROTOCOL_VERSION: NetworkProtocolVersion =
    NetworkProtocolVersion::Oct2026;

pub const CONNECTED_PEERS_BROADCAST_INTERVAL: Duration = Duration::from_secs(1);
