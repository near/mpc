use std::num::NonZeroUsize;
use std::time::Duration;

use crate::network::view::network_link_latency::MeanBlockLag;

/// Maximum length of a single network message. This is a security measure
/// to prevent a malicious node from sending a huge message that would
/// cause OOM errors.
pub const MAX_MESSAGE_SIZE_BYTES: usize = 100 * 1024 * 1024;
/// Timeout in seconds for reading messages from the network peers.
/// This is to prevent hanging peer connections.
pub const MESSAGE_READ_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

pub const CONNECTED_PEERS_BROADCAST_INTERVAL: Duration = Duration::from_secs(1);

pub const METRICS_EMIT_INTERVAL: Duration = Duration::from_secs(5);
/// Gossip-delay samples averaged per link direction. One arrives per received row, so this is
/// roughly a window in seconds: ten average out the broadcast-phase jitter of up to two
/// [`CONNECTED_PEERS_BROADCAST_INTERVAL`]s and still react within seconds.
pub const RECENT_DELAY_SAMPLES: NonZeroUsize =
    NonZeroUsize::new(10).expect("literal must be non-zero");
/// Largest moving-average gossip delay, in blocks, at which a link still counts as online: the
/// liveness lag plus a buffer for the extra gossip hop in the measurement.
pub const MAX_ONLINE_DELAY_BLOCKS: MeanBlockLag =
    MeanBlockLag::new(mpc_node_config::MAX_INDEXER_HEIGHT_DIFF + 10);
/// Network view updates buffered per participant. Every participant sends one per
/// [`CONNECTED_PEERS_BROADCAST_INTERVAL`], so this is a few intervals of backlog before producers
/// start dropping updates.
pub const NETWORK_VIEW_UPDATES_BUFFERED_PER_PARTICIPANT: usize = 4;
