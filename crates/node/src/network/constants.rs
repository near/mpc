use std::time::Duration;

/// Maximum length of a single network message. This is a security measure
/// to prevent a malicious node from sending a huge message that would
/// cause OOM errors.
pub const MAX_MESSAGE_SIZE_BYTES: usize = 100 * 1024 * 1024;
/// Timeout in seconds for reading messages from the network peers.
/// This is to prevent hanging peer connections.
pub const MESSAGE_READ_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

pub const CONNECTED_PEERS_BROADCAST_INTERVAL: Duration = Duration::from_secs(1);
/// How often the first-hand indexer heights are published to their readers. Less than a block, so
/// the heights we broadcast are hardly older than the ones we received.
pub const FIRST_HAND_INDEXER_HEIGHTS_PUBLISH_INTERVAL: near_time::Duration =
    near_time::Duration::milliseconds(300);

pub const METRICS_EMIT_INTERVAL: Duration = Duration::from_secs(5);
/// Network view updates buffered per participant. Every participant sends one per
/// [`CONNECTED_PEERS_BROADCAST_INTERVAL`], so this is a few intervals of backlog before producers
/// start dropping updates.
pub const NETWORK_VIEW_UPDATES_BUFFERED_PER_PARTICIPANT: usize = 4;
/// Picks one attempt at finding a clique of participants tries before the search starts over with
/// the candidates in a new random order. An attempt that never backs out of a pick tries one per
/// participant it needs; backing out of dead ends is exponential in the worst case.
pub const MAX_PICKS_PER_CLIQUE_SEARCH_ATTEMPT: usize = 3_000;
/// Attempts before the search for a clique gives up. With
/// [`MAX_PICKS_PER_CLIQUE_SEARCH_ATTEMPT`], sized for 30 participants with randomly broken
/// connections: all attempts together take about 2 ms, and giving up then means, in practice, that
/// no clique exists.
pub const MAX_CLIQUE_SEARCH_ATTEMPTS: usize = 10;
