use std::num::NonZeroUsize;
use std::time::Duration;

//use crate::network::view::network_link_latency::MeanBlockLag;

/// Maximum length of a single network message. This is a security measure
/// to prevent a malicious node from sending a huge message that would
/// cause OOM errors.
pub const MAX_MESSAGE_SIZE_BYTES: usize = 100 * 1024 * 1024;
/// Timeout in seconds for reading messages from the network peers.
/// This is to prevent hanging peer connections.
pub const MESSAGE_READ_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

pub const CONNECTED_PEERS_BROADCAST_INTERVAL: Duration = Duration::from_secs(1);

pub const METRICS_EMIT_INTERVAL: Duration = Duration::from_secs(5);
/// Lags kept per link direction for the mean lag. One arrives per received report, so at one per
/// [`CONNECTED_PEERS_BROADCAST_INTERVAL`] the mean spans a minute.
pub const RECENT_DELAY_SAMPLES: NonZeroUsize =
    NonZeroUsize::new(60).expect("literal must be non-zero");
///// Largest moving-average gossip delay, in blocks, at which a link still counts as online: the
///// liveness lag plus a buffer for the extra gossip hop in the measurement.
// todo: uncalibrated; see the todo on `RecentBlockLags`' `GradeLink` impl
//pub const MAX_ONLINE_DELAY_BLOCKS: MeanBlockLag =
//    MeanBlockLag::new(mpc_node_config::MAX_INDEXER_HEIGHT_DIFF + 10);
/// Uninterrupted presence behind the `Seconds` and `HalfMinute` uptimes.
pub const UPTIME_SECONDS: near_time::Duration = near_time::Duration::seconds(5);
pub const UPTIME_HALF_MINUTE: near_time::Duration = near_time::Duration::seconds(25);
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
