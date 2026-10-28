use std::time::Duration;

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
pub const RECENT_DELAY_SAMPLES: usize = 10;
