use std::time::Duration;

/// Maximum length of a single network message. This is a security measure
/// to prevent a malicious node from sending a huge message that would
/// cause OOM errors.
pub const MAX_MESSAGE_BYTES: usize = 100 * 1024 * 1024;
/// Timeout in seconds for reading messages from the network peers.
/// This is to prevent hanging peer connections.
pub const MESSAGE_READ_TIMEOUT_DURATION: Duration = Duration::from_secs(30);
