use std::time::Duration;

/// Maximum length of a single network message. This is a security measure
/// to prevent a malicious node from sending a huge message that would
/// cause OOM errors.
pub const MAX_MESSAGE_LEN: u32 = 100 * 1024 * 1024;
pub(crate) const READ_HDR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
pub(crate) const READ_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
pub(crate) const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
pub(crate) const HANDSHAKE_TIMEOUT: std::time::Duration = Duration::from_secs(1);
