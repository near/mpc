use std::time::Duration;

pub(crate) const READ_HDR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub(crate) const READ_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
pub(crate) const HANDSHAKE_TIMEOUT: std::time::Duration = Duration::from_secs(1);
const MESSAGE_READ_TIMEOUT_SECS: std::time::Duration = Duration::from_secs(1); // todo: adjust
