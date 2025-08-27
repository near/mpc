use tokio_util::sync::CancellationToken;

use crate::types::CommunicatorPeerId;

#[derive(Clone)]
struct Connection {
    pub peer_id: CommunicatorPeerId,
    pub cancel: CancellationToken,
}
