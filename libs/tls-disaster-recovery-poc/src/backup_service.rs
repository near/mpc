use crate::network::client::Client;
use crate::network::types::{CommPeers, CommunicatorPeerId, Connection, Peer};
use rustls::ClientConfig;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

pub struct BackupService {
    client: Client,
}

impl BackupService {
    pub fn new(tls_config: Arc<ClientConfig>, mpc_node: Peer) -> Self {
        let mut peers = CommPeers::new();
        let _ = peers.insert(mpc_node);
        let cancel = CancellationToken::new();
        let client = Client::new(tls_config, peers, cancel);
        Self { client }
    }
    pub async fn connect(&mut self, peer: &Peer) -> anyhow::Result<Arc<Connection>> {
        self.client.get_conn(peer).await
    }
    pub fn remove(&mut self, peer: &Peer) -> anyhow::Result<()> {
        self.client.peers.remove(&peer.public_key)
    }
    pub fn add_peer(&mut self, peer: Peer) -> anyhow::Result<CommunicatorPeerId> {
        self.client.peers.insert(peer)
    }
}
