use crate::network::server::{Server, listen};
use crate::network::types::{CommPeers, Connection, Peer};
use rustls::ServerConfig;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

pub struct MpcNode {
    server: Arc<Server>,
}

impl MpcNode {
    pub fn serve(&self) {
        tokio::spawn(listen(self.server.clone()));
    }
    pub fn new(tls_config: Arc<ServerConfig>, backup_service: Peer, port: u16) -> Self {
        let mut peers = CommPeers::new();
        let _ = peers.insert(backup_service);
        let cancel = CancellationToken::new();
        let server = Arc::new(Server::new(tls_config, port, peers, cancel));
        Self { server }
    }
    pub async fn wait_for_peer(&self, peer: &Peer) -> Arc<Connection> {
        loop {
            if let Some(conn) = self.server.get_conn(&peer).await {
                break conn;
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    pub fn cancel(&self) {
        self.server.cancel.cancel();
    }
}
