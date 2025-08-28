use crate::network::conn::{recv_loop, send};
use crate::network::constants;
use crate::network::handshake::handshake;
use crate::network::types::{CommPeers, Connection, Connections, Peer};
use anyhow::Context;
use rustls::ClientConfig;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/* --------------------------- */
/* ------- Client logic -------*/
/* --------------------------- */
pub struct Client {
    client_config: Arc<ClientConfig>,
    cancel: CancellationToken,
    pub peers: CommPeers,
    connections: Connections,
}

impl Client {
    // todo: add capability to change partcipant set.
    pub fn new(
        client_config: Arc<ClientConfig>,
        peers: CommPeers,
        cancel: CancellationToken,
    ) -> Self {
        Client {
            cancel,
            client_config,
            peers,
            connections: Connections::new(),
        }
    }
    pub async fn get_conn(&mut self, peer: &Peer) -> anyhow::Result<Arc<Connection>> {
        if self.peers.get_peer(&peer.public_key).is_none() {
            anyhow::bail!("not an allowed peer");
        }
        if self.connections.get(&peer.public_key).is_none() {
            let conn = establish_connection_as_client(
                self.client_config.clone(),
                peer.clone(),
                self.cancel.child_token(),
            )
            .await?;
            self.connections.insert(conn).await;
        }
        let Some(conn) = self.connections.get(&peer.public_key) else {
            anyhow::bail!("expected connection");
        };
        Ok(conn)
    }
}

async fn establish_connection_as_client(
    client_config: Arc<ClientConfig>,
    peer: Peer,
    cancel: CancellationToken,
) -> anyhow::Result<Connection> {
    let tls_stream = tokio::select! {
     _ = cancel.cancelled() => {
            anyhow::bail!("cancelled");
    }
    res = async {
        let conn = TcpStream::connect(peer.address.clone())
            .await
            .context("TCP connect")?;
        let mut tls_stream = tokio_rustls::TlsConnector::from(client_config)
            .connect(mpc_tls::constants::SERVER_NAME.try_into().unwrap(), conn)
            .await
            .context("TLS connect")?;
        let common_state = tls_stream.get_ref().1;
        let peer_pk = mpc_tls::tls::extract_public_key(common_state)?;
        if peer_pk != peer.public_key {
            anyhow::bail!("expected match");
        }

        tracing::info!(target: "establish_connection_as_client", "Performing P2P handshake with: {:?}", peer.address);
        handshake(&mut tls_stream, constants::HANDSHAKE_TIMEOUT)
            .await
            .context("p2p handshake")?;

        tracing::info!(target:"establish_connection_as_client", "Concluded P2P handshake with: {:?}", peer.address);
        Ok(tls_stream)
    } => res?
    };
    let (tls_reader, tls_writer) = tokio::io::split(tls_stream);
    let (outgoing_sender, outgoing_receiver) = tokio::sync::mpsc::unbounded_channel();

    let cancel_send_and_write = cancel.child_token();
    tokio::spawn(send(
        tls_writer,
        cancel_send_and_write.child_token(),
        outgoing_receiver,
        peer.clone(),
    ));

    let (incoming_sender, incoming_receiver) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(recv_loop(
        tls_reader,
        cancel_send_and_write.child_token(),
        incoming_sender,
        peer.clone(),
    ));

    Ok(Connection::new(
        peer,
        cancel_send_and_write,
        outgoing_sender,
        Mutex::new(incoming_receiver),
    ))
}
