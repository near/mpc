use crate::network::conn::{recv_loop, send};
use crate::network::constants::HANDSHAKE_TIMEOUT;
use crate::network::handshake::handshake;
use crate::network::types::{CommPeers, Connection, Peer};
use anyhow::Context;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use super::constants;

/* --------------------------- */
/* ------- Server logic -------*/
/* --------------------------- */
pub struct Server {
    server_config: Arc<rustls::server::ServerConfig>,
    my_port: u16,
    server_connections: Arc<Mutex<ServerConnections>>,
    pub cancel: CancellationToken,
}

impl Server {
    pub fn new(
        server_config: Arc<rustls::server::ServerConfig>,
        my_port: u16,
        allowed_peer_keys: CommPeers,
        cancel: CancellationToken,
    ) -> Self {
        let server_connections = ServerConnections::new(allowed_peer_keys);
        Server {
            server_connections: Arc::new(Mutex::new(server_connections)),
            server_config,
            my_port,
            cancel,
        }
    }
    pub async fn get_conn(&self, peer: &Peer) -> Option<Arc<Connection>> {
        self.server_connections.lock().await.get(&peer.public_key)
    }
}

pub async fn listen(server: Arc<Server>) -> anyhow::Result<()> {
    tracing::info!("spinning up server");
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(server.server_config.clone());
    let tcp_listener = tokio::net::TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(0, 0, 0, 0),
        server.my_port,
    )))
    .await
    .context("TCP bind")?;
    tokio::spawn(listen_incoming(
        tls_acceptor,
        tcp_listener,
        server.cancel.child_token(),
        server.server_connections.clone(),
    ));
    Ok(())
}
struct ServerConnections {
    allowed_peer_keys: CommPeers,
    connections: HashMap<ed25519_dalek::VerifyingKey, Arc<Connection>>,
}

impl ServerConnections {
    // todo: add capability to change participant set
    pub fn new(allowed_peer_keys: CommPeers) -> Self {
        ServerConnections {
            allowed_peer_keys,
            connections: HashMap::new(),
        }
    }
    pub async fn add_or_replace(&mut self, conn: Connection) -> bool {
        match self.connections.entry(conn.peer.public_key) {
            Entry::Vacant(v) => {
                v.insert(Arc::new(conn));
                false
            }
            Entry::Occupied(mut o) => {
                tracing::info!(
                    "replacing existing connection for peer {:?}",
                    conn.peer.public_key
                );
                o.get().cancel().await;
                o.insert(Arc::new(conn));
                true
            }
        }
    }
    pub async fn get_peer(&self, key: &ed25519_dalek::VerifyingKey) -> Option<Peer> {
        self.allowed_peer_keys.get_peer(key)
    }
    pub fn get(&self, key: &ed25519_dalek::VerifyingKey) -> Option<Arc<Connection>> {
        self.connections.get(key).cloned()
    }
}

async fn listen_incoming(
    tls_acceptor: tokio_rustls::TlsAcceptor,
    tcp_listener: tokio::net::TcpListener,
    cancel: CancellationToken,
    server_connections: Arc<Mutex<ServerConnections>>,
) {
    tracing::info!("listening");
    loop {
        let tcp_stream: TcpStream = tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("listener cancelled; stopping accept loop");
                break;
            }
            res = tcp_listener.accept() => {
                match res {
                    Ok((s, addr)) => {
                        tracing::debug!(%addr, "accepted TCP connection");
                        s
                    }
                    Err(e) => {
                        tracing::warn!(error=%e, "accept failed; continuing");
                        continue;
                    }
                }
            }
        };

        let tls_acceptor = tls_acceptor.clone();
        let server_connections = server_connections.clone();
        let child = cancel.child_token();

        tokio::spawn(async move {
            accept_connection(tls_acceptor, tcp_stream, server_connections.clone(), child).await
        });
    }
}

async fn accept_connection(
    tls_acceptor: tokio_rustls::TlsAcceptor,
    tcp_stream: TcpStream,
    server_connections: Arc<Mutex<ServerConnections>>,
    cancel: CancellationToken,
) -> anyhow::Result<bool> {
    let (peer, tls_stream) = tokio::select! {
        _ = cancel.cancelled() => {
            anyhow::bail!("cancelled");
    }
        res = async {
            let mut stream = tls_acceptor.accept(tcp_stream).await?;
            let common_state = stream.get_ref().1;
            let peer_pk = mpc_tls::tls::extract_public_key(common_state)?;
            // todo: can you split read / write locks?
            let Some(peer) = server_connections.lock().await.get_peer(&peer_pk).await else {
                anyhow::bail!("peer is not in list of allowed peers.");
            };
            tracing::info!(target: "accept_connection","Performing P2P handshake with: {:?}", peer.address);
            handshake(&mut stream, HANDSHAKE_TIMEOUT)
                .await
                .context("p2p handshake")?;
            tracing::info!(target: "accept_connection", "Concluded P2P handshake with: {:?}", peer.address);
            Ok::<_, anyhow::Error>((peer, stream))
            } => res?,
    };

    let (tls_reader, tls_writer) = tokio::io::split(tls_stream);
    let (outgoing_sender, outgoing_receiver) =
        tokio::sync::mpsc::channel(constants::CHANNEL_CAPACITY);
    let cancel_send_and_write = cancel.child_token();
    tokio::spawn(send(
        tls_writer,
        cancel_send_and_write.child_token(),
        outgoing_receiver,
        peer.clone(),
    ));

    let (incoming_sender, incoming_receiver) =
        tokio::sync::mpsc::channel(constants::CHANNEL_CAPACITY);
    tokio::spawn(recv_loop(
        tls_reader,
        cancel_send_and_write.child_token(),
        incoming_sender,
        peer.clone(),
    ));
    let conn = Connection::new(
        peer,
        cancel_send_and_write,
        outgoing_sender,
        Mutex::new(incoming_receiver),
    );
    Ok(server_connections.lock().await.add_or_replace(conn).await)
}
