use crate::handshake::handshake;
use crate::messages::{Messages, PeerMessage};
use crate::types::{CommPeers, CommunicatorPeerId};
use crate::{constants, messages};
use anyhow::Context;
use borsh::BorshDeserialize;
use rustls::{ClientConfig, ServerConfig};
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::MissedTickBehavior;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

struct OutgoingConnection {
    cancel: CancellationToken,
    send: tokio::sync::mpsc::UnboundedSender<Messages>,
}

struct OutgoingConnections {
    cancel: CancellationToken,
    client_config: Arc<ClientConfig>,
    peers: Arc<CommPeers>,
    outgoing: Mutex<BTreeMap<CommunicatorPeerId, OutgoingConnection>>,
    establishing: BTreeMap<CommunicatorPeerId, Semaphore>,
}

// todo: implement a buffer: have a queue for outgoing messages and have this struct handle that.
// Performance wise, this is not ideal.
impl OutgoingConnections {
    pub fn new(
        peers: Arc<CommPeers>,
        client_config: Arc<ClientConfig>,
        cancel: CancellationToken,
    ) -> Self {
        let mut establishing = BTreeMap::new();
        for peer_id in peers.ids().iter() {
            establishing.insert(peer_id.clone(), Semaphore::new(1));
        }
        tracing::info!("generated outgoing connections: {:?}", establishing);
        Self {
            cancel,
            client_config,
            peers,
            outgoing: Mutex::new(BTreeMap::new()),
            establishing,
        }
    }

    pub async fn is_connected(&self, peer_id: CommunicatorPeerId) -> bool {
        if let Some(res) = self.outgoing.lock().await.get(&peer_id) {
            !res.cancel.is_cancelled() && !res.send.is_closed()
        } else {
            false
        }
    }
    // todo: refactor and prettify this. no need for this to be so complicated.
    pub async fn get_or_connect(
        &self,
        peer_id: CommunicatorPeerId,
    ) -> anyhow::Result<tokio::sync::mpsc::UnboundedSender<Messages>> {
        let Some(establishing) = self.establishing.get(&peer_id) else {
            anyhow::bail!("could not find mutex. not a peer")
        };
        let _permit = establishing.acquire().await;
        if let Some(res) = self.outgoing.lock().await.get(&peer_id) {
            if !res.cancel.is_cancelled() && !res.send.is_closed() {
                return Ok(res.send.clone());
            }
        }
        let Some(peer) = self.peers.get(&peer_id) else {
            anyhow::bail!("not a peer")
        };
        let (send, recv) = tokio::sync::mpsc::unbounded_channel();
        let cancel_token = self.cancel.child_token();
        establish_connection(
            self.client_config.clone(),
            &peer.address,
            peer.public_key,
            cancel_token.child_token(),
            recv,
        )
        .await?;
        self.outgoing.lock().await.insert(
            peer_id,
            OutgoingConnection {
                cancel: cancel_token,
                send: send.clone(),
            },
        );
        return Ok(send);
    }
    pub fn cancel(&mut self) {
        self.cancel.cancel();
    }
    // todo: implement drop
}

pub struct Communicator {
    outgoing_connections: Arc<OutgoingConnections>,
    incoming_connections: Arc<Mutex<IncomingConnections>>,
    cancel: CancellationToken,
}

impl Communicator {
    pub async fn new(
        comm_peers: Arc<CommPeers>,
        server_config: Arc<ServerConfig>,
        client_config: Arc<ClientConfig>,
        cancel: CancellationToken,
        my_port: u16,
        message_sender: tokio::sync::mpsc::UnboundedSender<PeerMessage>,
    ) -> anyhow::Result<Self> {
        // spawn server:
        let incoming_connections = Arc::new(Mutex::new(IncomingConnections::new()));
        let mut server = Server::new(
            server_config,
            my_port,
            comm_peers.clone(),
            cancel.clone(),
            incoming_connections.clone(),
        );
        server.listen(message_sender).await?;

        let outgoing = Arc::new(OutgoingConnections::new(
            comm_peers.clone(),
            client_config,
            cancel.child_token(),
        ));
        comm_peers.ids().iter().map(|peer_id| {
            let outgoing_clone = outgoing.clone();
            let peer_id_clone = peer_id.clone();
            tokio::spawn(async move { outgoing_clone.get_or_connect(peer_id_clone).await })
        });
        Ok(Communicator {
            outgoing_connections: outgoing,
            incoming_connections,
            cancel,
        })
    }

    pub async fn send(&self, msg: PeerMessage) -> anyhow::Result<()> {
        let sender = self
            .outgoing_connections
            .get_or_connect(msg.peer_id)
            .await?;
        Ok(sender.send(msg.message)?)
    }
}

async fn send(
    mut tls_conn: TlsStream<TcpStream>,
    cancel: CancellationToken,
    mut receiver: tokio::sync::mpsc::UnboundedReceiver<Messages>,
) -> anyhow::Result<()> {
    // heartbeat timer
    let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(1));
    heartbeat_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut sent_bytes: u64 = 0;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {anyhow::bail!("closed");}
            data = receiver.recv() => {
                let Some(data) = data else {
                    anyhow::bail!("receiver has been dropped.");
                };
                let serialized = borsh::to_vec(&data)?;
                let len: u32 = serialized.len().try_into().context("Message too long")?;
                tls_conn.write_u32(len).await?;
                tls_conn.write_all(&serialized).await?;
                sent_bytes += 4 + len as u64;
                tracing::info!("Sent {} bytes", sent_bytes);

            }
            // send heartbeat every second
            _ = heartbeat_interval.tick() => {
                let packet = Messages::KEEPALIVE;
                let serialized = borsh::to_vec(&packet)?;
                let len: u32 = serialized.len().try_into().context("Message too long")?;
                tls_conn.write_u32(len).await?;
                tls_conn.write_all(&serialized).await?;
                sent_bytes += 4 + len as u64;
                tracing::trace!(sent_bytes, "sent heartbeat");
            }
            _ = tls_conn.read_u8() => {
                // We do not expect any data from the other side. However,
                // selecting on it will quickly return error if the connection
                // is broken before we have data to send. That way we can
                // immediately quit the loop as soon as the connection is broken
                // (so we can reconnect).
                cancel.cancel();
                anyhow::bail!("closed")
            }
        }
    }
}

// return a connection type with a method
async fn establish_connection(
    client_config: Arc<ClientConfig>,
    target_address: &str,
    expected_public_key: ed25519_dalek::VerifyingKey,
    cancel: CancellationToken,
    receiver: tokio::sync::mpsc::UnboundedReceiver<Messages>,
) -> anyhow::Result<()> {
    let tls_conn = tokio::select! {
         _ = cancel.cancelled() => {
                anyhow::bail!("cancelled");
        }
        res = async {
            let conn = TcpStream::connect(target_address)
                .await
                .context("TCP connect")?;
            let mut tls_conn = tokio_rustls::TlsConnector::from(client_config)
                .connect(mpc_tls::constants::SERVER_NAME.try_into().unwrap(), conn)
                .await
                .context("TLS connect")?;
            let common_state = tls_conn.get_ref().1;
            let peer_pk = mpc_tls::tls::extract_public_key(common_state)?;
            if peer_pk != expected_public_key {
                anyhow::bail!("expected match");
            }

            tracing::info!("Performing P2P handshake with: {:?}", target_address);
            handshake(&mut tls_conn, constants::HANDSHAKE_TIMEOUT)
                .await
                .context("p2p handshake")?;

            tracing::info!("Concluded P2P handshake with: {:?}", target_address);
            Ok(tls_conn)
    } => res?
        };
    tokio::spawn(send(tls_conn, cancel.clone(), receiver));
    Ok(())
}

pub async fn recv_loop<R: AsyncRead + Unpin>(
    mut stream: R,
    cancel: CancellationToken,
    message_sender: tokio::sync::mpsc::UnboundedSender<PeerMessage>,
    peer_id: CommunicatorPeerId,
) -> anyhow::Result<()> {
    let mut received_bytes: u64 = 0;

    loop {
        let len = tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!(target:"receiver", %peer_id, "cancelled");
                return Ok(());
            },
            res = tokio::time::timeout(constants::READ_HDR_TIMEOUT, stream.read_u32()) => {
                match res {
                    Err(_) => anyhow::bail!("header read timed out"),
                    Ok(Err(e)) => return Err(e).context("failed to read header"),
                    Ok(Ok(n)) => n,
                }
            }
        };

        if len == 0 {
            // Optional: treat zero-length as protocol error
            anyhow::bail!("unexpected zero-length message");
        }
        if len > messages::MAX_MESSAGE_LEN {
            anyhow::bail!("message too long: {}", len);
        }

        let mut buf = vec![0u8; len as usize];

        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!(target:"receiver", %peer_id, "cancelled during body read");
                return Ok(());
            },
            res = tokio::time::timeout(constants::READ_BODY_TIMEOUT, stream.read_exact(&mut buf)) => {
                match res {
                    Err(_) => anyhow::bail!("body read timed out"),
                    Ok(Err(e)) => return Err(e).context("failed to read body"),
                    Ok(Ok(_)) => {}
                }
            }
        }

        received_bytes += 4 + len as u64;
        tracing::info!(target: "receiver", %peer_id, received_bytes, "received bytes");

        let packet = Messages::try_from_slice(&buf).context("failed to deserialize packet")?;
        match packet {
            Messages::KEEPALIVE => {}
            Messages::Secrets(_) => {
                message_sender.send(PeerMessage {
                    peer_id,
                    message: packet,
                })?;
            }
        }
    }
}

#[derive(Clone)]
struct Connection {
    pub peer_id: CommunicatorPeerId,
    pub cancel: CancellationToken,
}

struct IncomingConnections {
    incoming: BTreeMap<CommunicatorPeerId, CancellationToken>,
}

impl IncomingConnections {
    fn new() -> Self {
        Self {
            incoming: BTreeMap::new(),
        }
    }

    /// Inserts the connection's cancellation token keyed by peer_id.
    /// Returns `false` if it was newly inserted, `true` if an existing entry was replaced.
    /// If replaced, the old connection is cancelled.
    pub fn insert(&mut self, conn: Connection) -> bool {
        match self.incoming.entry(conn.peer_id) {
            Entry::Vacant(v) => {
                v.insert(conn.cancel);
                false
            }
            Entry::Occupied(mut o) => {
                tracing::info!("replacing existing connection for peer {:?}", conn.peer_id); // todo: add targets
                // Cancel the previous connection for this peer.
                o.get().cancel();
                o.insert(conn.cancel);
                true
            }
        }
    }

    pub fn contains(&self, peer_id: CommunicatorPeerId) -> bool {
        self.incoming.contains_key(&peer_id)
    }
}

// note: duplex connection
async fn accept_connection(
    tls_acceptor: tokio_rustls::TlsAcceptor,
    tcp_stream: TcpStream,
    allowed_peer_keys: Arc<CommPeers>,
    message_sender: tokio::sync::mpsc::UnboundedSender<PeerMessage>,
    cancel: CancellationToken,
    connections: Arc<Mutex<IncomingConnections>>,
) -> anyhow::Result<()> {
    let (stream, conn) = tokio::select! {
        _ = cancel.cancelled() => {
            anyhow::bail!("cancelled");
    }
        res = async {
            let mut stream = tls_acceptor.accept(tcp_stream).await?;
            let common_state = stream.get_ref().1;
            let peer_pk = mpc_tls::tls::extract_public_key(common_state)?;
            let Some(peer_id) = allowed_peer_keys.is_allowed(&peer_pk) else {
                anyhow::bail!("peer is not in list of allowed peers.");
            };
            tracing::info!("Performing P2P handshake with: {:?}", peer_id);
            handshake(&mut stream, constants::HANDSHAKE_TIMEOUT)
                .await
                .context("p2p handshake")?;
            tracing::info!("(incoming) Concluded P2P handshake with: {:?}", peer_id);
            let cancel_recv = CancellationToken::new();
            Ok::<_, anyhow::Error>((stream, Connection{peer_id, cancel: cancel_recv}))
            } => res?,
    };
    connections.lock().await.insert(conn.clone());
    tokio::spawn(recv_loop(stream, conn.cancel, message_sender, conn.peer_id));
    Ok(())
}

async fn listen_incoming(
    tls_acceptor: tokio_rustls::TlsAcceptor,
    tcp_listener: tokio::net::TcpListener,
    allowed_peer_keys: Arc<CommPeers>,
    cancel: CancellationToken,
    connections: Arc<Mutex<IncomingConnections>>,
    message_sender: tokio::sync::mpsc::UnboundedSender<PeerMessage>,
) {
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
        let allowed = allowed_peer_keys.clone();
        let conns = connections.clone();
        let tx = message_sender.clone();
        let child = cancel.child_token();

        tokio::spawn(async move {
            if let Err(e) =
                accept_connection(tls_acceptor, tcp_stream, allowed, tx, child, conns).await
            {
                tracing::warn!(error=%e, "accept_connection failed");
            }
        });
    }
}

struct Server {
    server_config: Arc<rustls::server::ServerConfig>,
    my_port: u16,
    allowed_peer_keys: Arc<CommPeers>,
    cancel: CancellationToken,
    connections: Arc<Mutex<IncomingConnections>>,
}

impl Server {
    pub fn new(
        server_config: Arc<rustls::server::ServerConfig>,
        my_port: u16,
        allowed_peer_keys: Arc<CommPeers>,
        cancel: CancellationToken,
        connections: Arc<Mutex<IncomingConnections>>,
    ) -> Self {
        Server {
            server_config,
            my_port,
            allowed_peer_keys,
            cancel,
            connections,
        }
    }
    pub async fn listen(
        &mut self,
        message_sender: tokio::sync::mpsc::UnboundedSender<PeerMessage>,
    ) -> anyhow::Result<()> {
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(self.server_config.clone());
        let tcp_listener = tokio::net::TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(0, 0, 0, 0),
            self.my_port,
        )))
        .await
        .context("TCP bind")?;
        tokio::spawn(listen_incoming(
            tls_acceptor,
            tcp_listener,
            self.allowed_peer_keys.clone(),
            self.cancel.child_token(),
            self.connections.clone(),
            message_sender,
        ));
        Ok(())
    }
}
