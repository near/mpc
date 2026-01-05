use anyhow::{anyhow, Context};
use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::VerifyingKey;
use rustls::{ClientConfig, CommonState};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    config::MpcConfig,
    network::{
        conn::{
            AllNodeConnectivities, ConnectionVersion, NodeConnectivity, NodeConnectivityInterface,
        },
        constants::{MAX_MESSAGE_LEN, MESSAGE_READ_TIMEOUT_SECS},
        handshake::p2p_handshake,
        MeshNetworkTransportReceiver, MeshNetworkTransportSender,
    },
    primitives::{
        IndexerHeightMessage, MpcMessage, MpcPeerMessage, ParticipantId, PeerIndexerHeightMessage,
        PeerMessage,
    },
    tracking::{self, AutoAbortTask, AutoAbortTaskCollection},
};

/// This struct manages **outgoing connections only** - one persistent TLS connection to each
/// peer in the network. When the application wants to send a message to a peer, it queues the
/// message through the corresponding [`PersistentConnection`], which handles automatic
/// reconnection if the connection drops. Each connection runs two background tasks: one for
/// sending data, and one for sending 1-second interval ping heartbeats and monitoring pong responses.
///
/// Implements the [`MeshNetworkTransportSender`] trait to provide a high-level API for sending
/// messages (`.send()`, `.send_indexer_height()`) and checking connectivity status
/// (`.connectivity()`, `.wait_for_ready()`), while handling low-level connection management.
pub struct TlsMeshSender {
    /// The participant ID of this node.
    my_id: ParticipantId,
    /// List of all participant IDs in the network (including this node).
    participants: Vec<ParticipantId>,
    /// Outgoing connections to all peers (excludes this node). Each connection automatically
    /// retries on failure. This is where actual message sending happens - when you call
    /// `.send()`, it looks up the connection here and queues the message.
    connections: HashMap<ParticipantId, Arc<PersistentConnection>>,
    /// Tracks connection state (incoming and outgoing) for all peers. This is separate from
    /// `connections` because it monitors *both directions* - while `connections` only manages
    /// our outgoing connections, `connectivities` tracks whether both our outgoing connection
    /// to a peer AND their incoming connection to us are alive. Used by `.wait_for_ready()`
    /// and `.connectivity()` to check bidirectional connectivity status.
    connectivities: Arc<AllNodeConnectivities<TlsConnection, ()>>,
}

/// This struct manages **incoming connections only** - it accepts TLS connections from all
/// peers and multiplexes their messages into a single channel. The application calls
/// `.receive()` to get the next message from any peer. Each incoming connection runs its own
/// background task that reads from the TLS stream, handles Ping/Pong packets, and forwards
/// MPC/IndexerHeight messages to the unified receiver channel.
///
/// Ping/Pong handling uses cross-stream communication to maintain unidirectional I/O: when
/// receiving a Ping, this handler sends Pong via the outgoing connection to that peer; when
/// receiving a Pong, it notifies the outgoing connection's keepalive task via a watch channel.
///
/// Implements [`MeshNetworkTransportReceiver`] to receive messages from all peers in the
/// mesh network.
pub struct TlsMeshReceiver {
    /// Unified message queue receiving messages from all peers' incoming connections.
    /// When any peer sends us a message, it gets queued here. The application calls
    /// `.receive()` to dequeue the next message (which includes the sender's ID).
    receiver: UnboundedReceiver<PeerMessage>,
    /// Background task running the TCP acceptor loop on our listening port. It continuously
    /// accepts incoming TCP connections and spawns a new task for each one that:
    /// 1) Performs TLS handshake and authenticates the peer's identity
    /// 2) Registers the connection with `connectivities` for bidirectional tracking
    /// 3) Reads messages from the peer in a loop (read-only stream usage)
    /// 4) On Ping: Sends Pong via our outgoing connection to maintain unidirectional I/O
    /// 5) On Pong: Notifies the outgoing connection's keepalive task via watch channel
    /// 6) Forwards MpcMessage and IndexerHeight to the unified `receiver` channel
    ///
    /// The [`AutoAbortTask`] wrapper ensures automatic cleanup on drop.
    _incoming_connections_task: AutoAbortTask<()>,
}

/// Maps public keys to [`ParticipantId`]s for authenticating incoming connections.
///
/// This struct is populated at startup with the known public keys of all participants in the
/// network. When a peer establishes an incoming TLS connection, we extract their public key
/// from their TLS certificate and look it up in this map to determine their [`ParticipantId`].
/// This ensures that only known participants can connect, and we can correctly attribute
/// incoming messages to the right peer. If a connection presents an unknown public key, it is
/// rejected during the authentication phase.
#[derive(Default)]
struct ParticipantIdentities {
    key_to_participant_id: HashMap<VerifyingKey, ParticipantId>,
}

/// Maintains a persistent outgoing TLS connection to a single peer with automatic reconnection.
///
/// This struct wraps a [`TlsConnection`] and ensures it stays alive throughout the lifetime of
/// the node. If the underlying TCP/TLS connection drops (due to network issues, peer restart,
/// etc.), the background task automatically attempts to reconnect after a 1-second delay. Each
/// [`TlsMeshSender`] owns one `PersistentConnection` per peer in the network (N-1 total).
struct PersistentConnection {
    target_participant_id: ParticipantId,
    connectivity: Arc<NodeConnectivity<TlsConnection, ()>>,
    /// Channel for buffering Pongs when outgoing connection is temporarily unavailable.
    pong_buffer: UnboundedSender<u64>,
    /// Background reconnection task that maintains the connection lifecycle.
    ///
    /// This task runs an infinite loop that:
    /// 1. Attempts to establish a new [`TlsConnection`] to `target_participant_id`
    /// 2. On success: Registers the connection with `connectivity` and blocks waiting for it
    ///    to close (via `wait_for_close()`)
    /// 3. On failure: Logs the error and sleeps for [`CONNECTION_RETRY_DELAY`] before retrying
    /// 4. When a connection closes (step 2 completes): Loops back to step 1
    ///
    /// The task owns the active [`TlsConnection`] (wrapped in Arc), so when the task is
    /// aborted (via dropping this `PersistentConnection`), the connection is automatically
    /// cleaned up. The [`AutoAbortTask`] wrapper ensures the task is aborted when this struct
    /// is dropped, providing RAII-style cleanup on node shutdown.
    _task: AutoAbortTask<()>,
}

/// Represents an active outgoing TLS/TCP connection to a single peer participant.
///
/// This struct encapsulates a single established TCP connection with TLS encryption to one peer.
/// It uses **unidirectional I/O** - the TLS stream is write-only from this connection's
/// perspective. When you want to send a message to a peer, you queue it through the `sender`
/// channel, and the background `_sender_task` reads from the channel and writes to the TLS
/// stream. Pong responses arrive via the separate incoming connection and are forwarded to
/// the keepalive task via the `pong_tx` watch channel for health monitoring.
struct TlsConnection {
    /// Channel for queuing outbound packets ([`Packet::Ping`], [`Packet::MpcMessage`],
    /// [`Packet::IndexerHeight`]) to be sent.
    ///
    /// The application sends messages by calling `.send_mpc_message()` or `.send_indexer_height()`,
    /// which queue packets into this channel. The `_sender_task` continuously reads from the
    /// receiver end of this channel and writes packets to the TLS stream. This decouples message
    /// sending from I/O operations, allowing the application to queue messages without blocking
    /// on network writes.
    sender: UnboundedSender<Packet>,
    /// Background task that owns the TLS stream and handles write-only I/O operations.
    ///
    /// This task continuously reads packets from the `sender` channel and writes them to the
    /// TLS stream. The stream is used unidirectionally - only for sending. Connection health
    /// monitoring is handled by the keepalive task which cancels the `closed` token when
    /// a pong timeout occurs. When this task is aborted (via [`AutoAbortTask`] drop), it closes
    /// the underlying TLS/TCP stream, which triggers [`PersistentConnection`] to reconnect.
    _sender_task: AutoAbortTask<()>,
    /// Background task that sends Ping heartbeats and monitors Pong responses.
    ///
    /// This task sends a Ping with an incrementing sequence number and then waits for either a
    /// Pong response (via the `pong_tx` watch channel) or a timeout. When a Pong is received,
    /// it validates the sequence number, calculates RTT, and waits until [`Self::PING_INTERVAL`]
    /// (1 second) has elapsed since the ping was sent before sending the next one. If no Pong is
    /// received within [`Self::PONG_TIMEOUT`] (5 seconds), it closes the connection by cancelling
    /// the `closed` token. This ensures pings are sent at exactly 1-second intervals while only
    /// sending when the previous ping received a response.
    _keepalive_task: AutoAbortTask<()>,
    /// Watch channel sender for receiving pong notifications from the incoming connection handler.
    ///
    /// The incoming handler sends PongInfo when it receives a Pong packet. The keepalive task
    /// monitors this channel to detect connection health and calculate RTT. This enables clean
    /// async communication without mutexes.
    pong_tx: tokio::sync::watch::Sender<PongInfo>,
    /// Token that gets cancelled when the connection closes, allowing waiters to be notified.
    ///
    /// Used by [`PersistentConnection`] via the `wait_for_close()` method to block until the
    /// connection dies (either due to network failure, timeout, or intentional shutdown). When
    /// `_sender_task` exits, the [`DropToCancel`] guard automatically cancels this token,
    /// unblocking any tasks waiting on it.
    closed: CancellationToken,
}

/// Simple structure to cancel the CancellationToken when dropped.
struct DropToCancel(CancellationToken);

impl Drop for DropToCancel {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Information about the last received pong, sent via watch channel from incoming handler
/// to keepalive task for health monitoring.
#[derive(Clone, Copy)]
struct PongInfo {
    /// Sequence number of the most recent Pong received.
    seq: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
enum Packet {
    Ping(u64),
    Pong(u64),
    MpcMessage(MpcMessage),
    IndexerHeight(IndexerHeightMessage),
}

impl TlsConnection {
    /// Both sides of the connection must complete handshake within this time, or else
    /// the connection is considered not successful.
    const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

    /// If we don't receive a pong response within this time, consider the connection dead.
    const PONG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

    /// Interval between consecutive pings. A new ping is sent 1 second after the previous
    /// ping was sent, but only after receiving its pong response.
    const PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

    /// Makes a TLS/TCP connection to the given address, authenticating the
    /// other side as the given participant.
    async fn new(
        client_config: Arc<ClientConfig>,
        target_address: &str,
        target_participant_id: ParticipantId,
        participant_identities: &ParticipantIdentities,
    ) -> anyhow::Result<TlsConnection> {
        let conn = TcpStream::connect(target_address)
            .await
            .context("TCP connect")?;
        let mut tls_conn = tokio_rustls::TlsConnector::from(client_config)
            .connect("dummy".try_into().unwrap(), conn)
            .await
            .context("TLS connect")?;

        let peer_id = verify_peer_identity(tls_conn.get_ref().1, participant_identities)
            .context("Verify server identity")?;
        if peer_id != target_participant_id {
            anyhow::bail!(
                "Incorrect peer identity, expected {}, authenticated {}",
                target_participant_id,
                peer_id
            );
        }

        info!("Performing P2P handshake with: {:?}", target_address);
        p2p_handshake(&mut tls_conn, Self::HANDSHAKE_TIMEOUT)
            .await
            .context("p2p handshake")?;

        let (sender, mut receiver) = mpsc::unbounded_channel::<Packet>();
        let (pong_tx, mut pong_rx) = tokio::sync::watch::channel(PongInfo { seq: 0 });
        let closed = CancellationToken::new();
        let closed_clone = closed.clone();

        let sender_task = tracking::spawn_checked(
            &format!("TLS connection to {}", target_participant_id),
            async move {
                let _drop_to_cancel = DropToCancel(closed_clone);
                let mut sent_bytes: u64 = 0;
                loop {
                    tokio::select! {
                        data = receiver.recv() => {
                            let Some(data) = data else {
                                break;
                            };
                            let serialized = borsh::to_vec(&data)?;
                            let len: u32 = serialized.len().try_into().context("Message too long")?;
                            tls_conn.write_u32(len).await?;
                            tls_conn.write_all(&serialized).await?;
                            sent_bytes += 4 + len as u64;

                            tracking::set_progress(&format!("Sent {} bytes", sent_bytes));
                        }
                        _ = tls_conn.read_u8() => {
                            // We do not expect any data from the other side. However,
                            // selecting on it will quickly return error if the connection
                            // is broken before we have data to send. That way we can
                            // immediately quit the loop as soon as the connection is broken
                            // (so we can reconnect).
                            break;
                        }
                    }
                }
                anyhow::Ok(())
            },
        );
        let sender_clone = sender.clone();
        let closed_for_keepalive = closed.clone();
        let keepalive_task = tracking::spawn(
            &format!("Ping sender for {}", target_participant_id),
            async move {
                let mut seq: u64 = 0;
                let mut last_received_pong_seq: u64 = 0;
                loop {
                    seq += 1;
                    let ping_sent_at = Instant::now();
                    if sender_clone.send(Packet::Ping(seq)).is_err() {
                        // The receiver side will be dropped when the sender task is
                        // dropped (i.e. connection is closed).
                        break;
                    }

                    // Wait for either a pong response or timeout
                    tokio::select! {
                        _ = pong_rx.changed() => {
                            // Pong received, validate and calculate RTT
                            let pong_info = *pong_rx.borrow_and_update();
                            if pong_info.seq > last_received_pong_seq {
                                let expected_seq = last_received_pong_seq + 1;
                                if pong_info.seq != expected_seq {
                                    tracing::warn!(
                                        "Received pong {} from {}, expected {}, lost {} pong(s)",
                                        pong_info.seq, target_participant_id, expected_seq, pong_info.seq - expected_seq
                                    );
                                }
                                last_received_pong_seq = pong_info.seq;
                                let rtt = ping_sent_at.elapsed();
                                tracking::set_progress(&format!(
                                    "Received pong {} from {}, RTT: {:?}",
                                    pong_info.seq, target_participant_id, rtt
                                ));
                            } else {
                                tracing::debug!(
                                    "Received stale pong {} from {}, already received {}",
                                    pong_info.seq, target_participant_id, last_received_pong_seq
                                );
                            }
                            // Wait until PING_INTERVAL has elapsed since ping was sent
                            let elapsed = ping_sent_at.elapsed();
                            if elapsed < Self::PING_INTERVAL {
                                tokio::time::sleep(Self::PING_INTERVAL - elapsed).await;
                            }
                        }
                        _ = tokio::time::sleep(Self::PONG_TIMEOUT) => {
                            tracing::warn!(
                                "No pong received from {} for {:?}, closing connection",
                                target_participant_id,
                                Self::PONG_TIMEOUT
                            );
                            closed_for_keepalive.cancel();
                            break;
                        }
                    }
                }
            },
        );
        Ok(TlsConnection {
            sender,
            _sender_task: sender_task,
            _keepalive_task: keepalive_task,
            pong_tx,
            closed,
        })
    }

    async fn wait_for_close(&self) {
        self.closed.cancelled().await;
    }

    fn send_mpc_message(&self, msg: MpcMessage) -> anyhow::Result<()> {
        self.sender.send(Packet::MpcMessage(msg))?;
        Ok(())
    }

    fn send_indexer_height(&self, msg: IndexerHeightMessage) -> anyhow::Result<()> {
        self.sender.send(Packet::IndexerHeight(msg))?;
        Ok(())
    }
}

impl PersistentConnection {
    const CONNECTION_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

    /// Sends a message over the connection. If the connection was reset, fail.
    fn send_mpc_message(
        &self,
        expected_version: ConnectionVersion,
        msg: MpcMessage,
    ) -> anyhow::Result<()> {
        self.connectivity
            .outgoing_connection_asserting(expected_version)
            .with_context(|| format!("Cannot send MPC message to {}", self.target_participant_id))?
            .send_mpc_message(msg)
            .with_context(|| {
                format!("Cannot send MPC message to {}", self.target_participant_id)
            })?;
        Ok(())
    }

    /// Sends a message over the connection. This is done on a best-effort basis.
    fn send_indexer_height(&self, height: IndexerHeightMessage) {
        if let Some(conn) = self.connectivity.any_outgoing_connection() {
            let _ = conn.send_indexer_height(height);
        }
    }

    pub fn new(
        client_config: Arc<ClientConfig>,
        my_id: ParticipantId,
        target_address: String,
        target_participant_id: ParticipantId,
        participant_identities: Arc<ParticipantIdentities>,
        connectivity: Arc<NodeConnectivity<TlsConnection, ()>>,
    ) -> anyhow::Result<PersistentConnection> {
        let connectivity_clone = connectivity.clone();
        let (pong_buffer_tx, mut pong_buffer_rx) = mpsc::unbounded_channel::<u64>();
        let task = tracking::spawn(
            &format!("Persistent connection to {}", target_participant_id),
            async move {
                loop {
                    let new_conn = match TlsConnection::new(
                        client_config.clone(),
                        &target_address,
                        target_participant_id,
                        &participant_identities,
                    )
                    .await
                    {
                        Ok(new_conn) => {
                            tracing::info!(
                                "Outgoing {} --> {} connected",
                                my_id,
                                target_participant_id
                            );
                            Arc::new(new_conn)
                        }
                        Err(e) => {
                            tracing::info!(
                                "Could not connect to {}, retrying: {}, me {}",
                                target_participant_id,
                                e,
                                my_id
                            );
                            // Don't immediately retry, to avoid spamming the network with
                            // connection attempts.
                            tokio::time::sleep(Self::CONNECTION_RETRY_DELAY).await;
                            continue;
                        }
                    };
                    connectivity.set_outgoing_connection(&new_conn);

                    // Drain buffered Pongs and send them now that connection is available
                    while let Ok(seq) = pong_buffer_rx.try_recv() {
                        let _ = new_conn.sender.send(Packet::Pong(seq));
                    }

                    new_conn.wait_for_close().await;
                }
            },
        );
        Ok(PersistentConnection {
            target_participant_id,
            connectivity: connectivity_clone,
            pong_buffer: pong_buffer_tx,
            _task: task,
        })
    }
}

/// Creates a mesh network using TLS over TCP for communication.
pub async fn new_tls_mesh_network(
    config: &MpcConfig,
    p2p_private_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<(
    impl MeshNetworkTransportSender,
    impl MeshNetworkTransportReceiver,
)> {
    let (server_config, client_config) = mpc_tls::tls::configure_tls(p2p_private_key)?;

    let my_port = config
        .participants
        .participants
        .iter()
        .find(|participant| participant.id == config.my_participant_id)
        .map(|participant| participant.port)
        .ok_or_else(|| anyhow!("My ID not found in participants"))?;

    info!("Preparing participant data.");
    // Prepare participant data.
    let mut participant_identities = ParticipantIdentities::default();
    let mut connections = HashMap::new();
    let connectivities = Arc::new(AllNodeConnectivities::new(
        config.my_participant_id,
        &config
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .collect::<Vec<_>>(),
    ));
    for participant in &config.participants.participants {
        if participant.id == config.my_participant_id {
            continue;
        }
        participant_identities
            .key_to_participant_id
            .insert(participant.p2p_public_key, participant.id);
    }
    let participant_identities = Arc::new(participant_identities);
    let client_config = Arc::new(client_config);
    for participant in &config.participants.participants {
        if participant.id == config.my_participant_id {
            continue;
        }
        connections.insert(
            participant.id,
            Arc::new(PersistentConnection::new(
                client_config.clone(),
                config.my_participant_id,
                format!("{}:{}", participant.address, participant.port),
                participant.id,
                participant_identities.clone(),
                connectivities.get(participant.id)?,
            )?),
        );
    }

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let (message_sender, message_receiver) = mpsc::unbounded_channel();
    let tcp_listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(0, 0, 0, 0),
        my_port,
    )))
    .await
    .context("TCP bind")?;

    let connectivities_clone = connectivities.clone();
    let my_id = config.my_participant_id;
    let connections_for_incoming = connections.clone();
    info!("Spawning incoming connections handler.");
    let incoming_connections_task = tracking::spawn("Handle incoming connections", async move {
        let mut tasks = AutoAbortTaskCollection::new();
        while let Ok((tcp_stream, _)) = tcp_listener.accept().await {
            let message_sender = message_sender.clone();
            let participant_identities = participant_identities.clone();
            let tls_acceptor = tls_acceptor.clone();
            let connectivities = connectivities_clone.clone();
            let connections = connections_for_incoming.clone();
            tasks.spawn_checked::<_, ()>("Handle connection", async move {
                let mut stream = tls_acceptor.accept(tcp_stream).await?;
                let peer_id = verify_peer_identity(stream.get_ref().1, &participant_identities)?;
                tracking::set_progress(&format!("Authenticated as {}", peer_id));
                p2p_handshake(&mut stream, TlsConnection::HANDSHAKE_TIMEOUT)
                    .await
                    .context("p2p handshake")?;
                tracing::info!("Incoming {} <-- {} connected", my_id, peer_id);
                let incoming_conn = Arc::new(());
                connectivities
                    .get(peer_id)?
                    .set_incoming_connection(&incoming_conn);
                let mut received_bytes: u64 = 0;
                loop {
                    let len = tokio::time::timeout(
                        std::time::Duration::from_secs(MESSAGE_READ_TIMEOUT_SECS),
                        stream.read_u32(),
                    )
                    .await??;
                    if len >= MAX_MESSAGE_LEN {
                        anyhow::bail!("Message too long");
                    }
                    let mut buf = vec![0; len as usize];
                    tokio::time::timeout(
                        std::time::Duration::from_secs(MESSAGE_READ_TIMEOUT_SECS),
                        stream.read_exact(&mut buf),
                    )
                    .await??;
                    received_bytes += 4 + len as u64;

                    let packet =
                        Packet::try_from_slice(&buf).context("Failed to deserialize packet")?;
                    match packet {
                        Packet::Ping(seq) => {
                            // Send Pong via our outgoing connection to the peer, maintaining
                            // unidirectional I/O design. If outgoing isn't ready, buffer the Pong.
                            if let Some(conn) = connections.get(&peer_id) {
                                if let Some(outgoing_conn) =
                                    conn.connectivity.any_outgoing_connection()
                                {
                                    if outgoing_conn.sender.send(Packet::Pong(seq)).is_err() {
                                        tracing::info!(
                                            "Outgoing connection to {} is dead, closing incoming connection for clean reconnect",
                                            peer_id
                                        );
                                        break;
                                    }
                                } else {
                                    // Outgoing connection not ready yet, buffer the Pong
                                    if conn.pong_buffer.send(seq).is_err() {
                                        tracing::warn!(
                                            "Cannot buffer Pong({}) for {}: pong buffer channel closed",
                                            seq, peer_id
                                        );
                                    }
                                }
                            } else {
                                tracing::warn!(
                                    "Cannot send Pong({}) to {}: connection not found in HashMap",
                                    seq, peer_id
                                );
                            }
                        }
                        Packet::Pong(seq) => {
                            // Notify the keepalive task of the pong via the watch channel
                            if let Some(conn) = connections.get(&peer_id) {
                                if let Some(outgoing_conn) =
                                    conn.connectivity.any_outgoing_connection()
                                {
                                    // Send the new pong info via watch channel
                                    let _ = outgoing_conn.pong_tx.send(PongInfo { seq });
                                } else {
                                    tracing::warn!("No outgoing connection to {} to forward Pong({})", peer_id, seq);
                                }
                            } else {
                                tracing::warn!("No connection found for peer {} to forward Pong({})", peer_id, seq);
                            }
                        }
                        Packet::MpcMessage(mpc_message) => {
                            message_sender.send(PeerMessage::Mpc(MpcPeerMessage {
                                from: peer_id,
                                message: mpc_message,
                            }))?;
                        }
                        Packet::IndexerHeight(message) => {
                            message_sender.send(PeerMessage::IndexerHeight(
                                PeerIndexerHeightMessage {
                                    from: peer_id,
                                    message,
                                },
                            ))?;
                        }
                    }

                    tracking::set_progress(&format!(
                        "Received {} bytes from {}",
                        received_bytes, peer_id
                    ));
                }
                anyhow::Ok(())
            });
        }
    });

    let sender = TlsMeshSender {
        my_id: config.my_participant_id,
        participants: config
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .collect(),
        connections,
        connectivities,
    };

    let receiver = TlsMeshReceiver {
        receiver: message_receiver,
        _incoming_connections_task: incoming_connections_task,
    };

    Ok((sender, receiver))
}

fn verify_peer_identity(
    conn: &CommonState,
    participant_identities: &ParticipantIdentities,
) -> anyhow::Result<ParticipantId> {
    let public_key = mpc_tls::tls::extract_public_key(conn)?;
    let Some(peer_id) = participant_identities
        .key_to_participant_id
        .get(&public_key)
    else {
        anyhow::bail!("Connection with unknown public key");
    };
    Ok(*peer_id)
}

#[async_trait::async_trait]
impl MeshNetworkTransportSender for TlsMeshSender {
    fn my_participant_id(&self) -> ParticipantId {
        self.my_id
    }

    fn all_participant_ids(&self) -> Vec<ParticipantId> {
        self.participants.clone()
    }

    fn connectivity(&self, participant_id: ParticipantId) -> Arc<dyn NodeConnectivityInterface> {
        self.connectivities.get(participant_id).unwrap().clone()
    }

    fn send(
        &self,
        recipient_id: ParticipantId,
        message: MpcMessage,
        connection_version: ConnectionVersion,
    ) -> anyhow::Result<()> {
        self.connections
            .get(&recipient_id)
            .ok_or_else(|| anyhow!("Recipient not found"))?
            .send_mpc_message(connection_version, message)
            .with_context(|| format!("Cannot send MPC message to recipient {}", recipient_id))?;
        Ok(())
    }

    fn send_indexer_height(&self, height: IndexerHeightMessage) {
        for conn in self.connections.values() {
            conn.send_indexer_height(height.clone());
        }
    }

    async fn wait_for_ready(
        &self,
        threshold: usize,
        peers_to_consider: &[ParticipantId],
    ) -> anyhow::Result<()> {
        self.connectivities
            .wait_for_ready(threshold, peers_to_consider)
            .await;
        Ok(())
    }
}

#[async_trait]
impl MeshNetworkTransportReceiver for TlsMeshReceiver {
    async fn receive(&mut self) -> anyhow::Result<PeerMessage> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| anyhow!("Channel closed"))
    }
}

// TODO(#1675): move this inside test feature
pub mod testing {
    use crate::config::{MpcConfig, ParticipantInfo, ParticipantsConfig};
    use crate::primitives::ParticipantId;
    use ed25519_dalek::SigningKey;
    use near_account_id::AccountId;
    use rand::rngs::OsRng;

    /// A unique seed for each integration test to avoid port conflicts during testing.
    #[derive(Copy, Clone)]
    pub struct PortSeed {
        port_number: u16,
        case: u16,
    }

    impl PortSeed {
        // The base port number used, hoping the OS is not using ports in this range
        pub const BASE_PORT: u16 = 10000;
        // This constant must be equal to the total number of ports defined below
        pub const TOTAL_DEFINED_PORTS: u16 = 19;
        // Maximum number of nodes that can be handled without port collisions
        pub const MAX_NODES: u16 = 10;
        // Maximum number of cases that can be handled without port collisions
        pub const MAX_CASES: u16 = 4;
        // Each function below corresponds to a port per node. Each defines an offset,
        // and all offsets must be different
        pub const TOTAL_PORTS_PER_NODE: u16 = 3;

        pub const fn new(port_number: u16) -> Self {
            Self {
                port_number,
                case: 0,
            }
        }

        pub fn with_case(&self, case: u16) -> Self {
            Self {
                port_number: self.port_number,
                case,
            }
        }

        fn compute_port(&self, node_index: u16, offset: u16) -> u16 {
            Self::BASE_PORT
                + self.port_number * Self::MAX_NODES * Self::MAX_CASES * Self::TOTAL_PORTS_PER_NODE
                + node_index * Self::MAX_CASES * Self::TOTAL_PORTS_PER_NODE
                + self.case * Self::TOTAL_PORTS_PER_NODE
                + offset
        }

        pub fn p2p_port(&self, node_index: usize) -> u16 {
            self.compute_port(node_index as u16, 0)
        }

        pub fn web_port(&self, node_index: usize) -> u16 {
            self.compute_port(node_index as u16, 1)
        }

        pub fn migration_web_port(&self, node_index: usize) -> u16 {
            self.compute_port(node_index as u16, 2)
        }

        pub const CLI_FOR_PYTEST: Self = Self::new(0);
    }

    #[cfg(any(test, feature = "test-utils"))]
    impl PortSeed {
        // Each place that passes a PortSeed in should define a unique one here.
        pub const P2P_BASIC_TEST: Self = Self::new(1);
        pub const P2P_WAIT_FOR_READY_TEST: Self = Self::new(2);
        pub const BASIC_CLUSTER_TEST: Self = Self::new(3);
        pub const FAULTY_CLUSTER_TEST: Self = Self::new(4);
        pub const KEY_RESHARING_SIMPLE_TEST: Self = Self::new(5);
        pub const KEY_RESHARING_MULTISTAGE_TEST: Self = Self::new(6);
        pub const KEY_RESHARING_SIGNATURE_BUFFERING_TEST: Self = Self::new(7);
        pub const BASIC_MULTIDOMAIN_TEST: Self = Self::new(8);
        pub const FAULTY_STUCK_INDEXER_TEST: Self = Self::new(9);
        pub const RECOVERY_TEST: Self = Self::new(10);
        pub const ONBOARDING_TEST: Self = Self::new(11);
        pub const MIGRATION_WEBSERVER_SUCCESS_TEST: Self = Self::new(12);
        pub const MIGRATION_WEBSERVER_FAILURE_TEST: Self = Self::new(13);
        pub const MIGRATION_WEBSERVER_SUCCESS_TEST_GET_KEYSHARES: Self = Self::new(14);
        pub const MIGRATION_WEBSERVER_SUCCESS_TEST_SET_KEYSHARES: Self = Self::new(15);
        pub const MIGRATION_WEBSERVER_CHANGE_MIGRATION_INFO: Self = Self::new(16);
        pub const BACKUP_CLI_WEBSERVER_GET_KEYSHARES: Self = Self::new(17);
        pub const BACKUP_CLI_WEBSERVER_PUT_KEYSHARES: Self = Self::new(18);
    }

    pub fn generate_test_p2p_configs(
        participant_accounts: &[AccountId],
        threshold: usize,
        // this is a hack to make sure that when tests run in parallel, they don't
        // collide on the same port.
        port_seed: PortSeed,
        // Supply `Some` value here if you want to use pre-existing p2p key pairs
        p2p_keypairs: Option<Vec<SigningKey>>,
    ) -> anyhow::Result<Vec<(MpcConfig, SigningKey)>> {
        let p2p_keypairs = if let Some(p2p_keypairs) = p2p_keypairs {
            p2p_keypairs
        } else {
            participant_accounts
                .iter()
                .map(|_account_id| SigningKey::generate(&mut OsRng))
                .collect::<Vec<_>>()
        };
        let mut participants = Vec::new();
        for (i, (participant_account, p2p_signing_key)) in participant_accounts
            .iter()
            .zip(p2p_keypairs.iter())
            .enumerate()
        {
            participants.push(ParticipantInfo {
                id: ParticipantId::from_raw(rand::random()),
                address: "127.0.0.1".to_string(),
                port: port_seed.p2p_port(i),
                p2p_public_key: p2p_signing_key.verifying_key(),
                near_account_id: participant_account.clone(),
            });
        }

        let mut configs = Vec::new();
        for (i, singing_key) in p2p_keypairs.into_iter().enumerate() {
            let participants = ParticipantsConfig {
                threshold: threshold as u64,
                participants: participants.clone(),
            };

            let mpc_config = MpcConfig {
                my_participant_id: participants.participants[i].id,
                participants,
            };
            configs.push((mpc_config, singing_key));
        }

        Ok(configs)
    }
}

#[cfg(test)]
mod tests {
    use crate::cli::LogFormat;
    use crate::config::MpcConfig;
    use crate::network::{MeshNetworkTransportReceiver, MeshNetworkTransportSender};
    use crate::p2p::testing::{generate_test_p2p_configs, PortSeed};
    use crate::primitives::{
        ChannelId, MpcMessage, MpcStartMessage, MpcTaskId, ParticipantId, PeerMessage, UniqueId,
    };
    use crate::providers::EcdsaTaskId;
    use crate::tracing::init_logging;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use mpc_contract::primitives::domain::DomainId;
    use mpc_contract::primitives::key_state::{AttemptId, EpochId, KeyEventId};
    use rand::Rng;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_basic_tls_mesh_network() {
        init_logging(LogFormat::Plain);
        let configs = generate_test_p2p_configs(
            &["test0".parse().unwrap(), "test1".parse().unwrap()],
            2,
            PortSeed::P2P_BASIC_TEST,
            None,
        )
        .unwrap();
        let participant0 = configs[0].0.my_participant_id;
        let participant1 = configs[1].0.my_participant_id;

        let all_participants = [participant0, participant1];

        start_root_task_with_periodic_dump(async move {
            let (sender0, mut receiver0) =
                super::new_tls_mesh_network(&configs[0].0, &configs[0].1)
                    .await
                    .unwrap();
            let (sender1, mut receiver1) =
                super::new_tls_mesh_network(&configs[1].0, &configs[1].1)
                    .await
                    .unwrap();

            sender0.wait_for_ready(2, &all_participants).await.unwrap();
            sender1.wait_for_ready(2, &all_participants).await.unwrap();

            for _ in 0..100 {
                // todo: adjust test?
                let domain_id = rand::thread_rng().gen();
                let epoch_id = rand::thread_rng().gen();
                let n_attempts = rand::thread_rng().gen::<usize>() % 100;
                let mut attempt_id = AttemptId::new();
                for _ in 0..n_attempts {
                    attempt_id = attempt_id.next();
                }
                let channel_id = ChannelId(UniqueId::generate(participant0));
                let key_id =
                    KeyEventId::new(EpochId::new(epoch_id), DomainId(domain_id), attempt_id);
                let msg0to1 = MpcMessage {
                    channel_id,
                    kind: crate::primitives::MpcMessageKind::Start(MpcStartMessage {
                        task_id: MpcTaskId::EcdsaTaskId(EcdsaTaskId::KeyResharing {
                            key_event: key_id,
                        }),
                        participants: vec![participant0, participant1],
                    }),
                };
                sender0
                    .send(
                        participant1,
                        msg0to1.clone(),
                        sender0.connectivity(participant1).connection_version(),
                    )
                    .unwrap();
                let PeerMessage::Mpc(msg) = receiver1.receive().await.unwrap() else {
                    panic!("Expected MPC message");
                };
                assert_eq!(msg.from, participant0);
                assert_eq!(msg.message, msg0to1);

                let msg1to0 = MpcMessage {
                    channel_id,
                    kind: crate::primitives::MpcMessageKind::Abort("test".to_owned()),
                };
                sender1
                    .send(
                        participant0,
                        msg1to0.clone(),
                        sender1.connectivity(participant0).connection_version(),
                    )
                    .unwrap();

                let PeerMessage::Mpc(msg) = receiver0.receive().await.unwrap() else {
                    panic!("Expected MPC message");
                };
                assert_eq!(msg.from, participant1);
                assert_eq!(msg.message, msg1to0);
            }
        })
        .await;
    }

    fn all_alive_participant_ids(sender: &impl MeshNetworkTransportSender) -> Vec<ParticipantId> {
        let mut result = Vec::new();
        for participant in sender.all_participant_ids() {
            if participant == sender.my_participant_id() {
                continue;
            }
            if sender
                .connectivity(participant)
                .is_bidirectionally_connected()
            {
                result.push(participant);
            }
        }
        result.push(sender.my_participant_id());
        result.sort();
        result
    }

    #[tokio::test]
    async fn test_wait_for_ready() {
        init_logging(LogFormat::Plain);
        let mut configs = generate_test_p2p_configs(
            &[
                "test0".parse().unwrap(),
                "test1".parse().unwrap(),
                "test2".parse().unwrap(),
                "test3".parse().unwrap(),
            ],
            4,
            PortSeed::P2P_WAIT_FOR_READY_TEST,
            None,
        )
        .unwrap();

        let all_participants = |mpc_config: &MpcConfig| {
            mpc_config
                .participants
                .participants
                .iter()
                .map(|p| p.id)
                .collect::<Vec<_>>()
        };

        // Make node 3 use the wrong address for the 0th node. All connections should work
        // except from 3 to 0.
        configs[3].0.participants.participants[0].address = "169.254.1.1".to_owned();
        start_root_task_with_periodic_dump(async move {
            let (sender0, _receiver0) = super::new_tls_mesh_network(&configs[0].0, &configs[0].1)
                .await
                .unwrap();
            let (sender1, receiver1) = super::new_tls_mesh_network(&configs[1].0, &configs[1].1)
                .await
                .unwrap();
            let (sender2, _receiver2) = super::new_tls_mesh_network(&configs[2].0, &configs[2].1)
                .await
                .unwrap();
            let (sender3, _receiver3) = super::new_tls_mesh_network(&configs[3].0, &configs[3].1)
                .await
                .unwrap();

            let all_participants0 = &all_participants(&configs[0].0);
            let all_participants1 = &all_participants(&configs[1].0);
            let all_participants2 = &all_participants(&configs[2].0);
            let all_participants3 = &all_participants(&configs[3].0);

            sender1.wait_for_ready(4, all_participants1).await.unwrap();
            sender2.wait_for_ready(4, all_participants2).await.unwrap();
            // Node 3 should not be able to connect to node 0, so if we wait for 4,
            // it should fail. This goes both ways (3 to 0 and 0 to 3).
            assert!(timeout(
                Duration::from_secs(1),
                sender0.wait_for_ready(4, all_participants0)
            )
            .await
            .is_err());
            assert!(timeout(
                Duration::from_secs(1),
                sender3.wait_for_ready(4, all_participants3)
            )
            .await
            .is_err());

            // But if we wait for 3, it should succeed.
            sender0.wait_for_ready(3, all_participants0).await.unwrap();
            sender3.wait_for_ready(3, all_participants3).await.unwrap();

            let ids: Vec<_> = configs[0]
                .0
                .participants
                .participants
                .iter()
                .map(|p| p.id)
                .collect();
            assert_eq!(
                all_alive_participant_ids(&sender0),
                sorted(&[ids[0], ids[1], ids[2]]),
            );
            assert_eq!(all_alive_participant_ids(&sender1), sorted(&ids));
            assert_eq!(all_alive_participant_ids(&sender2), sorted(&ids));
            assert_eq!(
                all_alive_participant_ids(&sender3),
                sorted(&[ids[1], ids[2], ids[3]]),
            );

            // Disconnect node 1. Other nodes should notice the change.
            drop((sender1, receiver1));
            tokio::time::sleep(Duration::from_secs(2)).await;
            assert_eq!(
                all_alive_participant_ids(&sender0),
                sorted(&[ids[0], ids[2]])
            );
            assert_eq!(
                all_alive_participant_ids(&sender2),
                sorted(&[ids[0], ids[2], ids[3]])
            );
            assert_eq!(
                all_alive_participant_ids(&sender3),
                sorted(&[ids[2], ids[3]])
            );

            // Reconnect node 1. Other nodes should re-establish the connections.
            let (sender1, _receiver1) = super::new_tls_mesh_network(&configs[1].0, &configs[1].1)
                .await
                .unwrap();
            sender0.wait_for_ready(3, all_participants0).await.unwrap();
            sender1.wait_for_ready(4, all_participants1).await.unwrap();
            sender2.wait_for_ready(4, all_participants2).await.unwrap();
            sender3.wait_for_ready(3, all_participants3).await.unwrap();
            assert_eq!(
                all_alive_participant_ids(&sender0),
                sorted(&[ids[0], ids[1], ids[2]]),
            );
            assert_eq!(all_alive_participant_ids(&sender1), sorted(&ids));
            assert_eq!(all_alive_participant_ids(&sender2), sorted(&ids));
            assert_eq!(
                all_alive_participant_ids(&sender3),
                sorted(&[ids[1], ids[2], ids[3]]),
            );
        })
        .await;
    }

    fn sorted(ids: &[ParticipantId]) -> Vec<ParticipantId> {
        let mut ids = ids.to_vec();
        ids.sort();
        ids
    }
}
