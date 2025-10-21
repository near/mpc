use crate::config::MpcConfig;
use crate::network::conn::{
    AllNodeConnectivities, ConnectionVersion, NodeConnectivity, NodeConnectivityInterface,
};
use crate::network::constants::{MAX_MESSAGE_LEN, MESSAGE_READ_TIMEOUT_SECS};
use crate::network::handshake::p2p_handshake;
use crate::network::{MeshNetworkTransportReceiver, MeshNetworkTransportSender};
use crate::primitives::{
    IndexerHeightMessage, MpcMessage, MpcPeerMessage, ParticipantId, PeerIndexerHeightMessage,
    PeerMessage,
};
use crate::tracking::{self, AutoAbortTask, AutoAbortTaskCollection};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::VerifyingKey;
use rustls::{ClientConfig, CommonState};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Implements MeshNetworkTransportSender for sending messages over a TLS-based
/// mesh network.
pub struct TlsMeshSender {
    my_id: ParticipantId,
    participants: Vec<ParticipantId>,
    connections: HashMap<ParticipantId, Arc<PersistentConnection>>,
    connectivities: Arc<AllNodeConnectivities<TlsConnection, ()>>,
}

/// Implements MeshNetworkTransportReceiver.
pub struct TlsMeshReceiver {
    receiver: UnboundedReceiver<PeerMessage>,
    _incoming_connections_task: AutoAbortTask<()>,
}

/// Maps public keys to participant IDs. Used to identify incoming connections.
#[derive(Default)]
struct ParticipantIdentities {
    key_to_participant_id: HashMap<VerifyingKey, ParticipantId>,
}

/// A retrying connection that will automatically reconnect if the TCP
/// connection is broken.
struct PersistentConnection {
    target_participant_id: ParticipantId,
    connectivity: Arc<NodeConnectivity<TlsConnection, ()>>,
    // The task that loops to connect to the target. When `PersistentConnection`
    // is dropped, this task is aborted. The task owns any active connection,
    // so dropping it also frees any connection currently alive.
    _task: AutoAbortTask<()>,
}

/// State for a single TLS/TCP connection to one participant. We only ever send
/// messages through this connection, so there is nothing to handle receiving.
/// Dropping this struct will automatically close the connection.
struct TlsConnection {
    /// Used to send messages via the connection.
    sender: UnboundedSender<Packet>,
    /// Task that reads messages from the channel (other side of `sender`) and
    /// sends it over the TLS connection. This task owns the connection, so
    /// dropping it closes the connection.
    _sender_task: AutoAbortTask<()>,
    /// Task that periodically sends a Ping message to the other side. It does
    /// not expect a Pong, it simply keeps the connection alive (so we can
    /// quickly detect if the connection is broken).
    _keepalive_task: AutoAbortTask<()>,
    /// This is cancelled when the connection is closed. Used to wait for the
    /// connection to close.
    closed: CancellationToken,
}

/// Simple structure to cancel the CancellationToken when dropped.
struct DropToCancel(CancellationToken);

impl Drop for DropToCancel {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
enum Packet {
    Ping,
    MpcMessage(MpcMessage),
    IndexerHeight(IndexerHeightMessage),
}

impl TlsConnection {
    /// Both sides of the connection must complete handshake within this time, or else
    /// the connection is considered not successful.
    const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

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
        let keepalive_task = tracking::spawn(
            &format!("TCP keepalive for {}", target_participant_id),
            async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    if sender_clone.send(Packet::Ping).is_err() {
                        // The receiver side will be dropped when the sender task is
                        // dropped (i.e. connection is closed).
                        break;
                    }
                }
            },
        );
        Ok(TlsConnection {
            sender,
            _sender_task: sender_task,
            _keepalive_task: keepalive_task,
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
                            new_conn
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
                    let new_conn = Arc::new(new_conn);
                    connectivity.set_outgoing_connection(&new_conn);
                    new_conn.wait_for_close().await;
                }
            },
        );
        Ok(PersistentConnection {
            target_participant_id,
            connectivity: connectivity_clone,
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
    info!("Spawning incoming connections handler.");
    let incoming_connections_task = tracking::spawn("Handle incoming connections", async move {
        let mut tasks = AutoAbortTaskCollection::new();
        while let Ok((tcp_stream, _)) = tcp_listener.accept().await {
            let message_sender = message_sender.clone();
            let participant_identities = participant_identities.clone();
            let tls_acceptor = tls_acceptor.clone();
            let connectivities = connectivities_clone.clone();
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
                        Packet::Ping => {
                            // Do nothing. Pings are just for TCP keepalive.
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

pub mod testing {
    use crate::config::{MpcConfig, ParticipantInfo, ParticipantsConfig};
    use crate::primitives::ParticipantId;
    use ed25519_dalek::SigningKey;
    use near_sdk::AccountId;
    use rand::rngs::OsRng;

    /// A unique seed for each integration test to avoid port conflicts during testing.
    #[derive(Copy, Clone)]
    pub struct PortSeed(u16);

    impl PortSeed {
        pub fn p2p_port(&self, node_index: usize) -> u16 {
            (10000_usize + self.0 as usize * 100 + node_index)
                .try_into()
                .unwrap()
        }

        pub fn web_port(&self, node_index: usize) -> u16 {
            (20000_usize + self.0 as usize * 100 + node_index)
                .try_into()
                .unwrap()
        }

        pub fn migration_web_port(&self, node_index: usize) -> u16 {
            (30000_usize + self.0 as usize * 100 + node_index)
                .try_into()
                .unwrap()
        }

        pub const CLI_FOR_PYTEST: Self = Self(0);
    }

    #[cfg(any(test, feature = "test-utils"))]
    impl PortSeed {
        // Each place that passes a PortSeed in should define a unique one here.
        pub const P2P_BASIC_TEST: Self = Self(1);
        pub const P2P_WAIT_FOR_READY_TEST: Self = Self(2);
        pub const BASIC_CLUSTER_TEST: Self = Self(3);
        pub const FAULTY_CLUSTER_TEST: Self = Self(4);
        pub const KEY_RESHARING_SIMPLE_TEST: Self = Self(5);
        pub const KEY_RESHARING_MULTISTAGE_TEST: Self = Self(6);
        pub const KEY_RESHARING_SIGNATURE_BUFFERING_TEST: Self = Self(7);
        pub const BASIC_MULTIDOMAIN_TEST: Self = Self(8);
        pub const FAULTY_STUCK_INDEXER_TEST: Self = Self(9);
        pub const RECOVERY_TEST: Self = Self(10);
        pub const ONBOARDING_TEST: Self = Self(11);
        pub const MIGRATION_WEBSERVER_SUCCESS_TEST: Self = Self(12);
        pub const MIGRATION_WEBSERVER_FAILURE_TEST: Self = Self(13);
        pub const MIGRATION_WEBSERVER_SUCCESS_TEST_GET_KEYSHARES: Self = Self(14);
        pub const MIGRATION_WEBSERVER_SUCCESS_TEST_SET_KEYSHARES: Self = Self(15);
        pub const MIGRATION_WEBSERVER_CHANGE_MIGRATION_INFO: Self = Self(16);
        pub const BACKUP_CLI_WEBSERVER_GET_KEYSHARES: Self = Self(17);
        pub const BACKUP_CLI_WEBSERVER_PUT_KEYSHARES: Self = Self(18);
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
