use crate::network::conn::{ConnectionVersion, NodeConnectivity};
use crate::network::handshake::p2p_handshake;
use crate::p2p::certificate::verify_peer_identity;
use crate::primitives::{IndexerHeightMessage, MpcMessage, ParticipantId};
use crate::tracking::{self, AutoAbortTask};
use anyhow::Context;
use borsh::{BorshDeserialize, BorshSerialize};
use rustls::ClientConfig;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_util::sync::CancellationToken;
use tracing::info;

use super::participants::ParticipantIdentities;

/// A retrying connection that will automatically reconnect if the TCP
/// connection is broken.
pub(crate) struct PersistentConnection {
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
pub(crate) struct TlsConnection {
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
pub(crate) enum Packet {
    Ping,
    MpcMessage(MpcMessage),
    IndexerHeight(IndexerHeightMessage),
}

impl TlsConnection {
    /// Both sides of the connection must complete handshake within this time, or else
    /// the connection is considered not successful.
    pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

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
    pub(crate) fn send_mpc_message(
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
    pub(crate) fn send_indexer_height(&self, height: IndexerHeightMessage) {
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

#[cfg(test)]
mod tests {
    use crate::cli::LogFormat;
    use crate::config::MpcConfig;
    use crate::network::MeshNetworkTransportSender;
    use crate::p2p::mesh::new_tls_mesh_network;
    use crate::p2p::testing::{generate_test_p2p_configs, PortSeed};
    use crate::primitives::ParticipantId;
    use crate::tracing::init_logging;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use std::time::Duration;
    use tokio::time::timeout;

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
            let (sender0, _receiver0) = new_tls_mesh_network(&configs[0].0, &configs[0].1)
                .await
                .unwrap();
            let (sender1, receiver1) = new_tls_mesh_network(&configs[1].0, &configs[1].1)
                .await
                .unwrap();
            let (sender2, _receiver2) = new_tls_mesh_network(&configs[2].0, &configs[2].1)
                .await
                .unwrap();
            let (sender3, _receiver3) = new_tls_mesh_network(&configs[3].0, &configs[3].1)
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
            let (sender1, _receiver1) = new_tls_mesh_network(&configs[1].0, &configs[1].1)
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
