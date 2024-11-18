use crate::config::{MpcConfig, ParticipantInfo, ParticipantsConfig, SecretsConfig};
use crate::network::{MeshNetworkTransportReceiver, MeshNetworkTransportSender};
use crate::primitives::{MpcMessage, MpcPeerMessage, ParticipantId};
use crate::tracking;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use borsh::BorshDeserialize;
use futures::lock::Mutex;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::quic::Suite;
use rustls::server::danger::ClientCertVerifier;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

/// Implements MeshNetworkTransportSender for sending messages over a QUIC-based
/// mesh network.
pub struct QuicMeshSender {
    my_id: ParticipantId,
    participants: Vec<ParticipantId>,
    connections: HashMap<ParticipantId, Arc<PersistentConnection>>,
}

/// Implements MeshNetworkTransportReceiver.
pub struct QuicMeshReceiver {
    receiver: Receiver<MpcPeerMessage>,
}

/// Maps public keys to participant IDs. Used to identify incoming connections.
#[derive(Default)]
struct ParticipantIdentities {
    key_to_participant_id: HashMap<Vec<u8>, ParticipantId>,
}

/// A always-allowing client certificate verifier for the QUIC TLS layer.
/// Note that in general, verifying the certificate simply means that the
/// other party's public key has been correctly signed by a certificate
/// authority. In this case, we don't need that, because we already know
/// the exact public key we're expecting from each peer. So don't bother
/// verifying the certificate itself.
#[derive(Debug)]
struct DummyClientCertVerifier;

impl ClientCertVerifier for DummyClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// A retrying connection that will automatically reconnect if the QUIC
/// connection is broken.
#[derive(Clone)]
struct PersistentConnection {
    endpoint: Endpoint,
    target_address: String,
    target_participant_id: ParticipantId,
    participant_identities: Arc<ParticipantIdentities>,
    current: Arc<Mutex<Option<Arc<quinn::Connection>>>>,
    is_alive: Arc<AtomicBool>,
}

impl PersistentConnection {
    /// Returns a new QUIC stream, establishing a new connection if necessary.
    /// The stream itself can still fail after returning if the connection
    /// drops while the stream is used; but if the connection is already known
    /// to have failed before the stream is opened, this will re-establish the
    /// connection first.
    async fn new_stream(&self) -> anyhow::Result<quinn::SendStream> {
        let conn = {
            let mut current = self.current.lock().await;
            if current.is_none() {
                // Reconnect, if we never connected, or the previous connection was closed.
                self.reestablish_locked_connection(&mut *current).await?;
            }
            let conn = current.as_mut().unwrap().clone();
            conn
        };
        let stream = conn.open_uni().await?;
        Ok(stream)
    }

    async fn reestablish_locked_connection(&self, current: &mut Option<Arc<quinn::Connection>>) -> anyhow::Result<()> {
        let current_clone = self.current.clone();
        let socket_addr = self.target_address.to_socket_addrs()?.next().unwrap();
        let new_conn = self.endpoint.connect(socket_addr, "dummy")?.await?;
        let participant_id = verify_peer_identity(&new_conn, &self.participant_identities)?;
        if participant_id != self.target_participant_id {
            anyhow::bail!("Unexpected peer identity");
        }
        let new_conn = Arc::new(new_conn);
        *current = Some(new_conn.clone());

        tracking::spawn(
            &format!(
                "Delete connection if closed for participant {}",
                participant_id
            ),
            async move {
                // Wait for the connection to close, then delete it.
                // It's not immediate and not perfect, but at least we'll try to
                // reestablish the connection as soon as we know it's closed.
                new_conn.closed().await;
                let mut current = current_clone.lock().await;
                if let Some(current_conn) = &*current {
                    if Arc::ptr_eq(current_conn, &new_conn) {
                        *current = None;
                    }
                }
            },
        );
        Ok(())
    }
}

/// Configures the quinn library to properly perform TLS handshakes.
fn configure_quinn(config: &MpcConfig) -> anyhow::Result<(ServerConfig, ClientConfig)> {
    // The issuer is a dummy certificate authority that every node trusts.
    let issuer_signer = rcgen::KeyPair::from_pem(&config.participants.dummy_issuer_private_key)?;
    let issuer_cert =
        rcgen::CertificateParams::new(vec!["root".to_string()])?.self_signed(&issuer_signer)?;

    // This is the keypair that is secret to this node, used in P2P handshakes.
    let p2p_key = rcgen::KeyPair::from_pem(&config.secrets.p2p_private_key)?;
    let p2p_key_der =
        rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(p2p_key.serialize_der()));

    let p2p_cert = rcgen::CertificateParams::new(vec!["dummy".to_string()])?.signed_by(
        &p2p_key,
        &issuer_cert,
        &issuer_signer,
    )?;

    // Use a single trusted issuer.
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add(issuer_cert.der().clone())?;

    // As the server, we do not verify the client's certificate, but we still need
    // a custom verifier or else the certificate will not even be propagated to us
    // when we handle the connection. Later we'll check that the client provided a
    // valid public key in the certificate.
    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(DummyClientCertVerifier))
        .with_single_cert(vec![p2p_cert.der().clone()], p2p_key_der.clone_key())?;
    // As a client, we verify that the server has a valid certificate signed by the
    // dummy issuer (this is required by rustls). When making the connection we also
    // check that the server has the right public key.
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_client_auth_cert(vec![p2p_cert.der().clone()], p2p_key_der.clone_key())?;

    let server_suite = initial_suite_from_provider(server_config.crypto_provider())
        .ok_or_else(|| anyhow!("No supported cipher suite found in server config"))?;
    let client_suite = initial_suite_from_provider(client_config.crypto_provider())
        .ok_or_else(|| anyhow!("No supported cipher suite found in client config"))?;

    let server_config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::with_initial(
        server_config.into(),
        server_suite,
    )?));
    let client_config = ClientConfig::new(Arc::new(QuicClientConfig::with_initial(
        client_config.into(),
        client_suite,
    )?));
    Ok((server_config, client_config))
}

/// I don't understand this function but it's copied from the quinn code to satisfy the quinn API.
fn initial_suite_from_provider(provider: &Arc<rustls::crypto::CryptoProvider>) -> Option<Suite> {
    provider
        .cipher_suites
        .iter()
        .find_map(|cs| match (cs.suite(), cs.tls13()) {
            (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => {
                Some(suite.quic_suite())
            }
            _ => None,
        })
        .flatten()
}

/// Creates a mesh network using QUIC for communication.
pub async fn new_quic_mesh_network(
    config: &MpcConfig,
) -> Result<(
    impl MeshNetworkTransportSender,
    impl MeshNetworkTransportReceiver,
)> {
    let (server_config, client_config) = configure_quinn(config)?;

    let my_port = config
        .participants
        .participants
        .iter()
        .find(|participant| participant.id == config.my_participant_id)
        .map(|participant| participant.port)
        .ok_or_else(|| anyhow!("My ID not found in participants"))?;

    // Create server and client endpoints.
    let server = Endpoint::server(
        server_config,
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), my_port),
    )?;

    let mut client = Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))?;
    client.set_default_client_config(client_config);

    // Prepare participant data.
    let mut participant_ids = Vec::new();
    let mut participant_identities = ParticipantIdentities::default();
    let mut connections = HashMap::new();
    for participant in &config.participants.participants {
        participant_ids.push(participant.id);
        participant_identities
            .key_to_participant_id
            .insert(hex::decode(&participant.p2p_public_key)?, participant.id);
    }
    let participant_identities = Arc::new(participant_identities);
    for participant in &config.participants.participants {
        connections.insert(
            participant.id,
            Arc::new(PersistentConnection {
                endpoint: client.clone(),
                target_address: format!("{}:{}", participant.address, participant.port),
                target_participant_id: participant.id,
                participant_identities: participant_identities.clone(),
                current: Arc::new(Mutex::new(None)),
                is_alive: Arc::new(AtomicBool::new(false)),
            }),
        );
    }

    // TODO: what should the channel size be? What's our flow control strategy in general?
    let (message_sender, message_receiver) = mpsc::channel(100000);
    let endpoint_for_listener = server.clone();

    tracking::spawn("Handle incoming connections", async move {
        while let Some(conn) = endpoint_for_listener.accept().await {
            let message_sender = message_sender.clone();
            let participant_identities = participant_identities.clone();
            tracking::spawn("Handle connection", async move {
                if let Ok(connection) = conn.await {
                    let verified_participant_id =
                        verify_peer_identity(&connection, &participant_identities)?;
                    tracking::set_progress(&format!("Connection from {}", verified_participant_id));

                    loop {
                        let stream = connection.accept_uni().await?;
                        tracing::debug!("Accepted stream from {}", verified_participant_id);
                        let message_sender = message_sender.clone();
                        tracking::spawn(
                            &format!("Handle stream from {}", verified_participant_id),
                            async move {
                                if let Err(e) = handle_incoming_stream(
                                    verified_participant_id,
                                    stream,
                                    message_sender,
                                )
                                .await
                                {
                                    eprintln!("Error handling incoming stream: {}", e);
                                }
                            },
                        );
                    }
                }
                anyhow::Ok(())
            });
        }
    });

    let sender = QuicMeshSender {
        my_id: config.my_participant_id,
        participants: participant_ids,
        connections,
    };

    let receiver = QuicMeshReceiver {
        receiver: message_receiver,
    };

    Ok((sender, receiver))
}

fn verify_peer_identity(
    conn: &Connection,
    participant_identities: &ParticipantIdentities,
) -> anyhow::Result<ParticipantId> {
    let Some(identity) = conn.peer_identity() else {
        anyhow::bail!("Connection without peer identity");
    };
    let Ok(certs) = identity.downcast::<Vec<CertificateDer<'static>>>() else {
        anyhow::bail!("Connection with unexpected peer identity type");
    };
    if certs.len() != 1 {
        anyhow::bail!("Connection with unexpected number of certificates");
    };
    let Ok(cert) = X509Certificate::from_der(&certs[0]) else {
        anyhow::bail!("Connection with invalid certificate");
    };
    let Ok(public_key) = cert.1.public_key().parsed() else {
        anyhow::bail!("Connection with invalid public key");
    };
    let PublicKey::EC(ec) = public_key else {
        anyhow::bail!("Connection with unexpected public key type");
    };
    let Some(peer_id) = participant_identities.key_to_participant_id.get(ec.data()) else {
        anyhow::bail!("Connection with unknown public key");
    };
    Ok(*peer_id)
}

/// For now, each stream handles exactly one MpcMessage. This reads the message
/// and sends it to the message_sender.
async fn handle_incoming_stream(
    peer_id: ParticipantId,
    mut recv: quinn::RecvStream,
    message_sender: Sender<MpcPeerMessage>,
) -> Result<()> {
    let mut msg_len_buf = [0u8; 4];
    recv.read_exact(&mut msg_len_buf).await?;
    let msg_len = u32::from_be_bytes(msg_len_buf) as usize;

    let mut msg_buf = vec![0u8; msg_len];
    recv.read_exact(&mut msg_buf).await?;

    let peer_message = MpcPeerMessage {
        from: peer_id,
        message: MpcMessage::try_from_slice(&msg_buf)?,
    };

    message_sender.send(peer_message).await?;
    Ok(())
}

#[async_trait]
impl MeshNetworkTransportSender for QuicMeshSender {
    fn my_participant_id(&self) -> ParticipantId {
        self.my_id
    }

    fn all_participant_ids(&self) -> Vec<ParticipantId> {
        self.participants.clone()
    }

    fn other_participant_ids(&self) -> Vec<ParticipantId> {
        self.participants
            .iter()
            .filter(|id| **id != self.my_id)
            .cloned()
            .collect()
    }

    async fn send(&self, recipient_id: ParticipantId, message: MpcMessage) -> Result<()> {
        // For now, every message opens a new stream. This is totally fine
        // for performance, but it does mean messages may not arrive in order.
        let mut stream = self
            .connections
            .get(&recipient_id)
            .ok_or_else(|| anyhow!("Recipient not found"))?
            .new_stream()
            .await?;

        let msg = borsh::to_vec(&message)?;
        stream.write_all(&(msg.len() as u32).to_be_bytes()).await?;
        stream.write_all(&msg).await?;
        stream.finish()?;

        Ok(())
    }

    async fn wait_for_ready(&self) -> anyhow::Result<()> {
        let handles = self.connections.iter().map(|(participant_id, conn)| {
            let participant_id = *participant_id;
            let conn = conn.clone();
            tracking::spawn(
                &format!("Wait for connection to {}", participant_id),
                async move {
                    loop {
                        match conn.new_stream().await {
                            Ok(_) => break,
                            Err(e) => {
                                tracing::info!(
                                    "Waiting for connection to {}: {}",
                                    participant_id,
                                    e
                                );
                            }
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                },
            )
        });
        futures::future::join_all(handles).await;
        Ok(())
    }

    fn run_check_connections(&self, period: Duration) {
        for (id, connection) in &self.connections {
            if id == &self.my_id {
                continue;
            }
            let connection = connection.clone();
            let id = id.clone();
            tracking::spawn(
                format!("checking connection for participant {}", id).as_str(),
                async move {
                    loop {
                        tokio::time::sleep(period).await;
                        let mut current = connection.current.lock().await;
                        if current.is_none() {
                            match connection.reestablish_locked_connection(&mut *current).await {
                                Ok(_) => {
                                    connection.is_alive.store(true, Ordering::SeqCst);
                                }
                                Err(err) => {
                                    tracking::set_progress(format!("Could not reestablish new connection with participant {}, got error {}", id, err).as_str());
                                    connection.is_alive.store(false, Ordering::SeqCst);
                                }
                            }
                        }
                    }
                }
            );
        }
    }

    fn all_alive_participant_ids(&self) -> Vec<ParticipantId> {
        self
            .connections
            .iter()
            .filter(
                |(_, conn)|
                conn.is_alive.load(Ordering::SeqCst)
            )
            .map(|(p, _)| p.clone())
            .chain(vec![self.my_id])
            .collect()
    }
}

#[async_trait]
impl MeshNetworkTransportReceiver for QuicMeshReceiver {
    async fn receive(&mut self) -> Result<MpcPeerMessage> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| anyhow!("Channel closed"))
    }
}

/// Generates an ECDSA keypair, returning the pem-encoded private key and the
/// hex-encoded public key.
pub fn generate_keypair() -> Result<(String, String)> {
    let key_pair = rcgen::KeyPair::generate()?;
    Ok((
        key_pair.serialize_pem(),
        hex::encode(key_pair.public_key_raw()),
    ))
}

pub fn generate_test_p2p_configs(
    parties: usize,
    threshold: usize,
) -> anyhow::Result<Vec<MpcConfig>> {
    let mut participants = Vec::new();
    let mut keypairs = Vec::new();
    for i in 0..parties {
        let (p2p_private_key, p2p_public_key) = generate_keypair()?;
        participants.push(ParticipantInfo {
            id: ParticipantId(i as u32),
            address: "localhost".to_string(),
            port: 10000 + i as u16,
            p2p_public_key: p2p_public_key.clone(),
        });
        keypairs.push((p2p_private_key, p2p_public_key));
    }
    let (issuer_private_key, _) = generate_keypair()?;

    let mut configs = Vec::new();
    for i in 0..parties {
        let participants = ParticipantsConfig {
            threshold: threshold as u32,
            dummy_issuer_private_key: issuer_private_key.clone(),
            participants: participants.clone(),
        };

        let config = MpcConfig {
            my_participant_id: ParticipantId(i as u32),
            secrets: SecretsConfig {
                p2p_private_key: keypairs[i].0.clone(),
            },
            participants,
        };
        configs.push(config);
    }

    Ok(configs)
}

#[cfg(test)]
mod tests {
    use crate::network::{MeshNetworkTransportReceiver, MeshNetworkTransportSender};
    use crate::primitives::{MpcMessage, ParticipantId};
    use crate::tracing::init_logging;
    use crate::tracking::testing::start_root_task_with_periodic_dump;

    #[tokio::test]
    async fn test_basic_quic_mesh_network() {
        init_logging();
        let configs = super::generate_test_p2p_configs(2, 2).unwrap();
        println!("{:?}", configs[0]);
        start_root_task_with_periodic_dump(async move {
            let (sender0, mut receiver0) = super::new_quic_mesh_network(&configs[0]).await.unwrap();
            let (sender1, mut receiver1) = super::new_quic_mesh_network(&configs[1]).await.unwrap();

            for _ in 0..100 {
                sender0
                    .send(
                        ParticipantId(1),
                        MpcMessage {
                            data: vec![1, 2, 3],
                            task_id: crate::primitives::MpcTaskId::KeyGeneration,
                        },
                    )
                    .await
                    .unwrap();
                let msg = receiver1.receive().await.unwrap();
                assert_eq!(msg.from, ParticipantId(0));
                assert_eq!(msg.message.data, vec![1, 2, 3]);

                sender1
                    .send(
                        ParticipantId(0),
                        MpcMessage {
                            data: vec![4, 5, 6],
                            task_id: crate::primitives::MpcTaskId::KeyGeneration,
                        },
                    )
                    .await
                    .unwrap();

                let msg = receiver0.receive().await.unwrap();
                assert_eq!(msg.from, ParticipantId(1));
                assert_eq!(msg.message.data, vec![4, 5, 6]);
            }
        })
        .await;
    }
}
