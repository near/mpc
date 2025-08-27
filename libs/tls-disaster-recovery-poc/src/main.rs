use mpc_tls::tls::configure_tls;
use rand::rngs::OsRng;
use rustls::{ClientConfig, ServerConfig};
use std::sync::Arc;
use tls_disaster_recovery_poc::communicator::conn::{self, Communicator};
use tls_disaster_recovery_poc::messages::{Messages, PeerMessage};
use tls_disaster_recovery_poc::types::{self, CommPeers, Peer};
use tokio_util::sync::CancellationToken;
fn gen_peer(port: u16) -> anyhow::Result<TestPeer> {
    // Generate a fresh keypair
    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let (server_conf, client_conf) = configure_tls(&signing_key)?;
    Ok(TestPeer {
        server_conf,
        client_conf,
        peer: Peer {
            address: format!("127.0.0.1:{}", port).to_string(),
            public_key: verifying_key,
        },
    })
}

#[derive(Clone)]
struct TestPeer {
    peer: Peer,
    client_conf: Arc<ClientConfig>,
    server_conf: Arc<ServerConfig>,
}

async fn make_comm(
    comm_peers: Arc<CommPeers>,
    test_peer: TestPeer,
    port: u16,
) -> anyhow::Result<(
    conn::Communicator,
    tokio::sync::mpsc::UnboundedReceiver<PeerMessage>,
    CancellationToken,
)> {
    let (message_sender, message_receiver) = tokio::sync::mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    Ok((
        conn::Communicator::new(
            comm_peers,
            test_peer.server_conf,
            test_peer.client_conf,
            cancel.child_token(),
            port,
            message_sender,
        )
        .await?,
        message_receiver,
        cancel,
    ))
}
struct TestNode {
    communicator: Communicator,
    cancel: CancellationToken,
    receiver: tokio::sync::mpsc::UnboundedReceiver<PeerMessage>,
}
impl TestNode {
    async fn new(me: TestPeer, other: TestPeer, port: u16) -> anyhow::Result<Self> {
        let mut comm_peers = types::CommPeers::new();
        comm_peers.insert(other.peer.clone())?;
        let comm_peers = Arc::new(comm_peers);
        let (comm, recv, cancel) = make_comm(comm_peers.clone(), me.clone(), port).await?;
        Ok(TestNode {
            communicator: comm,
            cancel,
            receiver: recv,
        })
    }
    async fn send(&self, msg: &str) -> anyhow::Result<()> {
        let msg = PeerMessage {
            peer_id: 0.into(), //#CommunicatorPeerId(0),
            message: Messages::Secrets(msg.to_string()),
        };
        tracing::info!("sending message: {:?}", msg);
        self.communicator.send(msg).await
    }
    async fn expect(&mut self, expected: &str) {
        let rcvd = self.receiver.recv().await.unwrap();
        tracing::info!("received message: {:?}", rcvd);
        assert_eq!(rcvd.peer_id, 0.into());
        match rcvd.message {
            Messages::Secrets(msg) => assert_eq!(expected, msg),
            _ => assert!(false),
        }
    }
}

async fn gen_test_nodes() -> anyhow::Result<(TestNode, TestNode)> {
    let alice = gen_peer(ALICE_PORT)?;
    let bob = gen_peer(BOB_PORT)?;
    let alice_node = TestNode::new(alice.clone(), bob.clone(), ALICE_PORT).await?;
    let bob_node = TestNode::new(bob, alice, BOB_PORT).await?;
    Ok((alice_node, bob_node))
}

const BOB_PORT: u16 = 12345;
const ALICE_PORT: u16 = 23456;
use tracing_subscriber;
//configure_tls(p2p_private_key)
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let (mut alice, mut bob) = gen_test_nodes().await?;

    alice.send("Hello Bob").await?;
    bob.expect("Hello Bob").await;
    bob.send("Hello Alice").await?;
    alice.expect("Hello Alice").await;
    alice.send("Did you know we are communicating").await?;
    alice.send("in secret").await?;
    bob.expect("Did you know we are communicating").await;
    bob.send("in secret?").await?;
    bob.expect("in secret").await;
    bob.send("I see, you had the same thought.").await?;
    alice
        .send("We are completing each others sentences <3.")
        .await?;
    Ok(())
}
