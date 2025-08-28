use std::sync::Arc;
use std::time::Duration;
use tls_disaster_recovery_poc::backup_service::BackupService;
use tls_disaster_recovery_poc::mpc_node::MpcNode;
use tls_disaster_recovery_poc::network::messages::Messages;
use tls_disaster_recovery_poc::network::types::{Connection, Peer};

mod helpers {
    use mpc_tls::tls::configure_tls;
    use rand::rngs::OsRng;
    use rustls::{ClientConfig, ServerConfig};
    use std::sync::Arc;
    use tls_disaster_recovery_poc::network::types::Peer;

    pub fn gen_config(port: u16) -> anyhow::Result<(Peer, Arc<ServerConfig>, Arc<ClientConfig>)> {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let (server_config, client_config) = configure_tls(&signing_key)?;
        let myself = Peer {
            address: format!("127.0.0.1:{}", port).to_string(),
            public_key: verifying_key,
        };

        Ok((myself, server_config, client_config))
    }
}

use helpers::gen_config;

async fn test_exchange(sender: &Arc<Connection>, recipient: &Arc<Connection>) {
    let msg = "Hello".to_string();
    assert!(sender.send(Messages::Secrets(msg.clone())).is_ok());
    assert!(matches!(
        recipient.receive().await.unwrap(),
        Messages::Secrets(m) if m == msg
    ));
    let msg = "Did you know,".to_string();
    assert!(sender.send(Messages::Secrets(msg.clone())).is_ok());
    assert!(matches!(
        recipient.receive().await.unwrap(),
        Messages::Secrets(m) if m == msg
    ));
    let msg = "we are communicated over an encrypted channel?".to_string();
    assert!(sender.send(Messages::Secrets(msg.clone())).is_ok());
    assert!(matches!(
        recipient.receive().await.unwrap(),
        Messages::Secrets(m) if m == msg
    ));
}

async fn test_comm_cycle(
    backup_service: &mut BackupService,
    mpc_peer: &Peer,
    mpc_node: &MpcNode,
    backup_peer: &Peer,
) -> anyhow::Result<()> {
    let backup_conn = backup_service.connect(mpc_peer).await?;
    let mpc_conn = mpc_node.wait_for_peer(backup_peer).await;

    // test communication works
    test_exchange(&backup_conn, &mpc_conn).await;
    test_exchange(&mpc_conn, &backup_conn).await;
    Ok(())
}

async fn test_shutdown_mpc(
    backup_service: &mut BackupService,
    mpc_peer: &Peer,
    mpc_node: &MpcNode,
    backup_peer: &Peer,
) -> anyhow::Result<()> {
    let backup_conn = backup_service.connect(mpc_peer).await?;
    let mpc_conn = mpc_node.wait_for_peer(backup_peer).await;

    // close the old mpc node
    mpc_node.cancel();
    mpc_conn.cancel().await;

    // ensure the backup node closes the receiver
    assert!(backup_conn.receive().await.is_none());
    assert!(backup_conn.incoming_closed().await);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), backup_conn.outgoing_closed())
            .await
            .is_ok()
    );
    Ok(())
}

async fn start_new_mpc(port: u16, backup_peer: Peer) -> anyhow::Result<(MpcNode, Peer)> {
    /* Spin up a new node on a different port */
    let (new_mpc_node_peer, mpc_node_tls_config, _) = gen_config(port)?;
    let mpc_node = MpcNode::new(mpc_node_tls_config, backup_peer, port);
    mpc_node.serve();
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok((mpc_node, new_mpc_node_peer))
}

// note: do we need to set TCP nodelay somewhere?
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    const BACKUP_SERVER_PORT: u16 = 12345;
    const MPC_NODE_PORT: u16 = 23456;

    // 1. Start backup service and MPC node
    let (backup_service_peer, _, backup_service_tls_config) = gen_config(BACKUP_SERVER_PORT)?;
    let (mpc_node, mpc_node_peer) =
        start_new_mpc(MPC_NODE_PORT, backup_service_peer.clone()).await?;
    let mut backup_service = BackupService::new(backup_service_tls_config, mpc_node_peer.clone());

    // 2. receive secret shares from node
    test_comm_cycle(
        &mut backup_service,
        &mpc_node_peer,
        &mpc_node,
        &backup_service_peer,
    )
    .await?;

    // 3. shutdown MPC node
    test_shutdown_mpc(
        &mut backup_service,
        &mpc_node_peer,
        &mpc_node,
        &backup_service_peer,
    )
    .await?;

    // 4a. Remove mpc node from allowed peers
    backup_service.remove(&mpc_node_peer)?;

    // 4b. Start new MPC node
    let (mpc_node, new_mpc_node_peer) =
        start_new_mpc(MPC_NODE_PORT + 1, backup_service_peer.clone()).await?;

    // 4c. Add the new MPC node to the backup service
    assert_eq!(
        backup_service.add_peer(new_mpc_node_peer.clone())?,
        1.into()
    );

    // 5. ensure backup service can transmit secrets to the new node
    test_comm_cycle(
        &mut backup_service,
        &new_mpc_node_peer,
        &mpc_node,
        &backup_service_peer,
    )
    .await?;
    tracing::info!("Success!");
    Ok(())
}
