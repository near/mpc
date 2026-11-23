use std::path::PathBuf;

use chain_gateway::{ChainGateway, NodeConfig};
use mpc_node::{
    config::{PersistentSecrets, ensure_near_initialized},
    web::static_web_data,
};
use mpc_node_config::BackupServiceStartConfig;
use tee_authority::tee_authority::TeeAuthority;
use tee_context::generate_initial_attestation;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::adapters::web;

/// Starts the backup service a launcher configured, and serves its keys and attestation on
/// `/public_data` until the given [`CancellationToken`] is cancelled. Fails when the embedded
/// NEAR node follows a chain other than the configured genesis hash's.
pub async fn start_with_config_file(
    home_dir: PathBuf,
    config: BackupServiceStartConfig,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    ensure_near_initialized(&home_dir, &config.near_init, &config.mpc_contract_id)?;
    let (chain_gateway, _near_node, _) =
        ChainGateway::start(NodeConfig::new(home_dir.clone()), None, shutdown.clone()).await?;
    chain_gateway
        .ensure_chain_matches(Some(config.genesis_hash))
        .await?;

    let keys = static_web_data(
        &PersistentSecrets::generate_or_get_existing(&home_dir)?,
        None,
    );
    let tee_authority = TeeAuthority::new(config.tee.authority, config.pccs_endpoints)?;
    let attestation = generate_initial_attestation(
        &tee_authority,
        &keys.near_p2p_public_key,
        &keys.near_signer_public_key,
    )
    .await?;
    let (_, latest_attestation) = watch::channel(attestation);

    let (_, status) = web::status_channel();
    web::spawn_web_server(
        config.listen_address,
        status,
        Some(web::PublicData {
            keys,
            latest_attestation,
        }),
    )
    .await?;

    shutdown.cancelled().await;
    Ok(())
}
