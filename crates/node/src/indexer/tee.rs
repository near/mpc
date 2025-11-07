use std::{sync::Arc, time::Duration};

use backon::{BackoffBuilder, ExponentialBuilder};
use mpc_contract::tee::proposal::{LauncherDockerComposeHash, MpcDockerImageHash};
use mpc_contract::tee::tee_state::NodeId;
use tokio::sync::watch;

use crate::indexer::lib::get_mpc_allowed_launcher_compose_hashes;
use crate::indexer::{
    lib::{get_mpc_allowed_image_hashes, get_mpc_tee_accounts, wait_for_full_sync},
    IndexerState,
};

const ALLOWED_IMAGE_HASHES_REFRESH_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(1);
const MIN_BACKOFF_DURATION: Duration = Duration::from_secs(1);
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);
const TEE_ACCOUNTS_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// This future waits for the indexer to fully sync, and returns
/// a [`watch::Receiver`] that will be continuously updated with the latest
/// allowed [`AllowedDockerImageHash`]es when a change is detected
/// on the MPC smart contract.
pub async fn monitor_allowed_docker_images(
    sender: watch::Sender<Vec<MpcDockerImageHash>>,
    indexer_state: Arc<IndexerState>,
) {
    let fetch_allowed_image_hashes = {
        let indexer_state = indexer_state.clone();
        async move || {
            let mut backoff = ExponentialBuilder::default()
                .with_min_delay(MIN_BACKOFF_DURATION)
                .with_max_delay(MAX_BACKOFF_DURATION)
                .without_max_times()
                .with_jitter()
                .build();

            loop {
                match get_mpc_allowed_image_hashes(
                    indexer_state.mpc_contract_id.clone(),
                    &indexer_state.view_client,
                )
                .await
                {
                    Ok((_block_height, allowed_images)) => {
                        break allowed_images;
                    }
                    Err(e) => {
                        tracing::error!(target: "mpc", "error reading tee state from chain: {:?}", e);

                        let backoff_duration = backoff.next().unwrap_or(MAX_BACKOFF_DURATION);
                        tokio::time::sleep(backoff_duration).await;

                        continue;
                    }
                };
            }
        }
    };

    tracing::debug!(target: "indexer", "awaiting full sync to read mpc contract state");
    wait_for_full_sync(&indexer_state.client).await;

    loop {
        tokio::time::sleep(ALLOWED_IMAGE_HASHES_REFRESH_INTERVAL).await;
        let allowed_image_hashes = fetch_allowed_image_hashes().await;
        sender.send_if_modified(|previous_allowed_image_hashes| {
            if *previous_allowed_image_hashes != allowed_image_hashes {
                *previous_allowed_image_hashes = allowed_image_hashes;
                true
            } else {
                false
            }
        });
    }
}

/// This future waits for the indexer to fully sync, and returns
/// a [`watch::Receiver`] that will be continuously updated with the
/// allowed [`LauncherDockerComposeHash`]es when a change is detected
/// on the MPC smart contract.
pub async fn monitor_allowed_launcher_compose_hashes(
    sender: watch::Sender<Vec<LauncherDockerComposeHash>>,
    indexer_state: Arc<IndexerState>,
) {
    let fetch_allowed_launcher_compose_hashes = {
        let indexer_state = indexer_state.clone();
        async move || {
            let mut backoff = ExponentialBuilder::default()
                .with_min_delay(MIN_BACKOFF_DURATION)
                .with_max_delay(MAX_BACKOFF_DURATION)
                .without_max_times()
                .with_jitter()
                .build();

            loop {
                match get_mpc_allowed_launcher_compose_hashes(
                    indexer_state.mpc_contract_id.clone(),
                    &indexer_state.view_client,
                )
                .await
                {
                    Ok((_block_height, allowed_images)) => {
                        break allowed_images;
                    }
                    Err(e) => {
                        tracing::error!(target: "mpc", "error reading tee state from chain: {:?}", e);

                        let backoff_duration = backoff.next().unwrap_or(MAX_BACKOFF_DURATION);
                        tokio::time::sleep(backoff_duration).await;

                        continue;
                    }
                };
            }
        }
    };

    tracing::debug!(target: "indexer", "awaiting full sync to read mpc contract state");
    wait_for_full_sync(&indexer_state.client).await;

    loop {
        tokio::time::sleep(ALLOWED_IMAGE_HASHES_REFRESH_INTERVAL).await;
        let allowed_image_hashes = fetch_allowed_launcher_compose_hashes().await;
        sender.send_if_modified(|previous_allowed_image_hashes| {
            if *previous_allowed_image_hashes != allowed_image_hashes {
                *previous_allowed_image_hashes = allowed_image_hashes;
                true
            } else {
                false
            }
        });
    }
}

/// Fetches TEE accounts from the contract with retry logic.
async fn fetch_tee_accounts_with_retry(indexer_state: &IndexerState) -> Vec<NodeId> {
    let mut backoff = ExponentialBuilder::default()
        .with_min_delay(MIN_BACKOFF_DURATION)
        .with_max_delay(MAX_BACKOFF_DURATION)
        .without_max_times()
        .with_jitter()
        .build();

    loop {
        match get_mpc_tee_accounts(
            indexer_state.mpc_contract_id.clone(),
            &indexer_state.view_client,
        )
        .await
        {
            Ok((_block_height, tee_accounts)) => return tee_accounts,
            Err(e) => {
                tracing::error!(target: "mpc", "error reading TEE accounts from chain: {:?}", e);
                let backoff_duration = backoff.next().unwrap_or(MAX_BACKOFF_DURATION);
                tokio::time::sleep(backoff_duration).await;
            }
        }
    }
}

/// Monitor TEE accounts stored in the contract and update the watch channel when changes are detected.
pub async fn monitor_tee_accounts(
    sender: watch::Sender<Vec<NodeId>>,
    indexer_state: Arc<IndexerState>,
) {
    wait_for_full_sync(&indexer_state.client).await;

    loop {
        let tee_accounts = fetch_tee_accounts_with_retry(&indexer_state).await;
        sender.send_if_modified(|previous_tee_accounts| {
            if *previous_tee_accounts != tee_accounts {
                *previous_tee_accounts = tee_accounts;
                true
            } else {
                false
            }
        });
        tokio::time::sleep(TEE_ACCOUNTS_REFRESH_INTERVAL).await;
    }
}
