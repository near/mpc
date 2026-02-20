use std::future::Future;
use std::{sync::Arc, time::Duration};

use backon::{BackoffBuilder, ExponentialBuilder};
use mpc_contract::tee::proposal::{LauncherDockerComposeHash, MpcDockerImageHash};
use mpc_contract::tee::tee_state::NodeId;
use near_account_id::AccountId;
use tokio::sync::watch;

use crate::indexer::IndexerState;

const ALLOWED_HASHES_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const MIN_BACKOFF_DURATION: Duration = Duration::from_secs(1);
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);
const TEE_ACCOUNTS_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

async fn monitor_allowed_hashes<Fetcher, T, FetcherResponseFuture>(
    sender: watch::Sender<T>,
    indexer_state: Arc<IndexerState>,
    get_mpc_allowed_hashes: &Fetcher,
) where
    T: PartialEq,
    Fetcher: Fn() -> FetcherResponseFuture + Send + Sync,
    FetcherResponseFuture: Future<Output = anyhow::Result<(u64, T)>> + Send,
{
    let fetch_allowed_hashes = {
        let indexer_state = indexer_state.clone();
        async move || {
            let mut backoff = ExponentialBuilder::default()
                .with_min_delay(MIN_BACKOFF_DURATION)
                .with_max_delay(MAX_BACKOFF_DURATION)
                .without_max_times()
                .with_jitter()
                .build();

            loop {
                match get_mpc_allowed_hashes().await {
                    Ok((_block_height, allowed_hashes)) => {
                        break allowed_hashes;
                    }
                    Err(e) => {
                        let error_msg = format!("{:?}", e);
                        if error_msg.contains(
                            "wasm execution failed with error: MethodResolveError(MethodNotFound)",
                        ) {
                            tracing::info!(target: "mpc", "method  not found in contract: {error_msg}");
                        } else {
                            tracing::error!(target: "mpc", "error reading tee state from chain: {error_msg}");
                        }

                        let backoff_duration = backoff.next().unwrap_or(MAX_BACKOFF_DURATION);
                        tokio::time::sleep(backoff_duration).await;

                        continue;
                    }
                };
            }
        }
    };

    tracing::debug!(target: "indexer", "awaiting full sync to read mpc contract state");
    indexer_state.chain_gateway.wait_for_full_sync().await;

    loop {
        tokio::time::sleep(ALLOWED_HASHES_REFRESH_INTERVAL).await;
        let allowed_hashes = fetch_allowed_hashes().await;
        sender.send_if_modified(|previous_allowed_hashes| {
            if *previous_allowed_hashes != allowed_hashes {
                *previous_allowed_hashes = allowed_hashes;
                true
            } else {
                false
            }
        });
    }
}

/// This future waits for the indexer to fully sync, and returns
/// a [`watch::Receiver`] that will be continuously updated with the latest
/// allowed [`AllowedDockerImageHash`]es when a change is detected
/// on the MPC smart contract.
pub async fn monitor_allowed_docker_images(
    sender: watch::Sender<Vec<MpcDockerImageHash>>,
    indexer_state: Arc<IndexerState>,
) {
    let indexer_state_clone = indexer_state.clone(); //view_client.clone();
    let fetcher = { || indexer_state_clone.get_mpc_allowed_image_hashes() };

    monitor_allowed_hashes(sender, indexer_state, &fetcher).await
}

/// This future waits for the indexer to fully sync, and returns
/// a [`watch::Receiver`] that will be continuously updated with the
/// allowed [`LauncherDockerComposeHash`]es when a change is detected
/// on the MPC smart contract.
pub async fn monitor_allowed_launcher_compose_hashes(
    sender: watch::Sender<Vec<LauncherDockerComposeHash>>,
    indexer_state: Arc<IndexerState>,
) {
    let indexer_state_clone = indexer_state.clone();
    let fetcher = { || indexer_state_clone.get_mpc_allowed_launcher_compose_hashes() };

    monitor_allowed_hashes(sender, indexer_state, &fetcher).await
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
        match indexer_state.get_mpc_tee_accounts().await {
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
    indexer_state.chain_gateway.wait_for_full_sync().await;

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
