use std::future::Future;
use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder};
use mpc_contract::tee::proposal::{LauncherDockerComposeHash, MpcDockerImageHash};
use mpc_contract::tee::tee_state::NodeId;
use tokio::sync::watch;

use super::MpcContractStateViewer;

const ALLOWED_HASHES_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const MIN_BACKOFF_DURATION: Duration = Duration::from_secs(1);
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);
const TEE_ACCOUNTS_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

fn new_backoff() -> backon::ExponentialBackoff {
    ExponentialBuilder::default()
        .with_min_delay(MIN_BACKOFF_DURATION)
        .with_max_delay(MAX_BACKOFF_DURATION)
        .without_max_times()
        .with_jitter()
        .build()
}

async fn monitor_allowed_hashes<Fetcher, T, FetcherResponseFuture>(
    sender: watch::Sender<T>,
    get_mpc_allowed_hashes: &Fetcher,
) where
    T: PartialEq,
    Fetcher: Fn() -> FetcherResponseFuture + Send + Sync,
    FetcherResponseFuture: Future<Output = anyhow::Result<(u64, T)>> + Send,
{
    let fetch_allowed_hashes = {
        async move || {
            let mut backoff = new_backoff();

            loop {
                match get_mpc_allowed_hashes().await {
                    Ok((_block_height, allowed_hashes)) => {
                        break allowed_hashes;
                    }
                    Err(e) => {
                        // todo: we can remove this exponential backoff now --> the contract
                        // implements these methods
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
    mpc_contract: MpcContractStateViewer,
) {
    let fetcher = { || mpc_contract.get_mpc_allowed_image_hashes() };

    monitor_allowed_hashes(sender, &fetcher).await
}

/// This future waits for the indexer to fully sync, and returns
/// a [`watch::Receiver`] that will be continuously updated with the
/// allowed [`LauncherDockerComposeHash`]es when a change is detected
/// on the MPC smart contract.
pub async fn monitor_allowed_launcher_compose_hashes(
    sender: watch::Sender<Vec<LauncherDockerComposeHash>>,
    mpc_contract: MpcContractStateViewer,
) {
    let fetcher = { || mpc_contract.get_mpc_allowed_launcher_compose_hashes() };

    monitor_allowed_hashes(sender, &fetcher).await
}

/// Fetches TEE accounts from the contract with retry logic.
async fn fetch_tee_accounts_with_retry(contract: MpcContractStateViewer) -> Vec<NodeId> {
    let mut backoff = new_backoff();

    loop {
        match contract.get_mpc_tee_accounts().await {
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
    contract: MpcContractStateViewer,
) {
    loop {
        let tee_accounts = fetch_tee_accounts_with_retry(contract.clone()).await;
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
