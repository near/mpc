use std::collections::BTreeMap;
use std::future::Future;
use std::{sync::Arc, time::Duration};

use mpc_primitives::hash::LauncherDockerComposeHash;
use near_account_id::AccountId;
use near_mpc_contract_interface::types::{
    AllowedMpcDockerImageHash, ChainEntry, ForeignChain, NodeId,
};
use tokio::sync::watch;

use crate::indexer::IndexerState;
use crate::indexer::monitor::{fetch_with_retry, publish_if_changed};

const ALLOWED_HASHES_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const TEE_ACCOUNTS_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const FOREIGN_CHAIN_PROVIDERS_REFRESH_INTERVAL: Duration = Duration::from_secs(300);

async fn monitor_allowed_hashes<Fetcher, T, FetcherResponseFuture>(
    sender: watch::Sender<T>,
    indexer_state: Arc<IndexerState>,
    get_mpc_allowed_hashes: &Fetcher,
) where
    T: PartialEq,
    Fetcher: Fn(AccountId) -> FetcherResponseFuture + Send + Sync,
    FetcherResponseFuture: Future<Output = anyhow::Result<(u64, T)>> + Send,
{
    tracing::debug!(target: "indexer", "awaiting full sync to read mpc contract state");
    indexer_state.client.wait_for_full_sync().await;

    loop {
        tokio::time::sleep(ALLOWED_HASHES_REFRESH_INTERVAL).await;
        let allowed_hashes = fetch_with_retry(
            || async {
                get_mpc_allowed_hashes(indexer_state.mpc_contract_id.clone())
                    .await
                    .map(|(_block_height, allowed_hashes)| allowed_hashes)
            },
            "error reading tee state from chain",
        )
        .await;
        publish_if_changed(&sender, allowed_hashes);
    }
}

/// This future waits for the indexer to fully sync, and returns
/// a [`watch::Receiver`] that will be continuously updated with the latest
/// allowed [`AllowedMpcDockerImageHash`]es when a change is detected
/// on the MPC smart contract.
pub async fn monitor_allowed_docker_images(
    sender: watch::Sender<Vec<AllowedMpcDockerImageHash>>,
    indexer_state: Arc<IndexerState>,
) {
    let view_client = indexer_state.view_client.clone();
    let fetcher = { |id| view_client.get_mpc_allowed_image_hashes(id) };

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
    let view_client = indexer_state.view_client.clone();
    let fetcher = { |id| view_client.get_mpc_allowed_launcher_compose_hashes(id) };

    monitor_allowed_hashes(sender, indexer_state, &fetcher).await
}

/// Monitor TEE accounts stored in the contract and update the watch channel when changes are detected.
pub async fn monitor_tee_accounts(
    sender: watch::Sender<Vec<NodeId>>,
    indexer_state: Arc<IndexerState>,
) {
    indexer_state.client.wait_for_full_sync().await;

    loop {
        let tee_accounts = fetch_with_retry(
            || async {
                indexer_state
                    .view_client
                    .get_mpc_tee_accounts(indexer_state.mpc_contract_id.clone())
                    .await
                    .map(|(_block_height, tee_accounts)| tee_accounts)
            },
            "error reading TEE accounts from chain",
        )
        .await;
        publish_if_changed(&sender, tee_accounts);
        tokio::time::sleep(TEE_ACCOUNTS_REFRESH_INTERVAL).await;
    }
}

/// Monitor the allowed foreign-chain providers whitelist stored in the contract and update the
/// watch channel when changes are detected. Consumed by
/// `crate::foreign_chain_whitelist_verifier::run`.
pub async fn monitor_allowed_foreign_chain_providers(
    sender: watch::Sender<BTreeMap<ForeignChain, ChainEntry>>,
    indexer_state: Arc<IndexerState>,
) {
    indexer_state.client.wait_for_full_sync().await;

    loop {
        let whitelist = fetch_with_retry(
            || {
                indexer_state
                    .view_client
                    .get_allowed_foreign_chain_providers(indexer_state.mpc_contract_id.clone())
            },
            "error reading allowed_foreign_chain_providers from chain",
        )
        .await;
        publish_if_changed(&sender, whitelist);
        tokio::time::sleep(FOREIGN_CHAIN_PROVIDERS_REFRESH_INTERVAL).await;
    }
}
