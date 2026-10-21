use std::collections::BTreeMap;
use std::future::Future;
use std::{sync::Arc, time::Duration};

use backon::{BackoffBuilder, ExponentialBuilder};
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_mpc_contract_interface::types::{
    AllowedMpcDockerImageHash, ChainEntry, Ed25519PublicKey, ForeignChain, GetAttestationResponse,
};
use tokio::sync::watch;

use crate::indexer::IndexerState;
use crate::tee::attestation_freshness_metrics::record_stored_attestation;

const TEE_STATE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const MIN_BACKOFF_DURATION: Duration = Duration::from_secs(1);
const MAX_BACKOFF_DURATION: Duration = Duration::from_mins(1);
const FOREIGN_CHAIN_PROVIDERS_REFRESH_INTERVAL: Duration = Duration::from_mins(5);

async fn monitor_tee_state<Fetcher, T, FetcherResponseFuture>(
    sender: watch::Sender<T>,
    indexer_state: Arc<IndexerState>,
    fetch_tee_state: &Fetcher,
) where
    T: PartialEq,
    Fetcher: Fn() -> FetcherResponseFuture + Send + Sync,
    FetcherResponseFuture: Future<Output = anyhow::Result<(u64, T)>> + Send,
{
    let fetch_tee_state_with_retry = {
        async move || {
            let mut backoff = ExponentialBuilder::default()
                .with_min_delay(MIN_BACKOFF_DURATION)
                .with_max_delay(MAX_BACKOFF_DURATION)
                .without_max_times()
                .with_jitter()
                .build();

            loop {
                match fetch_tee_state().await {
                    Ok((_block_height, tee_state)) => {
                        break tee_state;
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
    indexer_state.client.wait_for_full_sync().await;

    loop {
        tokio::time::sleep(TEE_STATE_REFRESH_INTERVAL).await;
        let tee_state = fetch_tee_state_with_retry().await;
        sender.send_if_modified(|previous_tee_state| {
            if *previous_tee_state != tee_state {
                *previous_tee_state = tee_state;
                true
            } else {
                false
            }
        });
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
    let fetcher = { || view_client.get_mpc_allowed_image_hashes() };

    monitor_tee_state(sender, indexer_state, &fetcher).await
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
    let fetcher = { || view_client.get_mpc_allowed_launcher_compose_hashes() };

    monitor_tee_state(sender, indexer_state, &fetcher).await
}

/// Fetches the allowed foreign-chain providers whitelist from the contract with retry logic.
async fn fetch_allowed_foreign_chain_providers_with_retry(
    indexer_state: &IndexerState,
) -> BTreeMap<ForeignChain, ChainEntry> {
    let mut backoff = ExponentialBuilder::default()
        .with_min_delay(MIN_BACKOFF_DURATION)
        .with_max_delay(MAX_BACKOFF_DURATION)
        .without_max_times()
        .with_jitter()
        .build();

    loop {
        match indexer_state
            .view_client
            .get_allowed_foreign_chain_providers()
            .await
        {
            Ok(whitelist) => return whitelist,
            Err(e) => {
                tracing::error!(target: "mpc", "error reading allowed_foreign_chain_providers from chain: {:?}", e);
                let backoff_duration = backoff.next().unwrap_or(MAX_BACKOFF_DURATION);
                tokio::time::sleep(backoff_duration).await;
            }
        }
    }
}

/// Monitor the allowed foreign-chain providers whitelist stored in the contract and update the
/// watch channel when changes are detected. Consumed by
/// [`crate::foreign_chain_whitelist_verifier::run`].
pub async fn monitor_allowed_foreign_chain_providers(
    sender: watch::Sender<BTreeMap<ForeignChain, ChainEntry>>,
    indexer_state: Arc<IndexerState>,
) {
    indexer_state.client.wait_for_full_sync().await;

    loop {
        let whitelist = fetch_allowed_foreign_chain_providers_with_retry(&indexer_state).await;
        sender.send_if_modified(|previous| {
            if *previous != whitelist {
                *previous = whitelist;
                true
            } else {
                false
            }
        });
        tokio::time::sleep(FOREIGN_CHAIN_PROVIDERS_REFRESH_INTERVAL).await;
    }
}

pub async fn monitor_my_attestation(
    sender: watch::Sender<Option<GetAttestationResponse>>,
    indexer_state: Arc<IndexerState>,
    tls_public_key: Ed25519PublicKey,
) {
    let view_client = indexer_state.view_client.clone();
    let fetcher = async || {
        view_client
            .get_participant_attestation(&tls_public_key)
            .await
            .inspect(|(_, stored)| record_stored_attestation(stored.as_ref()))
    };

    monitor_tee_state(sender, indexer_state, &fetcher).await
}
