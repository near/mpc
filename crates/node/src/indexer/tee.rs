use std::{sync::Arc, time::Duration};

use backon::{BackoffBuilder, ExponentialBuilder};
use mpc_contract::tee::tee_state::NodeId;
use tokio::sync::watch;

use crate::indexer::IndexerState;

const MIN_BACKOFF_DURATION: Duration = Duration::from_secs(1);
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);
const TEE_ACCOUNTS_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Fetches TEE accounts from the contract with retry logic.
async fn fetch_tee_accounts_with_retry(indexer_state: &IndexerState) -> Vec<NodeId> {
    let mut backoff = ExponentialBuilder::default()
        .with_min_delay(MIN_BACKOFF_DURATION)
        .with_max_delay(MAX_BACKOFF_DURATION)
        .without_max_times()
        .with_jitter()
        .build();

    loop {
        match indexer_state
            .view_client
            .get_mpc_tee_accounts(indexer_state.mpc_contract_id.clone())
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
    indexer_state.client.wait_for_full_sync().await;

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
