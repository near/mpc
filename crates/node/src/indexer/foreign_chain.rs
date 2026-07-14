use std::sync::Arc;
use std::time::Duration;

use near_mpc_contract_interface::types as dtos;
use tokio::sync::watch;

use crate::indexer::IndexerState;

const FOREIGN_CHAIN_POLICY_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// On read errors the previously published value stays in effect.
pub async fn monitor_available_foreign_chains(
    sender: watch::Sender<dtos::AvailableForeignChains>,
    indexer_state: Arc<IndexerState>,
) {
    indexer_state.client.wait_for_full_sync().await;

    loop {
        match indexer_state
            .view_client
            .get_available_chains(&indexer_state.mpc_contract_id)
            .await
        {
            Ok((_block_height, chains)) => {
                sender.send_if_modified(|previous| {
                    if *previous != chains {
                        *previous = chains;
                        true
                    } else {
                        false
                    }
                });
            }
            Err(e) => {
                tracing::error!(target: "mpc", "error reading available foreign chains from chain: {:?}", e);
            }
        }
        tokio::time::sleep(FOREIGN_CHAIN_POLICY_REFRESH_INTERVAL).await;
    }
}

/// On read errors the previously published value stays in effect.
pub async fn monitor_foreign_chains_configs(
    sender: watch::Sender<dtos::ForeignChainsConfigs>,
    indexer_state: Arc<IndexerState>,
) {
    indexer_state.client.wait_for_full_sync().await;

    loop {
        match indexer_state
            .view_client
            .get_foreign_chains_configs(&indexer_state.mpc_contract_id)
            .await
        {
            Ok((_block_height, configs)) => {
                sender.send_if_modified(|previous| {
                    if *previous != configs {
                        *previous = configs;
                        true
                    } else {
                        false
                    }
                });
            }
            Err(e) => {
                tracing::error!(target: "mpc", "error reading foreign chains configs from chain: {:?}", e);
            }
        }
        tokio::time::sleep(FOREIGN_CHAIN_POLICY_REFRESH_INTERVAL).await;
    }
}
