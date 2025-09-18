use std::{sync::Arc, time::Duration};

use backon::{BackoffBuilder, ExponentialBuilder};
use mpc_contract::tee::proposal::AllowedDockerImageHash;
use tokio::sync::watch;

use crate::indexer::{
    lib::{get_mpc_allowed_image_hashes, wait_for_full_sync},
    IndexerState,
};

const ALLOWED_IMAGE_HASHES_REFRESH_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(1);
const MIN_BACKOFF_DURATION: Duration = Duration::from_secs(1);
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);

/// This future waits for the indexer to fully sync, and returns
/// a [`watch::Receiver`] that will be continuously updated with the latest
/// allowed [`AllowedDockerImageHash`]es when a change is detected
/// on the MPC smart contract.
pub async fn monitor_allowed_docker_images(
    sender: watch::Sender<Vec<AllowedDockerImageHash>>,
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
        let new_tee_state = fetch_allowed_image_hashes().await;
        sender.send_if_modified(|previous_state| {
            if *previous_state != new_tee_state {
                *previous_state = new_tee_state;
                true
            } else {
                false
            }
        });
    }
}
