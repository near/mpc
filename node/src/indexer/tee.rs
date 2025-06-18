use std::{sync::Arc, time::Duration};

use backon::{BackoffBuilder, ExponentialBuilder};
use mpc_contract::tee::proposal::AllowedDockerImageHash;
use tokio::sync::watch;

use crate::indexer::{
    lib::{get_mpc_tee_state, wait_for_full_sync},
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
    indexer_state: Arc<IndexerState>,
) -> watch::Receiver<Vec<AllowedDockerImageHash>> {
    tracing::debug!(target: "indexer", "awaiting full sync to read mpc contract state");
    wait_for_full_sync(&indexer_state.client).await;

    let fetch_allowed_image_hashes = {
        async move || {
            let mut backoff = ExponentialBuilder::default()
                .with_min_delay(MIN_BACKOFF_DURATION)
                .with_max_delay(MAX_BACKOFF_DURATION)
                .without_max_times()
                .with_jitter()
                .build();

            loop {
                match get_mpc_tee_state(
                    indexer_state.mpc_contract_id.clone(),
                    &indexer_state.view_client,
                )
                .await
                {
                    Ok((block_height, mut allowed_images_on_contract)) => {
                        let allowed_images: Vec<AllowedDockerImageHash> =
                            allowed_images_on_contract.get(block_height);
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

    let initial_state = fetch_allowed_image_hashes().await;
    let (sender, receiver) = watch::channel(initial_state);

    actix::spawn(async move {
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
    });

    receiver
}
