use std::future::IntoFuture;
use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder};
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_contract_transport::{ObservedState, ViewContract};
use near_mpc_contract_interface::client::MpcContractHandle;
use near_mpc_contract_interface::types::{
    AllowedMpcDockerImageHash, Ed25519PublicKey, GetAttestationResponse,
};
use tokio::sync::watch;

use crate::tee::attestation_freshness_metrics::record_stored_attestation;

const TEE_STATE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const MIN_BACKOFF_DURATION: Duration = Duration::from_secs(1);
const MAX_BACKOFF_DURATION: Duration = Duration::from_mins(1);

async fn monitor_tee_state<Fetcher, T, FetcherResponse, E>(
    sender: watch::Sender<T>,
    fetch_tee_state: &Fetcher,
) where
    T: PartialEq,
    Fetcher: Fn() -> FetcherResponse + Send + Sync,
    FetcherResponse: IntoFuture<Output = Result<ObservedState<T>, E>>,
    FetcherResponse::IntoFuture: Send,
    E: std::fmt::Debug,
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
                    Ok(observed) => {
                        break observed.value;
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

/// This future returns a [`watch::Receiver`] that will be continuously updated
/// with the latest allowed [`AllowedMpcDockerImageHash`]es when a change is
/// detected on the MPC smart contract.
pub async fn monitor_allowed_docker_images<V: ViewContract + Clone + Send + Sync + 'static>(
    sender: watch::Sender<Vec<AllowedMpcDockerImageHash>>,
    contract: MpcContractHandle<V>,
) {
    let fetcher = { || contract.allowed_docker_image_hashes() };

    monitor_tee_state(sender, &fetcher).await
}

/// This future returns a [`watch::Receiver`] that will be continuously updated
/// with the allowed [`LauncherDockerComposeHash`]es when a change is detected
/// on the MPC smart contract.
pub async fn monitor_allowed_launcher_compose_hashes<
    V: ViewContract + Clone + Send + Sync + 'static,
>(
    sender: watch::Sender<Vec<LauncherDockerComposeHash>>,
    contract: MpcContractHandle<V>,
) {
    let fetcher = { || contract.allowed_launcher_compose_hashes() };

    monitor_tee_state(sender, &fetcher).await
}

pub async fn monitor_my_attestation<V: ViewContract + Clone + Send + Sync + 'static>(
    sender: watch::Sender<Option<GetAttestationResponse>>,
    contract: MpcContractHandle<V>,
    tls_public_key: Ed25519PublicKey,
) {
    let fetcher = async || {
        contract
            .get_attestation(&tls_public_key)
            .await
            .inspect(|observed| record_stored_attestation(observed.value.as_ref()))
    };

    monitor_tee_state(sender, &fetcher).await
}
