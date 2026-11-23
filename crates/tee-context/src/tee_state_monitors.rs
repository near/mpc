use std::future::IntoFuture;
use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder};
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_contract_transport::{ObservedState, ViewContract};
use near_mpc_contract_interface::client::MpcContractHandle;
use near_mpc_contract_interface::types::{
    AllowedMpcDockerImageHash, Ed25519PublicKey, ExpectedMeasurements, StoredAttestation,
};
use tokio::sync::watch;

use crate::attestation_freshness_metrics::record_stored_attestation;

/// Keeps [`TeeStateReceivers`] up to date with the contract.
pub struct TeeStateMonitors {
    allowed_image_hashes: watch::Sender<Vec<AllowedMpcDockerImageHash>>,
    allowed_launcher_compose_hashes: watch::Sender<Vec<LauncherDockerComposeHash>>,
    allowed_os_measurements: watch::Sender<Vec<ExpectedMeasurements>>,
    stored_attestation: watch::Sender<Option<StoredAttestation>>,
}

/// The TEE state on the contract that an attestation is checked against. Each value is empty
/// until its first successful read.
#[derive(Clone)]
pub struct TeeStateReceivers {
    pub allowed_image_hashes: watch::Receiver<Vec<AllowedMpcDockerImageHash>>,
    pub allowed_launcher_compose_hashes: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    pub allowed_os_measurements: watch::Receiver<Vec<ExpectedMeasurements>>,
    /// The attestation the contract stores for the TLS key passed to [`TeeStateMonitors::spawn`].
    pub stored_attestation: watch::Receiver<Option<StoredAttestation>>,
}

impl TeeStateMonitors {
    pub fn new() -> (Self, TeeStateReceivers) {
        let monitors = Self {
            allowed_image_hashes: watch::Sender::new(vec![]),
            allowed_launcher_compose_hashes: watch::Sender::new(vec![]),
            allowed_os_measurements: watch::Sender::new(vec![]),
            stored_attestation: watch::Sender::new(None),
        };
        let receivers = TeeStateReceivers {
            allowed_image_hashes: monitors.allowed_image_hashes.subscribe(),
            allowed_launcher_compose_hashes: monitors.allowed_launcher_compose_hashes.subscribe(),
            allowed_os_measurements: monitors.allowed_os_measurements.subscribe(),
            stored_attestation: monitors.stored_attestation.subscribe(),
        };
        (monitors, receivers)
    }

    /// Spawns one task per view on the current Tokio runtime. The tasks retry failed reads
    /// forever.
    pub fn spawn<V: ViewContract + Clone + Send + Sync + 'static>(
        self,
        contract: MpcContractHandle<V>,
        tls_public_key: Ed25519PublicKey,
    ) {
        tokio::spawn(monitor_allowed_docker_images(
            self.allowed_image_hashes,
            contract.clone(),
        ));
        tokio::spawn(monitor_allowed_launcher_compose_hashes(
            self.allowed_launcher_compose_hashes,
            contract.clone(),
        ));
        tokio::spawn(monitor_allowed_os_measurements(
            self.allowed_os_measurements,
            contract.clone(),
        ));
        tokio::spawn(monitor_my_attestation(
            self.stored_attestation,
            contract,
            tls_public_key,
        ));
    }
}

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

async fn monitor_allowed_docker_images<V: ViewContract + Clone + Send + Sync + 'static>(
    sender: watch::Sender<Vec<AllowedMpcDockerImageHash>>,
    contract: MpcContractHandle<V>,
) {
    let fetcher = { || contract.allowed_docker_image_hashes() };

    monitor_tee_state(sender, &fetcher).await
}

async fn monitor_allowed_launcher_compose_hashes<
    V: ViewContract + Clone + Send + Sync + 'static,
>(
    sender: watch::Sender<Vec<LauncherDockerComposeHash>>,
    contract: MpcContractHandle<V>,
) {
    let fetcher = { || contract.allowed_launcher_compose_hashes() };

    monitor_tee_state(sender, &fetcher).await
}

async fn monitor_allowed_os_measurements<V: ViewContract + Clone + Send + Sync + 'static>(
    sender: watch::Sender<Vec<ExpectedMeasurements>>,
    contract: MpcContractHandle<V>,
) {
    let fetcher = { || contract.allowed_os_measurements() };

    monitor_tee_state(sender, &fetcher).await
}

async fn monitor_my_attestation<V: ViewContract + Clone + Send + Sync + 'static>(
    sender: watch::Sender<Option<StoredAttestation>>,
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
