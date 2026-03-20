mod errors;
mod types;

pub use errors::TeeContextError;
pub use near_mpc_contract_interface::types::SubmitParticipantInfoArgs;
pub use types::{AllowedTeeHashes, TeeNodeIdentity};

use chain_gateway::{
    Gas,
    state_viewer::{SubscribeToContractMethod, WatchContractState},
    transaction_sender::{SubmitTransaction, TransactionSender},
};
use near_account_id::AccountId;
use near_mpc_contract_interface::method_names::{
    ALLOWED_DOCKER_IMAGE_HASHES, ALLOWED_LAUNCHER_COMPOSE_HASHES, SUBMIT_PARTICIPANT_INFO,
    VERIFY_TEE,
};
use near_mpc_contract_interface::types::{Attestation, Ed25519PublicKey};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use mpc_primitives::hash::{DockerImageHash, LauncherDockerComposeHash};

const SUBMIT_ATTESTATION_GAS: Gas = Gas::from_teragas(300);
const VERIFY_TEE_GAS: Gas = Gas::from_teragas(300);

/// Shared TEE attestation lifecycle context.
///
/// Capabilities:
/// - Subscribes to changes in allowed image and launcher hashes.
/// - Submits attestations.
/// - Triggers on-chain re-validation of stored attestations.
pub struct TeeContext<S: SubmitTransaction = TransactionSender> {
    /// Contract that manages TEE attestations and allowed hashes.
    governance_contract: AccountId,
    /// Allowed TEE hashes from the governance contract.
    allowed_hashes_rx: watch::Receiver<AllowedTeeHashes>,
    /// Submits transactions to the governance contract.
    transaction_sender: S,
    /// Cancels the background hash-watcher task when `TeeContext` is dropped.
    _watcher_cancel: CancelOnDrop,
}

/// Cancels the background hash-watcher task when dropped.
struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl<S> TeeContext<S>
where
    S: SubmitTransaction,
    S::Error: Into<TeeContextError>,
{
    /// Creates a new `TeeContext`.
    ///
    /// Subscribes to the governance contract's allowed image and launcher hash
    /// view methods, waits for the first successful poll of each, then spawns
    /// a background task that merges updates into a single
    /// [`AllowedTeeHashes`] watch channel.
    pub async fn new(
        chain_gateway: impl SubscribeToContractMethod + Send + 'static,
        governance_contract: AccountId,
        transaction_sender: S,
    ) -> Result<Self, TeeContextError> {
        let cancel = CancellationToken::new();
        let rx =
            spawn_hash_watcher(chain_gateway, governance_contract.clone(), cancel.clone()).await?;

        Ok(Self {
            governance_contract,
            allowed_hashes_rx: rx,
            transaction_sender,
            _watcher_cancel: CancelOnDrop(cancel),
        })
    }

    /// Returns a [`watch::Receiver`] for the allowed TEE hashes.
    ///
    /// Use [`watch::Receiver::borrow()`] to read the latest value,
    /// [`watch::Receiver::changed()`] to wait for updates.
    pub fn watch_allowed_tee_hashes(&self) -> watch::Receiver<AllowedTeeHashes> {
        self.allowed_hashes_rx.clone()
    }

    /// Submits an attestation to the governance contract.
    pub async fn submit_attestation(
        &self,
        attestation: Attestation,
        tls_public_key: Ed25519PublicKey,
    ) -> Result<(), TeeContextError> {
        let args = SubmitParticipantInfoArgs {
            proposed_participant_attestation: attestation,
            tls_public_key,
        };
        let args_json = serde_json::to_vec(&args)?;

        self.transaction_sender
            .submit(
                self.governance_contract.clone(),
                SUBMIT_PARTICIPANT_INFO,
                args_json,
                SUBMIT_ATTESTATION_GAS,
            )
            .await
            .map_err(Into::into)
    }

    /// Triggers on-chain re-validation of all stored attestations.
    pub async fn verify_tee(&self) -> Result<(), TeeContextError> {
        self.transaction_sender
            .submit(self.governance_contract.clone(), VERIFY_TEE, b"{}".to_vec(), VERIFY_TEE_GAS)
            .await
            .map_err(Into::into)
    }
}

/// Subscribes to both allowed hash view methods on the governance contract and
/// merges updates into a single [`AllowedTeeHashes`] watch channel.
async fn spawn_hash_watcher(
    chain_gateway: impl SubscribeToContractMethod + Send + 'static,
    governance_contract: AccountId,
    cancel: CancellationToken,
) -> Result<watch::Receiver<AllowedTeeHashes>, TeeContextError> {
    let (tx, mut rx) = watch::channel(AllowedTeeHashes::default());

    tokio::spawn(watch_hashes(chain_gateway, governance_contract, tx, cancel));

    rx.changed().await.map_err(|_| {
        TeeContextError::ChainGateway(chain_gateway::errors::ChainGatewayError::MonitoringClosed)
    })?;

    Ok(rx)
}

/// Polls the governance contract for allowed image and launcher hashes,
/// merging updates into a single [`watch::Sender<AllowedTeeHashes>`].
///
/// Exits when the [`CancellationToken`] is cancelled or a subscription closes.
async fn watch_hashes(
    chain_gateway: impl SubscribeToContractMethod,
    governance_contract: AccountId,
    tx: watch::Sender<AllowedTeeHashes>,
    cancel: CancellationToken,
) {
    let mut image_sub = chain_gateway
        .subscribe_to_contract_method::<Vec<DockerImageHash>>(
            governance_contract.clone(),
            ALLOWED_DOCKER_IMAGE_HASHES,
        )
        .await;

    let mut launcher_sub = chain_gateway
        .subscribe_to_contract_method::<Vec<LauncherDockerComposeHash>>(
            governance_contract,
            ALLOWED_LAUNCHER_COMPOSE_HASHES,
        )
        .await;

    let (image, launcher) = match (image_sub.latest(), launcher_sub.latest()) {
        (Ok(image), Ok(launcher)) => (image, launcher),
        (image_res, launcher_res) => {
            if let Err(err) = &image_res {
                tracing::error!(%err, "failed to fetch initial docker image hashes");
            }
            if let Err(err) = &launcher_res {
                tracing::error!(%err, "failed to fetch initial launcher compose hashes");
            }
            return;
        }
    };

    tx.send_modify(|h| {
        h.allowed_docker_image_hashes = image.value;
        h.allowed_launcher_compose_hashes = launcher.value;
    });

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("hash watcher cancelled");
                break;
            }
            result = image_sub.changed() => {
                if result.is_err() {
                    tracing::warn!("docker image hashes subscription closed");
                    break;
                }
                match image_sub.latest() {
                    Ok(observed) => tx.send_modify(|h| h.allowed_docker_image_hashes = observed.value),
                    Err(err) => tracing::warn!(%err, "failed to read latest docker image hashes"),
                }
            }
            result = launcher_sub.changed() => {
                if result.is_err() {
                    tracing::warn!("launcher compose hashes subscription closed");
                    break;
                }
                match launcher_sub.latest() {
                    Ok(observed) => tx.send_modify(|h| h.allowed_launcher_compose_hashes = observed.value),
                    Err(err) => tracing::warn!(%err, "failed to read latest launcher compose hashes"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use chain_gateway::{
        errors::ChainGatewayError,
        mock::{MockChainState, MockError},
        types::ObservedState,
    };
    use near_mpc_contract_interface::types::{Attestation, MockAttestation};
    use std::sync::{Arc, Mutex};

    /// Block height returned by [`MockChainState`] view responses.
    const MOCK_BLOCK_HEIGHT: u64 = 1;

    /// Arbitrary 32-byte digests reused as both image and launcher hashes in tests.
    const ALLOWED_HASH_BYTES: [[u8; 32]; 3] = [[1u8; 32], [2u8; 32], [3u8; 32]];

    /// NEAR account ID of the governance contract used in tests.
    const GOVERNANCE_ACCOUNT: &str = "governance.testnet";

    /// A transaction captured by [`MockTransactionSender`].
    type RecordedCall = (AccountId, String, Vec<u8>);

    fn governance_account() -> AccountId {
        GOVERNANCE_ACCOUNT.parse().unwrap()
    }

    fn allowed_image_hashes() -> Vec<DockerImageHash> {
        ALLOWED_HASH_BYTES.map(DockerImageHash::from).to_vec()
    }

    fn allowed_launcher_hashes() -> Vec<LauncherDockerComposeHash> {
        ALLOWED_HASH_BYTES
            .map(LauncherDockerComposeHash::from)
            .to_vec()
    }

    /// Returns a [`MockChainState`] that responds with [`allowed_image_hashes`].
    fn mock_chain() -> MockChainState {
        MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_query_view_function_response(Ok(ObservedState {
                observed_at: MOCK_BLOCK_HEIGHT.into(),
                value: serde_json::to_vec(&allowed_image_hashes()).unwrap(),
            }))
            .build()
    }

    /// Fake [`TransactionSender`] that records submitted transactions
    /// instead of sending them on-chain. Optionally returns an error.
    #[derive(Clone, Default)]
    struct MockTransactionSender {
        calls: Arc<Mutex<Vec<RecordedCall>>>,
        error: Option<ChainGatewayError>,
    }

    impl MockTransactionSender {
        fn failing(error: ChainGatewayError) -> Self {
            Self {
                error: Some(error),
                ..Default::default()
            }
        }

        fn calls(&self) -> Vec<RecordedCall> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl SubmitTransaction for MockTransactionSender {
        type Error = ChainGatewayError;
        async fn submit(
            &self,
            receiver_id: AccountId,
            method_name: &str,
            args: Vec<u8>,
            _gas: Gas,
        ) -> Result<(), ChainGatewayError> {
            if let Some(err) = &self.error {
                return Err(err.clone());
            }
            self.calls
                .lock()
                .unwrap()
                .push((receiver_id, method_name.to_string(), args));
            Ok(())
        }
    }

    async fn create_test_context() -> (TeeContext<MockTransactionSender>, MockTransactionSender) {
        let mock_sender = MockTransactionSender::default();
        let ctx = TeeContext::new(mock_chain(), governance_account(), mock_sender.clone())
            .await
            .unwrap();
        (ctx, mock_sender)
    }

    #[tokio::test(start_paused = true)]
    async fn test_new_populates_allowed_hashes() {
        let (ctx, _) = create_test_context().await;
        // `MockChainState` returns the same response for all view calls,
        // so both hash types deserialize from the same bytes.
        assert_eq!(
            *ctx.watch_allowed_tee_hashes().borrow(),
            AllowedTeeHashes {
                allowed_docker_image_hashes: allowed_image_hashes(),
                allowed_launcher_compose_hashes: allowed_launcher_hashes(),
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_submit_attestation() {
        let (ctx, sender) = create_test_context().await;
        let attestation = Attestation::Mock(MockAttestation::Valid);
        let tls_key = Ed25519PublicKey([0u8; 32]);
        ctx.submit_attestation(attestation.clone(), tls_key.clone())
            .await
            .unwrap();

        let expected_args = serde_json::to_vec(&SubmitParticipantInfoArgs {
            proposed_participant_attestation: attestation,
            tls_public_key: tls_key,
        })
        .unwrap();
        assert_eq!(
            sender.calls(),
            vec![(
                governance_account(),
                SUBMIT_PARTICIPANT_INFO.to_string(),
                expected_args
            )]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_verify_tee() {
        let (ctx, sender) = create_test_context().await;
        ctx.verify_tee().await.unwrap();
        assert_eq!(
            sender.calls(),
            vec![(governance_account(), VERIFY_TEE.to_string(), b"{}".to_vec())]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_submit_attestation_propagates_transaction_error() {
        let mock_sender = MockTransactionSender::failing(ChainGatewayError::MonitoringClosed);
        let ctx = TeeContext::new(mock_chain(), governance_account(), mock_sender)
            .await
            .unwrap();

        let result = ctx
            .submit_attestation(
                Attestation::Mock(MockAttestation::Valid),
                Ed25519PublicKey([0u8; 32]),
            )
            .await;

        assert_matches!(result, Err(TeeContextError::ChainGateway(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn test_spawn_hash_watcher_fails_when_view_errors() {
        let mock = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_query_view_function_response(Err(MockError::ViewClientError))
            .build();

        let cancel = CancellationToken::new();
        let result = spawn_hash_watcher(mock, governance_account(), cancel).await;

        assert_matches!(result, Err(TeeContextError::ChainGateway(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn test_spawn_hash_watcher_initial_error_drops_sender() {
        let mock = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_query_view_function_response(Err(MockError::ViewClientError))
            .build();

        let cancel = CancellationToken::new();
        let result = spawn_hash_watcher(mock.clone(), governance_account(), cancel).await;
        assert_matches!(result, Err(TeeContextError::ChainGateway(_)));

        // The task exited on initial failure — no further polling should happen.
        assert_eq!(
            mock.await_next_view_call(std::time::Duration::from_secs(1))
                .await,
            Err(MockError::Timeout),
            "no additional polls should happen after initial failure"
        );
    }

    #[tokio::test]
    async fn test_drop_cancels_and_closes_receiver() {
        let (ctx, _) = create_test_context().await;

        // Clone the receiver so we can observe closure after dropping the context.
        let mut rx = ctx.watch_allowed_tee_hashes();

        // Dropping should cancel the background watcher loop.
        drop(ctx);

        // Once the watcher exits, the sender is dropped and changed() returns Err.
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), rx.changed()).await;
        assert!(res.is_ok(), "expected receiver to close after drop");
        assert!(
            res.unwrap().is_err(),
            "expected channel closed (sender dropped)"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_spawn_hash_watcher_updates_on_hash_change() {
        let mock = mock_chain();
        let cancel = CancellationToken::new();

        let mut rx = spawn_hash_watcher(mock.clone(), governance_account(), cancel)
            .await
            .unwrap();

        assert_eq!(
            *rx.borrow(),
            AllowedTeeHashes {
                allowed_docker_image_hashes: allowed_image_hashes(),
                allowed_launcher_compose_hashes: allowed_launcher_hashes(),
            }
        );

        // Simulate a contract state change at a newer block height.
        let updated_bytes = [99u8; 32];
        let updated_image = vec![DockerImageHash::from(updated_bytes)];
        let updated_launcher = vec![LauncherDockerComposeHash::from(updated_bytes)];
        mock.set_view_response(Ok(ObservedState {
            observed_at: (MOCK_BLOCK_HEIGHT + 1).into(),
            value: serde_json::to_vec(&updated_image).unwrap(),
        }))
        .await;

        // Advance time past the poll interval to trigger the update.
        tokio::time::sleep(chain_gateway::state_viewer::POLL_INTERVAL * 3).await;

        rx.changed().await.unwrap();
        assert_eq!(
            *rx.borrow(),
            AllowedTeeHashes {
                allowed_docker_image_hashes: updated_image,
                allowed_launcher_compose_hashes: updated_launcher,
            }
        );
    }

    /// Verifies that `watch_hashes` returns immediately (dropping the sender)
    /// when the initial hash fetch fails, rather than entering the poll loop.
    #[tokio::test(start_paused = true)]
    async fn test_watch_hashes_exits_on_initial_error() {
        let mock = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_query_view_function_response(Err(MockError::ViewClientError))
            .build();
        let (tx, mut rx) = watch::channel(AllowedTeeHashes::default());

        watch_hashes(mock, governance_account(), tx, CancellationToken::new()).await;

        assert!(rx.changed().await.is_err(), "sender should be dropped");
    }

    /// Verifies that cancelling the token causes `watch_hashes` to exit its
    /// poll loop and drop the sender, closing the watch channel.
    #[tokio::test(start_paused = true)]
    async fn test_watch_hashes_exits_on_cancellation() {
        let mock = mock_chain();
        let cancel = CancellationToken::new();
        let (tx, mut rx) = watch::channel(AllowedTeeHashes::default());

        let cancel_clone = cancel.clone();
        tokio::select! {
            _ = watch_hashes(mock, governance_account(), tx, cancel) => {}
            _ = async {
                rx.changed().await.unwrap();
                cancel_clone.cancel();
            } => {}
        }

        assert!(rx.changed().await.is_err(), "sender should be dropped");
    }

    /// Verifies that when the governance contract's view response changes,
    /// `watch_hashes` detects the update on the next poll cycle and sends
    /// the new hashes through the watch channel.
    #[tokio::test(start_paused = true)]
    async fn test_watch_hashes_propagates_updates() {
        let mock = mock_chain();
        let cancel = CancellationToken::new();
        let (tx, mut rx) = watch::channel(AllowedTeeHashes::default());

        let updated_bytes = [99u8; 32];
        let updated_image = vec![DockerImageHash::from(updated_bytes)];
        let updated_launcher = vec![LauncherDockerComposeHash::from(updated_bytes)];

        let cancel_clone = cancel.clone();
        let mock_clone = mock.clone();
        let expected_image = updated_image.clone();
        tokio::select! {
            _ = watch_hashes(mock, governance_account(), tx, cancel) => {}
            _ = async {
                rx.changed().await.unwrap();
                // Confirm initial value differs from the update we're about to make.
                assert_ne!(rx.borrow().allowed_docker_image_hashes, expected_image);
                mock_clone.set_view_response(Ok(ObservedState {
                    observed_at: (MOCK_BLOCK_HEIGHT + 1).into(),
                    value: serde_json::to_vec(&expected_image).unwrap(),
                })).await;
                tokio::time::sleep(chain_gateway::state_viewer::POLL_INTERVAL * 3).await;
                rx.changed().await.unwrap();
                cancel_clone.cancel();
            } => {}
        }

        assert_eq!(
            *rx.borrow(),
            AllowedTeeHashes {
                allowed_docker_image_hashes: updated_image,
                allowed_launcher_compose_hashes: updated_launcher,
            }
        );
    }
}
