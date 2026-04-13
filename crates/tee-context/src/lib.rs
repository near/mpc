mod errors;
mod types;

pub use errors::TeeContextError;
pub use near_mpc_contract_interface::types::SubmitParticipantInfoArgs;
pub use types::{AllowedTeeHashes, TeeNodeIdentity};

use chain_gateway::{
    Gas,
    state_viewer::{SubscribeToContractMethod, WatchContractState},
    transaction_sender::{SubmitFunctionCall, TransactionSigner},
};
use near_account_id::AccountId;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{Attestation, Ed25519PublicKey};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use mpc_primitives::hash::{DockerImageHash, LauncherDockerComposeHash};

/// Configurable method names for different TEE-enabled services.
///
/// MPC nodes and backup services use different contract methods for
/// attestation submission and allowed hash queries.
#[derive(Clone, Debug)]
pub struct TeeContextConfig {
    pub submit_attestation_method: &'static str,
    pub verify_method: &'static str,
    pub allowed_image_hashes_method: &'static str,
    pub allowed_launcher_compose_hashes_method: &'static str,
}

impl TeeContextConfig {
    pub fn mpc_node() -> Self {
        Self {
            submit_attestation_method: method_names::SUBMIT_PARTICIPANT_INFO,
            verify_method: method_names::VERIFY_TEE,
            allowed_image_hashes_method: method_names::ALLOWED_DOCKER_IMAGE_HASHES,
            allowed_launcher_compose_hashes_method: method_names::ALLOWED_LAUNCHER_COMPOSE_HASHES,
        }
    }

    pub fn backup_service() -> Self {
        Self {
            submit_attestation_method: method_names::REGISTER_BACKUP_SERVICE_WITH_ATTESTATION,
            verify_method: method_names::REVERIFY_BACKUP_SERVICES,
            allowed_image_hashes_method: method_names::ALLOWED_BACKUP_SERVICE_CODE_HASHES,
            allowed_launcher_compose_hashes_method:
                method_names::ALLOWED_BACKUP_SERVICE_LAUNCHER_COMPOSE_HASHES,
        }
    }
}

const SUBMIT_ATTESTATION_GAS: Gas = Gas::from_teragas(300);
const VERIFY_TEE_GAS: Gas = Gas::from_teragas(300);

/// Shared TEE attestation lifecycle context.
///
/// Capabilities:
/// - Subscribes to changes in allowed image and launcher hashes.
/// - Submits attestations.
/// - Triggers on-chain re-validation of stored attestations.
pub struct TeeContext<S> {
    /// Contract that manages TEE attestations and allowed hashes.
    governance_contract: AccountId,
    /// Configurable method names for this service type
    config: TeeContextConfig,
    /// Allowed TEE hashes from the governance contract.
    allowed_hashes_rx: watch::Receiver<AllowedTeeHashes>,
    /// Cancels the background hash-watcher task when `TeeContext` is dropped.
    _watcher_cancel: CancelOnDrop,
    submitter: S,
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
    S: SubmitFunctionCall + SubscribeToContractMethod + Clone + Send + 'static,
{
    /// Creates a new `TeeContext`.
    ///
    /// Subscribes to the governance contract's allowed image and launcher hash
    /// view methods, waits for the first successful poll of each, then spawns
    /// a background task that merges updates into a single
    /// [`AllowedTeeHashes`] watch channel.
    pub async fn new(
        chain_gateway: S,
        governance_contract: AccountId,
        config: TeeContextConfig,
    ) -> Result<Self, TeeContextError> {
        let cancel = CancellationToken::new();
        let rx = spawn_hash_watcher(
            chain_gateway.clone(),
            governance_contract.clone(),
            cancel.clone(),
            &config,
        )
        .await?;

        Ok(Self {
            governance_contract,
            config,
            allowed_hashes_rx: rx,
            _watcher_cancel: CancelOnDrop(cancel),
            submitter: chain_gateway,
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
        signer: &TransactionSigner,
        attestation: Attestation,
        tls_public_key: Ed25519PublicKey,
    ) -> Result<(), TeeContextError> {
        let args = SubmitParticipantInfoArgs {
            proposed_participant_attestation: attestation,
            tls_public_key,
        };
        let args_json = serde_json::to_vec(&args)?;

        self.submitter
            .submit_function_call_tx(
                signer,
                self.governance_contract.clone(),
                self.config.submit_attestation_method.to_string(),
                args_json,
                SUBMIT_ATTESTATION_GAS,
            )
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    /// Triggers on-chain re-validation of all stored attestations.
    pub async fn verify_tee(&self, signer: &TransactionSigner) -> Result<(), TeeContextError> {
        self.submitter
            .submit_function_call_tx(
                signer,
                self.governance_contract.clone(),
                self.config.verify_method.to_string(),
                b"{}".to_vec(),
                VERIFY_TEE_GAS,
            )
            .await
            .map(|_| ())
            .map_err(Into::into)
    }
}

/// Subscribes to both allowed hash view methods on the governance contract and
/// merges updates into a single [`AllowedTeeHashes`] watch channel.
async fn spawn_hash_watcher(
    chain_gateway: impl SubscribeToContractMethod + Send + 'static,
    governance_contract: AccountId,
    cancel: CancellationToken,
    config: &TeeContextConfig,
) -> Result<watch::Receiver<AllowedTeeHashes>, TeeContextError> {
    let (tx, mut rx) = watch::channel(AllowedTeeHashes::default());

    tokio::spawn(watch_hashes(
        chain_gateway,
        governance_contract,
        tx,
        cancel,
        config.allowed_image_hashes_method,
        config.allowed_launcher_compose_hashes_method,
    ));

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
    image_hashes_method: &'static str,
    launcher_compose_hashes_method: &'static str,
) {
    let mut image_sub = chain_gateway
        .subscribe_to_contract_method::<Vec<DockerImageHash>>(
            governance_contract.clone(),
            image_hashes_method,
        )
        .await;

    let mut launcher_sub = chain_gateway
        .subscribe_to_contract_method::<Vec<LauncherDockerComposeHash>>(
            governance_contract,
            launcher_compose_hashes_method,
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
        mock::{MockChainState, MockChainStateBuilder, MockError},
        types::{LatestFinalBlockInfo, ObservedState},
    };
    use ed25519_dalek::SigningKey;
    use near_mpc_contract_interface::types::{Attestation, MockAttestation};
    /// Block height returned by [`MockChainState`] view responses.
    const MOCK_BLOCK_HEIGHT: u64 = 1;

    /// Arbitrary 32-byte digests reused as both image and launcher hashes in tests.
    const ALLOWED_HASH_BYTES: [[u8; 32]; 3] = [[1u8; 32], [2u8; 32], [3u8; 32]];

    /// NEAR account ID of the governance contract used in tests.
    const GOVERNANCE_ACCOUNT: &str = "governance.testnet";

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

    fn mock_chain() -> MockChainState {
        MockChainStateBuilder::new()
            .with_syncing_status(Ok(false))
            .with_query_view_function_response(Ok(ObservedState {
                observed_at: MOCK_BLOCK_HEIGHT.into(),
                value: serde_json::to_vec(&allowed_image_hashes()).unwrap(),
            }))
            .build()
    }

    fn test_signer() -> TransactionSigner {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        TransactionSigner::from_key("test.near".parse().unwrap(), signing_key)
    }

    fn default_block_info() -> LatestFinalBlockInfo {
        LatestFinalBlockInfo {
            observed_at: MOCK_BLOCK_HEIGHT.into(),
            value: Default::default(),
        }
    }

    async fn create_context_with(
        latest_block: Result<LatestFinalBlockInfo, MockError>,
        submit_response: Result<(), MockError>,
    ) -> TeeContext<MockChainState> {
        let mock = MockChainStateBuilder::new()
            .with_syncing_status(Ok(false))
            .with_query_view_function_response(Ok(ObservedState {
                observed_at: MOCK_BLOCK_HEIGHT.into(),
                value: serde_json::to_vec(&allowed_image_hashes()).unwrap(),
            }))
            .with_latest_block(latest_block)
            .with_signed_transaction_submitter_response(submit_response)
            .build();
        TeeContext::new(mock, governance_account(), TeeContextConfig::mpc_node())
            .await
            .unwrap()
    }

    async fn create_test_context() -> (TeeContext<MockChainState>, MockChainState) {
        let mock_chain_state = MockChainStateBuilder::new()
            .with_syncing_status(Ok(false))
            .with_query_view_function_response(Ok(ObservedState {
                observed_at: MOCK_BLOCK_HEIGHT.into(),
                value: serde_json::to_vec(&allowed_image_hashes()).unwrap(),
            }))
            .with_latest_block(Ok(default_block_info()))
            .with_signed_transaction_submitter_response(Ok(()))
            .build();
        let ctx = TeeContext::new(
            mock_chain_state.clone(),
            governance_account(),
            TeeContextConfig::mpc_node(),
        )
        .await
        .unwrap();
        (ctx, mock_chain_state)
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
        let (ctx, mock_chain) = create_test_context().await;
        let attestation = Attestation::Mock(MockAttestation::Valid);
        let tls_key = Ed25519PublicKey([0u8; 32]);
        let signer = test_signer();
        ctx.submit_attestation(&signer, attestation, tls_key)
            .await
            .unwrap();

        let txs = mock_chain.signed_transactions().await;
        assert_eq!(txs.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_verify_tee() {
        let (ctx, mock_chain) = create_test_context().await;
        let signer = test_signer();
        ctx.verify_tee(&signer).await.unwrap();

        let txs = mock_chain.signed_transactions().await;
        assert_eq!(txs.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_submit_attestation_propagates_fetch_block_error() {
        let ctx = create_context_with(Err(MockError::LatestFinalBlockError), Ok(())).await;
        let result = ctx
            .submit_attestation(
                &test_signer(),
                Attestation::Mock(MockAttestation::Valid),
                Ed25519PublicKey([0u8; 32]),
            )
            .await;
        assert_matches!(result, Err(TeeContextError::ChainGateway(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn test_verify_tee_propagates_fetch_block_error() {
        let ctx = create_context_with(Err(MockError::LatestFinalBlockError), Ok(())).await;
        let result = ctx.verify_tee(&test_signer()).await;
        assert_matches!(result, Err(TeeContextError::ChainGateway(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn test_submit_attestation_propagates_submit_error() {
        let ctx = create_context_with(Ok(default_block_info()), Err(MockError::RpcError)).await;
        let result = ctx
            .submit_attestation(
                &test_signer(),
                Attestation::Mock(MockAttestation::Valid),
                Ed25519PublicKey([0u8; 32]),
            )
            .await;
        assert_matches!(result, Err(TeeContextError::ChainGateway(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn test_verify_tee_propagates_submit_error() {
        let ctx = create_context_with(Ok(default_block_info()), Err(MockError::RpcError)).await;
        let result = ctx.verify_tee(&test_signer()).await;
        assert_matches!(result, Err(TeeContextError::ChainGateway(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn test_new_fails_when_view_errors() {
        let mock = MockChainStateBuilder::new()
            .with_syncing_status(Ok(false))
            .with_query_view_function_response(Err(MockError::ViewClientError))
            .build();

        let result = TeeContext::new(
            mock.clone(),
            governance_account(),
            TeeContextConfig::mpc_node(),
        )
        .await;
        assert!(result.is_err());

        // The task exited on initial failure — no further polling should happen.
        assert_eq!(
            mock.await_next_view_call(std::time::Duration::from_secs(1))
                .await,
            Err(MockError::Timeout),
            "no additional polls should happen after initial failure"
        );
    }

    #[tokio::test(start_paused = true)]
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

    /// Verifies that `watch_hashes` returns immediately (dropping the sender)
    /// when the initial hash fetch fails, rather than entering the poll loop.
    #[tokio::test(start_paused = true)]
    async fn test_watch_hashes_exits_on_initial_error() {
        let mock = MockChainState::builder()
            .with_syncing_status(Ok(false))
            .with_query_view_function_response(Err(MockError::ViewClientError))
            .build();
        let (tx, mut rx) = watch::channel(AllowedTeeHashes::default());

        watch_hashes(
            mock,
            governance_account(),
            tx,
            CancellationToken::new(),
            method_names::ALLOWED_DOCKER_IMAGE_HASHES,
            method_names::ALLOWED_LAUNCHER_COMPOSE_HASHES,
        )
        .await;

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
            _ = watch_hashes(mock, governance_account(), tx, cancel, method_names::ALLOWED_DOCKER_IMAGE_HASHES, method_names::ALLOWED_LAUNCHER_COMPOSE_HASHES) => {}
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
            _ = watch_hashes(mock, governance_account(), tx, cancel, method_names::ALLOWED_DOCKER_IMAGE_HASHES, method_names::ALLOWED_LAUNCHER_COMPOSE_HASHES) => {}
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
