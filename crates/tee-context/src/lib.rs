mod errors;
mod types;

pub use errors::TeeContextError;
pub use types::{AllowedTeeHashes, TeeNodeIdentity};

use std::sync::Arc;
use std::time::Duration;

use chain_gateway::primitives::{FetchLatestFinalBlockInfo, SubmitSignedTransaction};
use chain_gateway::transaction_sender::GatewaySender;
use near_account_id::AccountId;
use near_contract_transport::watch::Subscribe;
use near_kit_primitives::signer::InMemorySigner;
use near_kit_primitives::{Contract as _, Viewer};
use near_mpc_contract_interface::contract::{MpcContract, MpcContractClient};
use near_mpc_contract_interface::types::{Attestation, Ed25519PublicKey};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

type Client<G> = MpcContractClient<Arc<GatewaySender<G, InMemorySigner>>>;

/// Shared TEE attestation lifecycle context.
///
/// Capabilities:
/// - Subscribes to changes in allowed image and launcher hashes.
/// - Submits attestations.
/// - Triggers on-chain re-validation of stored attestations.
pub struct TeeContext<G> {
    /// Allowed TEE hashes from the governance contract.
    allowed_hashes_rx: watch::Receiver<AllowedTeeHashes>,
    /// Cancels the background hash-watcher task when [`TeeContext`] is dropped.
    _watcher_cancel: CancelOnDrop,
    /// Submits attestations and triggers re-validation.
    contract: Client<G>,
}

/// Cancels the background hash-watcher task when dropped.
struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl<G> TeeContext<G>
where
    G: FetchLatestFinalBlockInfo + SubmitSignedTransaction + Viewer + Send + Sync + 'static,
    G::ViewError: std::fmt::Display + Send + Sync + 'static,
{
    /// Creates a new [`TeeContext`].
    ///
    /// Polls the governance contract's allowed image and launcher hash
    /// views every `poll_interval`, waits for the first successful poll of
    /// each, then spawns a background task that merges updates into a single
    /// [`AllowedTeeHashes`] watch channel.
    pub async fn new(
        chain_gateway: G,
        governance_contract: AccountId,
        signer: InMemorySigner,
        poll_interval: Duration,
    ) -> Result<Self, TeeContextError> {
        let sender = Arc::new(GatewaySender::new(chain_gateway, signer));
        let contract = MpcContract::client(sender, governance_contract);
        let cancel = CancellationToken::new();
        let rx = spawn_hash_watcher(contract.clone(), poll_interval, cancel.clone()).await?;

        Ok(Self {
            allowed_hashes_rx: rx,
            _watcher_cancel: CancelOnDrop(cancel),
            contract,
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
        self.contract
            .submit_participant_info(attestation, tls_public_key)
            .await?;
        Ok(())
    }

    /// Triggers on-chain re-validation of all stored attestations.
    pub async fn verify_tee(&self) -> Result<(), TeeContextError> {
        self.contract.verify_tee().await?;
        Ok(())
    }
}

/// Watches both allowed hash views on the governance contract and merges
/// updates into a single [`AllowedTeeHashes`] watch channel.
async fn spawn_hash_watcher<V>(
    contract: MpcContractClient<V>,
    poll_interval: Duration,
    cancel: CancellationToken,
) -> Result<watch::Receiver<AllowedTeeHashes>, TeeContextError>
where
    V: Viewer<ViewError: std::fmt::Display + Send + Sync + 'static> + Clone + Send + Sync + 'static,
{
    let (tx, mut rx) = watch::channel(AllowedTeeHashes::default());

    tokio::spawn(watch_hashes(contract, poll_interval, tx, cancel));

    rx.changed()
        .await
        .map_err(|_| TeeContextError::HashWatcherClosed)?;

    Ok(rx)
}

/// Polls the governance contract for allowed image and launcher hashes,
/// merging updates into a single [`watch::Sender<AllowedTeeHashes>`].
///
/// Exits when the [`CancellationToken`] is cancelled or a watch closes.
async fn watch_hashes<V>(
    contract: MpcContractClient<V>,
    poll_interval: Duration,
    tx: watch::Sender<AllowedTeeHashes>,
    cancel: CancellationToken,
) where
    V: Viewer<ViewError: std::fmt::Display + Send + Sync + 'static> + Clone + Send + Sync + 'static,
{
    let images = contract.clone();
    let mut image_sub = images
        .allowed_docker_image_hashes()
        .subscribe(poll_interval)
        .await;
    let mut launcher_sub = contract
        .allowed_launcher_compose_hashes()
        .subscribe(poll_interval)
        .await;

    let (image, launcher) = match (
        image_sub.borrow_and_update().clone(),
        launcher_sub.borrow_and_update().clone(),
    ) {
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
        h.allowed_docker_image_hashes = image.result;
        h.allowed_launcher_compose_hashes = launcher.result;
    });

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("hash watcher cancelled");
                break;
            }
            result = image_sub.changed() => {
                if result.is_err() {
                    tracing::warn!("docker image hashes watch closed");
                    break;
                }
                match image_sub.borrow_and_update().clone() {
                    Ok(observed) => tx.send_modify(|h| h.allowed_docker_image_hashes = observed.result),
                    Err(err) => tracing::warn!(%err, "failed to read latest docker image hashes"),
                }
            }
            result = launcher_sub.changed() => {
                if result.is_err() {
                    tracing::warn!("launcher compose hashes watch closed");
                    break;
                }
                match launcher_sub.borrow_and_update().clone() {
                    Ok(observed) => tx.send_modify(|h| h.allowed_launcher_compose_hashes = observed.result),
                    Err(err) => tracing::warn!(%err, "failed to read latest launcher compose hashes"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AllowedTeeHashes, TeeContext, TeeContextError, watch_hashes};
    use chain_gateway::{
        errors::ChainGatewayError,
        mock::{MockChainState, MockChainStateBuilder, MockError, ViewResponse},
        transaction_sender::SendFailure,
        types::LatestFinalBlockInfo,
    };
    use mpc_primitives::hash::LauncherDockerComposeHash;
    use near_account_id::AccountId;
    use near_kit_primitives::rpc::ViewFunctionResult;
    use near_kit_primitives::signer::{InMemorySigner, SecretKey};
    use near_kit_primitives::{Contract as _, ContractError, CryptoHash};
    use near_mpc_contract_interface::contract::MpcContract;
    use near_mpc_contract_interface::method_names::ALLOWED_LAUNCHER_COMPOSE_HASHES;
    use near_mpc_contract_interface::types::{
        AllowedMpcDockerImageHash, Attestation, Ed25519PublicKey, MockAttestation,
    };
    use std::assert_matches;
    use tokio::sync::watch;
    use tokio_util::sync::CancellationToken;
    /// Block height returned by [`MockChainState`] view responses.
    const MOCK_BLOCK_HEIGHT: u64 = 1;

    /// Arbitrary digests reused as both image and launcher hashes.
    const ALLOWED_HASHES: [([u8; 32], Option<u64>); 3] = [
        ([1u8; 32], None),
        ([2u8; 32], Some(1)),
        ([3u8; 32], Some(2)),
    ];

    /// NEAR account ID of the governance contract used in tests.
    const GOVERNANCE_ACCOUNT: &str = "governance.testnet";

    fn governance_account() -> AccountId {
        GOVERNANCE_ACCOUNT.parse().unwrap()
    }

    fn allowed_image_hashes() -> Vec<AllowedMpcDockerImageHash> {
        ALLOWED_HASHES
            .map(|(hash, expiry)| AllowedMpcDockerImageHash {
                image_hash: hash.into(),
                expiry_timestamp_seconds: expiry,
            })
            .to_vec()
    }

    fn allowed_launcher_hashes() -> Vec<LauncherDockerComposeHash> {
        ALLOWED_HASHES.map(|(hash, _)| hash.into()).to_vec()
    }

    fn raw_view(value: &impl serde::Serialize, height: u64) -> ViewResponse {
        Ok(ViewFunctionResult::new(
            serde_json::to_vec(value).unwrap(),
            height,
            CryptoHash::default(),
        ))
    }

    fn mock_chain() -> MockChainState {
        let mock = MockChainStateBuilder::new()
            .with_view_response(raw_view(&allowed_image_hashes(), MOCK_BLOCK_HEIGHT))
            .build();
        mock.set_view_response_for_method(
            ALLOWED_LAUNCHER_COMPOSE_HASHES,
            raw_view(&allowed_launcher_hashes(), MOCK_BLOCK_HEIGHT),
        );
        mock
    }

    fn test_signer() -> InMemorySigner {
        InMemorySigner::new(
            "test.near".parse::<AccountId>().unwrap(),
            SecretKey::ed25519_from_bytes([1u8; 32]),
        )
    }

    fn default_block_info() -> LatestFinalBlockInfo {
        LatestFinalBlockInfo {
            height: MOCK_BLOCK_HEIGHT.into(),
            hash: Default::default(),
        }
    }

    async fn create_context_with(
        latest_block: Result<LatestFinalBlockInfo, MockError>,
        submit_response: Result<(), MockError>,
    ) -> TeeContext<MockChainState> {
        let mock = MockChainStateBuilder::new()
            .with_view_response(raw_view(&allowed_image_hashes(), MOCK_BLOCK_HEIGHT))
            .with_latest_block(latest_block)
            .with_signed_transaction_submitter_response(submit_response)
            .build();
        mock.set_view_response_for_method(
            ALLOWED_LAUNCHER_COMPOSE_HASHES,
            raw_view(&allowed_launcher_hashes(), MOCK_BLOCK_HEIGHT),
        );
        TeeContext::new(
            mock,
            governance_account(),
            test_signer(),
            MockChainState::POLL_INTERVAL,
        )
        .await
        .unwrap()
    }

    async fn create_test_context() -> (TeeContext<MockChainState>, MockChainState) {
        let mock = MockChainStateBuilder::new()
            .with_view_response(raw_view(&allowed_image_hashes(), MOCK_BLOCK_HEIGHT))
            .with_latest_block(Ok(default_block_info()))
            .with_signed_transaction_submitter_response(Ok(()))
            .build();
        mock.set_view_response_for_method(
            ALLOWED_LAUNCHER_COMPOSE_HASHES,
            raw_view(&allowed_launcher_hashes(), MOCK_BLOCK_HEIGHT),
        );
        let ctx = TeeContext::new(
            mock.clone(),
            governance_account(),
            test_signer(),
            MockChainState::POLL_INTERVAL,
        )
        .await
        .unwrap();
        (ctx, mock)
    }

    macro_rules! assert_call_error {
        ($result:expr, $pattern:pat) => {
            assert_matches!(
                $result,
                Err(TeeContextError::ContractCall(ContractError::Backend(
                    SendFailure {
                        error: $pattern,
                        ..
                    }
                )))
            )
        };
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
        ctx.submit_attestation(attestation, tls_key).await.unwrap();

        let txs = mock_chain.signed_transactions();
        assert_eq!(txs.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_verify_tee() {
        let (ctx, mock_chain) = create_test_context().await;
        ctx.verify_tee().await.unwrap();

        let txs = mock_chain.signed_transactions();
        assert_eq!(txs.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_submit_attestation_propagates_fetch_block_error() {
        let ctx = create_context_with(Err(MockError::LatestFinalBlockError), Ok(())).await;
        let result = ctx
            .submit_attestation(
                Attestation::Mock(MockAttestation::Valid),
                Ed25519PublicKey([0u8; 32]),
            )
            .await;
        assert_call_error!(result, ChainGatewayError::FetchFinalBlock { .. });
    }

    #[tokio::test(start_paused = true)]
    async fn test_verify_tee_propagates_fetch_block_error() {
        let ctx = create_context_with(Err(MockError::LatestFinalBlockError), Ok(())).await;
        let result = ctx.verify_tee().await;
        assert_call_error!(result, ChainGatewayError::FetchFinalBlock { .. });
    }

    #[tokio::test(start_paused = true)]
    async fn test_submit_attestation_propagates_submit_error() {
        let ctx = create_context_with(Ok(default_block_info()), Err(MockError::RpcError)).await;
        let result = ctx
            .submit_attestation(
                Attestation::Mock(MockAttestation::Valid),
                Ed25519PublicKey([0u8; 32]),
            )
            .await;
        assert_call_error!(result, ChainGatewayError::SubmitSignedTransaction { .. });
    }

    #[tokio::test(start_paused = true)]
    async fn test_verify_tee_propagates_submit_error() {
        let ctx = create_context_with(Ok(default_block_info()), Err(MockError::RpcError)).await;
        let result = ctx.verify_tee().await;
        assert_call_error!(result, ChainGatewayError::SubmitSignedTransaction { .. });
    }

    #[tokio::test(start_paused = true)]
    async fn test_new_fails_when_view_errors() {
        let mock = MockChainStateBuilder::new()
            .with_view_response(Err(MockError::View("view failed")))
            .build();

        let result = TeeContext::new(
            mock.clone(),
            governance_account(),
            test_signer(),
            MockChainState::POLL_INTERVAL,
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
            .with_view_response(Err(MockError::View("view failed")))
            .build();
        let (tx, mut rx) = watch::channel(AllowedTeeHashes::default());

        watch_hashes(
            MpcContract::client(mock, governance_account()),
            MockChainState::POLL_INTERVAL,
            tx,
            CancellationToken::new(),
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
            _ = watch_hashes(
                MpcContract::client(mock, governance_account()),
                MockChainState::POLL_INTERVAL,
                tx,
                cancel,
            ) => {}
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
        let updated_image = vec![AllowedMpcDockerImageHash {
            image_hash: updated_bytes.into(),
            expiry_timestamp_seconds: Some(99),
        }];
        let updated_launcher = vec![LauncherDockerComposeHash::from(updated_bytes)];

        let cancel_clone = cancel.clone();
        let mock_clone = mock.clone();
        let expected_image = updated_image.clone();
        tokio::select! {
            _ = watch_hashes(
                MpcContract::client(mock.clone(), governance_account()),
                MockChainState::POLL_INTERVAL,
                tx,
                cancel,
            ) => {}
            _ = async {
                rx.changed().await.unwrap();
                // Confirm initial value differs from the update we're about to make.
                assert_ne!(rx.borrow().allowed_docker_image_hashes, expected_image);
                mock_clone.set_view_response(raw_view(&updated_image, MOCK_BLOCK_HEIGHT + 1));
                mock_clone.set_view_response_for_method(
                    ALLOWED_LAUNCHER_COMPOSE_HASHES,
                    raw_view(&updated_launcher, MOCK_BLOCK_HEIGHT + 1),
                );
                tokio::time::sleep(MockChainState::POLL_INTERVAL * 3).await;
                rx.changed().await.unwrap();
                cancel_clone.cancel();
            } => {}
        }

        assert_eq!(
            *rx.borrow(),
            AllowedTeeHashes {
                allowed_docker_image_hashes: expected_image,
                allowed_launcher_compose_hashes: updated_launcher,
            }
        );
    }
}
