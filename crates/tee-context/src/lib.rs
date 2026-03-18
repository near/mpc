mod errors;
mod types;

pub use errors::TeeContextError;
pub use types::{AllowedTeeHashes, SubmitParticipantInfoArgs, TeeNodeIdentity};

use std::sync::Arc;

use chain_gateway::{
    ChainGateway,
    state_viewer::{SubscribeToContractMethod, WatchContractState},
    transaction_sender::{SubmitFunctionCall, TransactionSigner},
};
use near_account_id::AccountId;
use near_indexer_primitives::types::Gas;
use near_mpc_contract_interface::method_names::{
    ALLOWED_DOCKER_IMAGE_HASHES, ALLOWED_LAUNCHER_COMPOSE_HASHES, SUBMIT_PARTICIPANT_INFO,
    VERIFY_TEE,
};
use near_mpc_contract_interface::types::{Attestation, Ed25519PublicKey};
use tokio::sync::watch;

use mpc_primitives::hash::{DockerImageHash, LauncherDockerComposeHash};

/// Shared TEE attestation lifecycle context.
///
/// Capabilities:
/// - Subscribes to changes in allowed image and launcher hashes.
/// - Submits attestations.
/// - Triggers on-chain re-validation of stored attestations.
#[derive(Clone)]
pub struct TeeContext {
    /// Contract that manages TEE attestations and allowed hashes.
    governance_contract: AccountId,
    /// Allowed TEE hashes from the governance contract.
    allowed_hashes_rx: watch::Receiver<AllowedTeeHashes>,
    /// Submits transactions to the governance contract.
    transaction_sender: TransactionSender,
}

impl TeeContext {
    /// Creates a new `TeeContext`.
    ///
    /// Subscribes to the governance contract's allowed image and launcher hash
    /// view methods, waits for the first successful poll of each, then spawns
    /// a background task that merges updates into a single
    /// [`AllowedTeeHashes`] watch channel.
    pub async fn new(
        chain_gateway: ChainGateway,
        governance_contract: AccountId,
        transaction_sender: TransactionSender,
    ) -> Result<Self, TeeContextError> {
        let rx = spawn_hash_watcher(chain_gateway, governance_contract.clone()).await?;

        Ok(Self {
            governance_contract,
            allowed_hashes_rx: rx,
            transaction_sender,
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
            )
            .await
    }

    /// Triggers on-chain re-validation of all stored attestations.
    pub async fn verify_tee(&self) -> Result<(), TeeContextError> {
        self.transaction_sender
            .submit(self.governance_contract.clone(), VERIFY_TEE, b"{}".to_vec())
            .await
    }
}

/// Bundles a [`ChainGateway`] with a [`TransactionSigner`] for submitting
/// transactions to the governance contract.
#[derive(Clone)]
pub struct TransactionSender {
    chain_gateway: ChainGateway,
    /// `Arc` because [`TransactionSigner`] holds a nonce counter (`Mutex<u64>`)
    /// and is not [`Clone`].
    signer: Arc<TransactionSigner>,
}

impl TransactionSender {
    pub fn new(chain_gateway: ChainGateway, signer: TransactionSigner) -> Self {
        Self {
            chain_gateway,
            signer: Arc::new(signer),
        }
    }

    async fn submit(
        &self,
        receiver_id: AccountId,
        method_name: &str,
        args: Vec<u8>,
    ) -> Result<(), TeeContextError> {
        const MAX_GAS: Gas = Gas::from_teragas(300);
        self.chain_gateway
            .submit_function_call_tx(
                &self.signer,
                receiver_id,
                method_name.to_string(),
                args,
                MAX_GAS,
            )
            .await?;
        Ok(())
    }
}

/// Subscribes to both allowed hash view methods on the governance contract and
/// merges updates into a single [`AllowedTeeHashes`] watch channel.
async fn spawn_hash_watcher(
    chain_gateway: ChainGateway,
    governance_contract: AccountId,
) -> Result<watch::Receiver<AllowedTeeHashes>, TeeContextError> {
    let (tx, mut rx) = watch::channel(AllowedTeeHashes::default());

    tokio::spawn(async move {
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

        let (Ok(image), Ok(launcher)) = (image_sub.latest(), launcher_sub.latest()) else {
            return;
        };

        tx.send_modify(|h| {
            h.allowed_docker_image_hashes = image.value;
            h.allowed_launcher_compose_hashes = launcher.value;
        });

        loop {
            tokio::select! {
                result = image_sub.changed() => {
                    if result.is_err() {
                        tracing::warn!("docker image hashes subscription closed");
                        break;
                    }
                    if let Ok(observed) = image_sub.latest() {
                        tx.send_modify(|h| h.allowed_docker_image_hashes = observed.value);
                    }
                }
                result = launcher_sub.changed() => {
                    if result.is_err() {
                        tracing::warn!("launcher compose hashes subscription closed");
                        break;
                    }
                    if let Ok(observed) = launcher_sub.latest() {
                        tx.send_modify(|h| h.allowed_launcher_compose_hashes = observed.value);
                    }
                }
            }
        }
    });

    rx.changed().await.map_err(|_| {
        TeeContextError::ChainGateway(chain_gateway::errors::ChainGatewayError::MonitoringClosed)
    })?;

    Ok(rx)
}
