use crate::indexer::participants::KeyEventIdComparisonResult;
use crate::indexer::tx_sender::TransactionSender;
use crate::indexer::types::{
    ChainStartKeygenArgs, ChainStartReshareArgs, ChainVoteAbortKeyEventInstanceArgs,
};
use crate::network::MeshNetworkClient;
use crate::primitives::{Curve, DomainConfig, KeyEventId, KeyForDomain, Keyset};
use crate::primitives::{MpcTaskId, ParticipantId};
use crate::providers::eddsa::{EddsaSignatureProvider, EddsaTaskId};
use crate::providers::EcdsaTaskId;
use crate::tracking::AutoAbortTaskCollection;
use crate::{
    config::ParticipantsConfig,
    indexer::{
        participants::ContractKeyEventInstance,
        types::{ChainSendTransactionRequest, ChainVotePkArgs, ChainVoteResharedArgs},
    },
    keyshare::{Keyshare, KeyshareData, KeyshareStorage},
    network::NetworkTaskChannel,
    providers::{
        CKDProvider, EcdsaSignatureProvider, RobustEcdsaSignatureProvider, SignatureProvider,
    },
};
use near_mpc_contract_interface::types as dtos;
use std::sync::Arc;
use std::time::Duration;
use threshold_signatures::{
    confidential_key_derivation as ckd, frost_ed25519, frost_secp256k1, ReconstructionLowerBound,
};
use tokio::sync::{mpsc, watch, RwLock};
use tokio::time::timeout;
use tracing::{error, info};

/// The key generation computation (same for both leader and follower) for a single key generation
/// attempt:
/// - reserves the key_id in keyshare_storage and performs sanity checks
/// - runs the distributed computation with other participants
/// - commits the new keyshare to storage.
/// - votes for the generated public key.
pub async fn keygen_computation_inner(
    channel: NetworkTaskChannel,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    chain_txn_sender: impl TransactionSender,
    generated_keys: Vec<KeyForDomain>,
    key_id: KeyEventId,
    domain: DomainConfig,
    threshold: ReconstructionLowerBound,
) -> anyhow::Result<()> {
    anyhow::ensure!(key_id.domain_id == domain.id, "Domain mismatch");
    let keyshare_handle = keyshare_storage
        .write()
        .await
        .start_generating_key(&generated_keys, key_id)
        .await?;
    tracing::info!(
        "Key generation attempt {:?}: starting key generation.",
        key_id
    );

    let (keyshare, public_key) = match domain.curve {
        Curve::Secp256k1 => {
            let keyshare =
                EcdsaSignatureProvider::run_key_generation_client(threshold, channel).await?;
            let public_key = dtos::PublicKey::Secp256k1(dtos::Secp256k1PublicKey::try_from(
                keyshare.public_key.to_element().to_affine(),
            )?);
            (KeyshareData::Secp256k1(keyshare), public_key)
        }
        Curve::V2Secp256k1 => {
            let keyshare =
                RobustEcdsaSignatureProvider::run_key_generation_client(threshold, channel).await?;
            let public_key = dtos::PublicKey::Secp256k1(dtos::Secp256k1PublicKey::try_from(
                keyshare.public_key.to_element().to_affine(),
            )?);
            (KeyshareData::V2Secp256k1(keyshare), public_key)
        }
        Curve::Edwards25519 => {
            let keyshare =
                EddsaSignatureProvider::run_key_generation_client(threshold, channel).await?;
            let public_key = dtos::PublicKey::Ed25519(dtos::Ed25519PublicKey::from(
                keyshare.public_key.to_element().compress(),
            ));
            (KeyshareData::Ed25519(keyshare), public_key)
        }
        Curve::Bls12381 => {
            let keyshare = CKDProvider::run_key_generation_client(threshold, channel).await?;
            let public_key = dtos::PublicKey::Bls12381(dtos::Bls12381G2PublicKey::from(
                &keyshare.public_key.to_element(),
            ));
            (KeyshareData::Bls12381(keyshare), public_key)
        }
    };

    tracing::info!("Key generation attempt {:?}: committing keyshare.", key_id);
    keyshare_handle
        .commit_keyshare(Keyshare {
            key_id,
            data: keyshare,
        })
        .await?;
    tracing::info!(
        "Key generation attempt {:?}: sending vote_pk transaction.",
        key_id
    );
    chain_txn_sender
        .send(ChainSendTransactionRequest::VotePk(ChainVotePkArgs {
            key_event_id: key_id.into(),
            public_key,
        }))
        .await?;
    Ok(())
}

/// Wrapper around `keygen_computation_inner` which
///  - Waits for the key event to start.
///  - Interrupts the inner computation if the key event expires.
///  - Sends a `vote_abort_key_event_instance` transaction if the inner computation fails.
async fn keygen_computation(
    mut contract_key_event_id: watch::Receiver<ContractKeyEventInstance>,
    channel: NetworkTaskChannel,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    chain_txn_sender: impl TransactionSender,
    key_id: KeyEventId,
    threshold: ReconstructionLowerBound,
) -> anyhow::Result<()> {
    let key_event = wait_for_contract_catchup(&mut contract_key_event_id, key_id).await;
    let inner = keygen_computation_inner(
        channel,
        keyshare_storage,
        chain_txn_sender.clone(),
        key_event.completed_domains,
        key_id,
        key_event.domain,
        threshold,
    );
    let expiration = key_event_id_expiration(contract_key_event_id, key_id);
    tokio::select! {
        res = inner => {
            match res {
                Ok(()) => {
                    tracing::info!("Key generation attempt {:?} completed successfully.", key_id);
                },
                Err(err) => {
                    tracing::error!("Key generation attempt {:?} failed: {:?}; sending vote_abort_key_event_instance", key_id, err);
                    chain_txn_sender.send(ChainSendTransactionRequest::VoteAbortKeyEventInstance(ChainVoteAbortKeyEventInstanceArgs {
                        key_event_id: key_id.into(),
                    })).await?;
                },
            }
        },
        _ = expiration => anyhow::bail!("Key event expired before computation completed."),
    }
    Ok(())
}

#[derive(Clone)]
pub struct ResharingArgs {
    pub previous_keyset: Keyset,
    pub existing_keyshares: Option<Vec<Keyshare>>,
    pub new_threshold: ReconstructionLowerBound,
    pub old_participants: ParticipantsConfig,
}

/// The key resharing computation (same for both leader and follower) for a single key resharing
/// attempt:
/// - reserves the key_id in keyshare_storage and performs sanity checks
/// - runs the key resharing distributed computation with other participants
/// - commits the new keyshare to storage
/// - votes on the contract to conclude the resharing.
///
/// If existing keyshares in `ResharingArgs` is not None, then they must contain a matching keyshare
/// of same domain as `key_id`.
async fn resharing_computation_inner(
    channel: NetworkTaskChannel,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    chain_txn_sender: impl TransactionSender,
    reshared_keys: Vec<KeyForDomain>,
    key_id: KeyEventId,
    domain: DomainConfig,
    args: Arc<ResharingArgs>,
) -> anyhow::Result<()> {
    anyhow::ensure!(key_id.domain_id == domain.id, "Domain mismatch");
    let keyshare_handle = keyshare_storage
        .write()
        .await
        .start_resharing_key(&reshared_keys, key_id)
        .await?;
    tracing::info!(
        "Key resharing attempt {:?}: starting key resharing.",
        key_id
    );
    let existing_keyshare = match &args.existing_keyshares {
        Some(existing_keyshares) => Some(
            existing_keyshares
                .iter()
                .find(|keyshare| keyshare.key_id.domain_id == key_id.domain_id)
                .cloned()
                .ok_or_else(|| {
                    anyhow::anyhow!("Expected existing keyshare for {:?} not found", key_id)
                })?,
        ),
        None => None,
    };

    let previous_public_key = &args
        .previous_keyset
        .public_key(key_id.domain_id)
        .map_err(|_| anyhow::anyhow!("Previous keyset does not contain key for {:?}", key_id))?;

    let public_key = dtos::PublicKey::from(previous_public_key.clone());

    let keyshare_data = match (public_key, domain.curve) {
        (
            near_mpc_contract_interface::types::PublicKey::Secp256k1(inner_public_key),
            Curve::Secp256k1,
        ) => {
            let pk = k256::PublicKey::try_from(&inner_public_key)?;
            let public_key = frost_secp256k1::VerifyingKey::new(pk.to_projective());
            let my_share = existing_keyshare
                .map(|keyshare| match keyshare.data {
                    KeyshareData::Secp256k1(data) => Ok(data.private_share),
                    _ => Err(anyhow::anyhow!("Expected ecdsa keyshare!")),
                })
                .transpose()?;
            let res = EcdsaSignatureProvider::run_key_resharing_client(
                args.new_threshold,
                my_share,
                public_key,
                &args.old_participants,
                channel,
            )
            .await?;
            KeyshareData::Secp256k1(res)
        }
        (
            near_mpc_contract_interface::types::PublicKey::Secp256k1(inner_public_key),
            Curve::V2Secp256k1,
        ) => {
            let pk = k256::PublicKey::try_from(&inner_public_key)?;
            let public_key = frost_secp256k1::VerifyingKey::new(pk.to_projective());
            let my_share = existing_keyshare
                .map(|keyshare| match keyshare.data {
                    KeyshareData::V2Secp256k1(data) => Ok(data.private_share),
                    _ => Err(anyhow::anyhow!("Expected ecdsa keyshare!")),
                })
                .transpose()?;
            let res = RobustEcdsaSignatureProvider::run_key_resharing_client(
                args.new_threshold,
                my_share,
                public_key,
                &args.old_participants,
                channel,
            )
            .await?;
            KeyshareData::V2Secp256k1(res)
        }
        (
            near_mpc_contract_interface::types::PublicKey::Ed25519(inner_public_key),
            Curve::Edwards25519,
        ) => {
            let public_key = frost_ed25519::VerifyingKey::deserialize(inner_public_key.as_ref())?;
            let my_share = existing_keyshare
                .map(|keyshare| match keyshare.data {
                    KeyshareData::Ed25519(data) => Ok(data.private_share),
                    _ => Err(anyhow::anyhow!("Expected eddsa keyshare!")),
                })
                .transpose()?;
            let res = EddsaSignatureProvider::run_key_resharing_client(
                args.new_threshold,
                my_share,
                public_key,
                &args.old_participants,
                channel,
            )
            .await?;
            KeyshareData::Ed25519(res)
        }
        (dtos::PublicKey::Bls12381(inner_public_key), Curve::Bls12381) => {
            let public_key = ckd::VerifyingKey::new(ckd::ElementG2::try_from(&inner_public_key)?);
            let my_share = existing_keyshare
                .map(|keyshare| match keyshare.data {
                    KeyshareData::Bls12381(data) => Ok(data.private_share),
                    _ => Err(anyhow::anyhow!("Expected ckd keyshare!")),
                })
                .transpose()?;
            let res = CKDProvider::run_key_resharing_client(
                args.new_threshold,
                my_share,
                public_key,
                &args.old_participants,
                channel,
            )
            .await?;
            KeyshareData::Bls12381(res)
        }
        (public_key, curve) => {
            return Err(anyhow::anyhow!(
                "Unexpected pair of ({:?}, {:?})",
                public_key,
                curve
            ));
        }
    };
    tracing::info!("Key resharing attempt {:?}: committing keyshare.", key_id);
    keyshare_handle
        .commit_keyshare(Keyshare {
            key_id,
            data: keyshare_data,
        })
        .await?;
    tracing::info!(
        "Key resharing attempt {:?}: sending vote_reshared transaction.",
        key_id
    );
    chain_txn_sender
        .send(ChainSendTransactionRequest::VoteReshared(
            ChainVoteResharedArgs {
                key_event_id: key_id.into(),
            },
        ))
        .await?;
    Ok(())
}

/// Wrapper around `resharing_computation_inner` which
///  - Waits for the key event to start.
///  - Interrupts the inner computation if the key event expires.
///  - Sends a `vote_abort_key_event_instance` transaction if the inner computation fails.
async fn resharing_computation(
    mut contract_key_event_id: watch::Receiver<ContractKeyEventInstance>,
    channel: NetworkTaskChannel,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    chain_txn_sender: impl TransactionSender,
    key_id: KeyEventId,
    args: Arc<ResharingArgs>,
) -> anyhow::Result<()> {
    let key_event = wait_for_contract_catchup(&mut contract_key_event_id, key_id).await;
    let inner = resharing_computation_inner(
        channel,
        keyshare_storage,
        chain_txn_sender.clone(),
        key_event.completed_domains,
        key_id,
        key_event.domain,
        args,
    );
    let expiration = key_event_id_expiration(contract_key_event_id, key_id);
    tokio::select! {
        res = inner => {
            match res {
                Ok(()) => {
                    tracing::info!("Key resharing attempt {:?} completed successfully.", key_id);
                },
                Err(err) => {
                    tracing::error!("Key resharing attempt {:?} failed: {:?}; sending vote_abort_key_event_instance", key_id, err);
                    chain_txn_sender.send(ChainSendTransactionRequest::VoteAbortKeyEventInstance(ChainVoteAbortKeyEventInstanceArgs {
                        key_event_id: key_id.into(),
                    })).await?;
                },
            }
        },
        _ = expiration => anyhow::bail!("Key event expired before computation completed."),
    }
    Ok(())
}

/// Waits until the contract is no longer behind the key event ID.
///
/// By the time this function exits, it's possible the contract is already ahead of the key event
/// ID; that is fine.
async fn wait_for_contract_catchup(
    key_event_receiver: &mut watch::Receiver<ContractKeyEventInstance>,
    key_event_id: KeyEventId,
) -> ContractKeyEventInstance {
    key_event_receiver
        .wait_for(|contract_event| {
            !matches!(
                contract_event.compare_to_expected_key_event_id(&key_event_id),
                KeyEventIdComparisonResult::RemoteBehind
            )
        })
        .await
        .expect("Should not fail since closure does not panic")
        .clone()
}

/// Resolves as soon as the contract has moved past the key event ID.
async fn key_event_id_expiration(
    mut key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    key_event_id: KeyEventId,
) {
    key_event_receiver
        .wait_for(|contract_event| {
            matches!(
                contract_event.compare_to_expected_key_event_id(&key_event_id),
                KeyEventIdComparisonResult::RemoteAhead
            )
        })
        .await
        .expect("Should not fail since closure does not panic");
}

/// The leader waits for at most this amount of time for the start transaction to materialize,
/// before retrying.
const MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE: Duration = Duration::from_secs(20);

/// The leader logic for an entire key generation (initializing) state.
/// Handles multiple domains and attempts. It does not return, except in case of catastrophic
/// failure (node shutting down). The coordinator is expected to interrupt this when the
/// contract state transitions out of the key generation state.
pub async fn keygen_leader(
    client: impl KeyEventLeaderClient,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    mut key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    chain_txn_sender: impl TransactionSender,
    threshold: ReconstructionLowerBound,
) -> anyhow::Result<()> {
    loop {
        // Wait for all participants to be connected. Otherwise, computations are most likely going
        // to fail so don't waste the effort.
        client.wait_for_all_participants_connected().await?;

        // Wait for the contract to have no active key event instance.
        let key_event_id = key_event_receiver
            .wait_for(|contract_event| !contract_event.started)
            .await?
            .id;
        // Send txn to start the keygen instance. This may or may not end up in the chain; we'll
        // wait for it. If it doesn't happen after some time, we try again.
        chain_txn_sender
            .send(ChainSendTransactionRequest::StartKeygen(
                ChainStartKeygenArgs {
                    key_event_id: key_event_id.into(),
                },
            ))
            .await?;

        match timeout(
            MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE,
            key_event_receiver.wait_for(|contract_event| contract_event.started),
        )
        .await
        {
            Ok(res) => {
                let contract_key_event_id = res?.id;
                if contract_key_event_id != key_event_id {
                    tracing::warn!(
                        "Activated key event {:?} does not match expected {:?}; retrying.",
                        contract_key_event_id,
                        key_event_id
                    );
                    continue;
                }
            }
            Err(_) => {
                tracing::warn!(
                    "Key event {:?} did not activate in time; retrying.",
                    key_event_id
                );
                continue;
            }
        }

        // Start the keygen computation.
        let participants = client.all_participant_ids();
        let Ok(channel) = client.new_channel_for_task(
            EcdsaTaskId::KeyGeneration {
                key_event: key_event_id.into(),
            },
            participants,
        ) else {
            tracing::warn!("Failed to create channel for keygen computation; retrying.");
            continue;
        };

        if let Err(e) = keygen_computation(
            key_event_receiver.clone(),
            channel,
            keyshare_storage.clone(),
            chain_txn_sender.clone(),
            key_event_id,
            threshold,
        )
        .await
        {
            tracing::warn!(
                "Leader keygen computation {:?} failed, retrying: {:?}",
                key_event_id,
                e
            );
        }
    }
}

/// The follower logic for an entire key generation (initializing) state.
/// See `keygen_leader` for more details that are in common.
pub async fn keygen_follower(
    mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    chain_txn_sender: impl TransactionSender + 'static,
    threshold: ReconstructionLowerBound,
) -> anyhow::Result<()> {
    let mut tasks = AutoAbortTaskCollection::new();
    loop {
        let channel = channel_receiver
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Channel receiver closed unexpectedly; exiting."))?;
        let key_event_id = match channel.task_id() {
            crate::primitives::MpcTaskId::EcdsaTaskId(EcdsaTaskId::KeyGeneration { key_event }) => {
                key_event
            }
            crate::primitives::MpcTaskId::EddsaTaskId(EddsaTaskId::KeyGeneration { key_event }) => {
                key_event
            }
            _ => {
                tracing::info!("Ignoring non-keygen task {:?}", channel.task_id());
                continue;
            }
        };

        tasks.spawn_checked(
            &format!("key generation follower for {:?}", key_event_id),
            keygen_computation(
                key_event_receiver.clone(),
                channel,
                keyshare_storage.clone(),
                chain_txn_sender.clone(),
                key_event_id.into(),
                threshold,
            ),
        );
    }
}

/// The leader logic for an entire key resharing state.
/// See `keygen_leader` for more details that are in common.
pub async fn resharing_leader(
    client: impl KeyEventLeaderClient,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    mut key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    chain_txn_sender: impl TransactionSender,
    args: Arc<ResharingArgs>,
) -> anyhow::Result<()> {
    loop {
        info!("Waiting for a connection to all participants.");
        // Wait for all participants to be connected. Otherwise, computations are most likely going
        // to fail so don't waste the effort.
        client
            .wait_for_all_participants_connected()
            .await
            .inspect_err(|e| error!("Could not connect to all participants: {:?}", e))?;

        info!("Wait for the contract to have no active key event instance.");
        let key_event_id = key_event_receiver
            .wait_for(|contract_event| !contract_event.started)
            .await?
            .id;
        // Send txn to start the resharing instance. This may or may not end up in the chain; we'll
        // wait for it. If it doesn't happen after some time, we try again.
        info!("Sending StartReshare to contract.");

        chain_txn_sender
            .send(ChainSendTransactionRequest::StartReshare(
                ChainStartReshareArgs {
                    key_event_id: key_event_id.into(),
                },
            ))
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to send start resharing transaction to contract: {:?}",
                    e
                )
            })?;

        match timeout(
            MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE,
            key_event_receiver.wait_for(|contract_event| contract_event.started),
        )
        .await
        {
            Ok(res) => {
                let contract_key_event_id = res?.id;
                if contract_key_event_id != key_event_id {
                    tracing::warn!(
                        "Activated key event {:?} does not match expected {:?}; retrying.",
                        contract_key_event_id,
                        key_event_id
                    );
                    continue;
                }
            }
            Err(_) => {
                tracing::warn!(
                    "Key event {:?} did not activate in time; retrying.",
                    key_event_id
                );
                continue;
            }
        }

        // Start the resharing computation.
        info!("Starting resharing computation.");
        let participants = client.all_participant_ids();
        let channel = match client.new_channel_for_task(
            EcdsaTaskId::KeyResharing {
                key_event: key_event_id.into(),
            },
            participants,
        ) {
            Ok(channel) => channel,
            Err(err) => {
                tracing::warn!(error =%err, "Failed to create channel for resharing computation; retrying.");
                continue;
            }
        };

        if let Err(e) = resharing_computation(
            key_event_receiver.clone(),
            channel,
            keyshare_storage.clone(),
            chain_txn_sender.clone(),
            key_event_id,
            args.clone(),
        )
        .await
        {
            tracing::warn!(
                "Leader resharing computation {:?} failed, retrying: {:?}",
                key_event_id,
                e
            );
        }
    }
}

/// The follower logic for an entire key resharing state.
/// See `keygen_leader` for more details that are in common.
pub async fn resharing_follower(
    mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    chain_txn_sender: impl TransactionSender + 'static,
    args: Arc<ResharingArgs>,
) -> anyhow::Result<()> {
    let mut tasks = AutoAbortTaskCollection::new();
    loop {
        let channel = channel_receiver
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Channel receiver closed unexpectedly; exiting."))?;
        let key_event_id = match channel.task_id() {
            crate::primitives::MpcTaskId::EcdsaTaskId(EcdsaTaskId::KeyResharing { key_event }) => {
                key_event
            }
            crate::primitives::MpcTaskId::EddsaTaskId(EddsaTaskId::KeyResharing { key_event }) => {
                key_event
            }
            _ => {
                tracing::info!("Ignoring non-resharing task {:?}", channel.task_id());
                continue;
            }
        };

        tasks.spawn_checked(
            &format!("key resharing follower for {:?}", key_event_id),
            resharing_computation(
                key_event_receiver.clone(),
                channel,
                keyshare_storage.clone(),
                chain_txn_sender.clone(),
                key_event_id.into(),
                args.clone(),
            ),
        );
    }
}

/// Network interface used by key event leaders (`keygen_leader` and `resharing_leader`).
///
/// This trait abstracts the network operations needed by leader functions, making them
/// testable without a real mesh network.
pub trait KeyEventLeaderClient: Send + Sync {
    /// Waits until all participants in the network are connected.
    fn wait_for_all_participants_connected(
        &self,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;

    /// Creates a new network channel for the given MPC task.
    fn new_channel_for_task(
        &self,
        task_id: impl Into<MpcTaskId>,
        participants: Vec<ParticipantId>,
    ) -> anyhow::Result<NetworkTaskChannel>;

    /// Returns the participant IDs of all nodes in the network.
    fn all_participant_ids(&self) -> Vec<ParticipantId>;
}

impl KeyEventLeaderClient for Arc<MeshNetworkClient> {
    async fn wait_for_all_participants_connected(&self) -> anyhow::Result<()> {
        self.leader_wait_for_all_connected().await
    }

    fn new_channel_for_task(
        &self,
        task_id: impl Into<MpcTaskId>,
        participants: Vec<ParticipantId>,
    ) -> anyhow::Result<NetworkTaskChannel> {
        MeshNetworkClient::new_channel_for_task(self, task_id, participants)
    }

    fn all_participant_ids(&self) -> Vec<ParticipantId> {
        MeshNetworkClient::all_participant_ids(self)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::indexer::participants::{ContractKeyEventInstance, KeyEventIdComparisonResult};
    use crate::indexer::tx_sender::{TransactionProcessorError, TransactionStatus};
    use crate::keyshare::KeyStorageConfig;
    use assert_matches::assert_matches;
    use crate::primitives::{AttemptId, DomainId, DomainPurpose, EpochId};
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[rstest::rstest]
    #[tokio::test(start_paused = true)]
    #[timeout(Duration::from_millis(100))]
    #[expect(non_snake_case)]
    async fn resharing_leader__should_retry_after_timeout_if_computation_is_not_started() {
        // Given
        // Simulate the expired/idle contract state: started=false but ID already
        // matches the next attempt (this is what next_attempt_id() produces).
        // This matches the state of a production incident - see [#2298](https://github.com/near/mpc/issues/2298)
        // for more context.
        let key_event_id = make_key_event_id(6, 1, 1);
        let instance = make_key_event_instance(key_event_id, false);
        let (_tx, rx) = watch::channel(instance);

        let txn_sender = CountingTransactionSender::new();
        let txn_sender_handle = txn_sender.clone();

        let keyshare_storage = KeyStorageConfig {
            home_dir: tempfile::tempdir().unwrap().keep(),
            local_encryption_key: [0u8; 16],
            gcp: None,
        }
        .create()
        .await
        .unwrap();
        let keyshare_storage = Arc::new(RwLock::new(keyshare_storage));

        // When
        let leader_handle = tokio::spawn(resharing_leader(
            MockKeyEventLeaderClient,
            keyshare_storage,
            rx,
            txn_sender,
            make_test_resharing_args(),
        ));

        // Advance past two full timeout cycles.
        // Note that tokio will auto-advance the clock here since we're running with paused time.
        // See https://docs.rs/tokio/latest/tokio/time/fn.advance.html#auto-advance.
        let wait_time =
            MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE * 2 + Duration::from_secs(5);
        tokio::time::sleep(wait_time).await;

        // Then
        let send_count = txn_sender_handle.count();
        assert!(
            send_count >= 2,
            "Expected at least 2 StartReshare attempts (retries after timeout), got {send_count}"
        );

        leader_handle.abort();
    }

    #[test]
    fn compare_to_expected_key_event_id__should_return_remote_behind_when_ids_match_but_not_started(
    ) {
        // Given
        let key_event_id = make_key_event_id(6, 1, 1);
        let instance = make_key_event_instance(key_event_id, false);

        // When
        let result = instance.compare_to_expected_key_event_id(&key_event_id);

        // Then
        assert_matches!(result, KeyEventIdComparisonResult::RemoteBehind);
    }

    #[test]
    fn compare_to_expected_key_event_id__should_return_remote_matches_when_ids_match_and_started() {
        // Given
        let key_event_id = make_key_event_id(6, 1, 1);
        let instance = make_key_event_instance(key_event_id, true);

        // When
        let result = instance.compare_to_expected_key_event_id(&key_event_id);

        // Then
        assert_matches!(result, KeyEventIdComparisonResult::RemoteMatches);
    }

    // -- Mocks and helpers --

    struct MockKeyEventLeaderClient;

    impl KeyEventLeaderClient for MockKeyEventLeaderClient {
        async fn wait_for_all_participants_connected(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn new_channel_for_task(
            &self,
            _task_id: impl Into<MpcTaskId>,
            _participants: Vec<ParticipantId>,
        ) -> anyhow::Result<NetworkTaskChannel> {
            anyhow::bail!("mock: should not reach channel creation during retry test")
        }

        fn all_participant_ids(&self) -> Vec<ParticipantId> {
            vec![]
        }
    }

    #[derive(Clone)]
    struct CountingTransactionSender {
        count: Arc<AtomicUsize>,
    }

    impl CountingTransactionSender {
        fn new() -> Self {
            Self {
                count: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn count(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }
    }

    impl TransactionSender for CountingTransactionSender {
        async fn send(
            &self,
            _transaction: ChainSendTransactionRequest,
        ) -> Result<(), TransactionProcessorError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn send_and_wait(
            &self,
            _transaction: ChainSendTransactionRequest,
        ) -> Result<TransactionStatus, TransactionProcessorError> {
            unimplemented!()
        }
    }

    fn make_key_event_id(epoch: u64, domain: u64, attempt: u64) -> KeyEventId {
        KeyEventId::new(EpochId::new(epoch), DomainId(domain), AttemptId(attempt))
    }

    fn make_key_event_instance(
        key_event_id: KeyEventId,
        started: bool,
    ) -> ContractKeyEventInstance {
        ContractKeyEventInstance {
            id: key_event_id,
            domain: DomainConfig {
                id: key_event_id.domain_id,
                curve: Curve::Secp256k1,
                purpose: DomainPurpose::Sign,
            },
            started,
            completed: BTreeSet::new(),
            completed_domains: vec![],
        }
    }

    fn make_test_resharing_args() -> Arc<ResharingArgs> {
        Arc::new(ResharingArgs {
            previous_keyset: Keyset::new(EpochId::new(5), vec![]),
            existing_keyshares: None,
            new_threshold: ReconstructionLowerBound::from(3),
            old_participants: ParticipantsConfig {
                threshold: 3,
                participants: vec![],
            },
        })
    }
}
