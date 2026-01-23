pub mod presign;
mod sign;

use mpc_contract::primitives::key_state::KeyEventId;
pub use presign::PresignatureStorage;
use std::collections::HashMap;

use crate::config::{ConfigFile, MpcConfig, ParticipantsConfig};
use crate::db::SecretDB;
use crate::metrics::tokio_task_metrics::ROBUST_ECDSA_TASK_MONITORS;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{MpcTaskId, UniqueId};
use crate::providers::{EcdsaSignatureProvider, SignatureProvider};
use crate::storage::SignRequestStorage;
use crate::tracking;

use crate::types::SignatureId;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_contract::primitives::domain::DomainId;
use near_time::Clock;
use std::sync::Arc;
use threshold_signatures::ecdsa::KeygenOutput;
use threshold_signatures::ecdsa::Signature;
use threshold_signatures::frost_secp256k1::keys::SigningShare;
use threshold_signatures::frost_secp256k1::VerifyingKey;

pub struct RobustEcdsaSignatureProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    sign_request_store: Arc<SignRequestStorage>,
    per_domain_data: HashMap<DomainId, PerDomainData>,
}

#[derive(Clone)]
pub(super) struct PerDomainData {
    pub keyshare: KeygenOutput,
    pub presignature_store: Arc<PresignatureStorage>,
}

#[derive(
    Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd, derive_more::From, derive_more::Into,
)]
pub struct EcdsaMessageHash([u8; 32]);

impl EcdsaMessageHash {
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl RobustEcdsaSignatureProvider {
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<MeshNetworkClient>,
        clock: Clock,
        db: Arc<SecretDB>,
        sign_request_store: Arc<SignRequestStorage>,
        keyshares: HashMap<DomainId, KeygenOutput>,
    ) -> anyhow::Result<Self> {
        let active_participants_query = {
            let network_client = client.clone();
            Arc::new(move || network_client.all_alive_participant_ids())
        };

        let mut per_domain_data = HashMap::new();
        for (domain_id, keyshare) in keyshares {
            let presignature_store = Arc::new(PresignatureStorage::new(
                clock.clone(),
                db.clone(),
                client.my_participant_id(),
                active_participants_query.clone(),
                domain_id,
            )?);
            per_domain_data.insert(
                domain_id,
                PerDomainData {
                    keyshare,
                    presignature_store,
                },
            );
        }

        Ok(Self {
            config,
            mpc_config,
            client,
            sign_request_store,
            per_domain_data,
        })
    }

    pub(super) fn domain_data(&self, domain_id: DomainId) -> anyhow::Result<PerDomainData> {
        self.per_domain_data
            .get(&domain_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No keyshare for domain {:?}", domain_id))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum RobustEcdsaTaskId {
    KeyGeneration {
        key_event: KeyEventId,
    },
    KeyResharing {
        key_event: KeyEventId,
    },
    Presignature {
        id: UniqueId,
        domain_id: DomainId,
    },
    Signature {
        id: SignatureId,
        presignature_id: UniqueId,
    },
}

impl From<RobustEcdsaTaskId> for MpcTaskId {
    fn from(val: RobustEcdsaTaskId) -> Self {
        MpcTaskId::RobustEcdsaTaskId(val)
    }
}

impl SignatureProvider for RobustEcdsaSignatureProvider {
    type PublicKey = VerifyingKey;
    type SecretShare = SigningShare;
    type KeygenOutput = KeygenOutput;
    type Signature = Signature;
    type TaskId = RobustEcdsaTaskId;

    async fn make_signature(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(Self::Signature, Self::PublicKey)> {
        ROBUST_ECDSA_TASK_MONITORS
            .make_signature_leader
            .instrument(self.make_signature_leader(id))
            .await
    }

    async fn run_key_generation_client(
        threshold: usize,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        let number_of_participants = channel.participants().len();
        let robust_ecdsa_threshold = translate_threshold(threshold, number_of_participants)?;
        EcdsaSignatureProvider::run_key_generation_client_internal(robust_ecdsa_threshold, channel)
            .await
    }

    async fn run_key_resharing_client(
        new_threshold: usize,
        my_share: Option<SigningShare>,
        public_key: VerifyingKey,
        old_participants: &ParticipantsConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        let number_of_participants = channel.participants().len();
        let new_robust_ecdsa_threshold =
            translate_threshold(new_threshold, number_of_participants)?;

        // This is a bad hack, but cannot think of a better way to solve it, as the struct
        // comes directly from generic implementations, so probably this is the best place
        // to do so anyway
        let mut old_participants_patched = old_participants.clone();
        old_participants_patched.threshold = translate_threshold(
            old_participants.threshold.try_into()?,
            old_participants.participants.len(),
        )?
        .try_into()?;

        EcdsaSignatureProvider::run_key_resharing_client_internal(
            new_robust_ecdsa_threshold,
            my_share,
            public_key,
            &old_participants_patched,
            channel,
        )
        .await
    }

    async fn process_channel(&self, channel: NetworkTaskChannel) -> anyhow::Result<()> {
        match channel.task_id() {
            MpcTaskId::RobustEcdsaTaskId(task) => match task {
                RobustEcdsaTaskId::KeyGeneration { .. } => {
                    anyhow::bail!("Key generation rejected in normal node operation");
                }
                RobustEcdsaTaskId::KeyResharing { .. } => {
                    anyhow::bail!("Key resharing rejected in normal node operation");
                }
                RobustEcdsaTaskId::Presignature { id, domain_id } => {
                    ROBUST_ECDSA_TASK_MONITORS
                        .presignature_generation_follower
                        .instrument(
                            self.run_presignature_generation_follower(channel, id, domain_id),
                        )
                        .await?;
                }
                RobustEcdsaTaskId::Signature {
                    id,
                    presignature_id,
                } => {
                    ROBUST_ECDSA_TASK_MONITORS
                        .make_signature_follower
                        .instrument(self.make_signature_follower(channel, id, presignature_id))
                        .await?;
                }
            },

            _ => anyhow::bail!(
                "eddsa task handler: received unexpected task id: {:?}",
                channel.task_id()
            ),
        }
        Ok(())
    }

    async fn spawn_background_tasks(self: Arc<Self>) -> anyhow::Result<()> {
        let generate_presignatures = self
            .per_domain_data
            .iter()
            .map(|(domain_id, data)| {
                tracking::spawn(
                    &format!("generate presignatures for domain {}", domain_id.0),
                    presign::run_background_presignature_generation(
                        self.client.clone(),
                        self.mpc_config.clone(),
                        self.config.presignature.clone().into(),
                        *domain_id,
                        data.presignature_store.clone(),
                        data.keyshare.clone(),
                    ),
                )
            })
            .collect::<Vec<_>>();

        for task in generate_presignatures {
            task.await??;
        }

        Ok(())
    }
}

/// Although currently the threshold is always equal to the number of signers, if in
/// the future we might want to change that invariant, for example to achieve
/// higher security guarantees for robust-ecdsa. In that case,
/// this function enforces that the number of signers and the threshold
/// computed below in `translate_threshold` stay consistent
pub(super) fn get_number_of_signers(threshold: usize, _number_of_participants: usize) -> usize {
    threshold
}

/// This function translates the current threshold from the contract
/// to the threshold expected by the robust-ecdsa scheme, which
/// is semantically different.
/// The function should be no longer needed when these issues are solved:
/// https://github.com/near/threshold-signatures/issues/255
/// https://github.com/near/mpc/issues/1649
pub(super) fn translate_threshold(
    threshold: usize,
    number_of_participants: usize,
) -> anyhow::Result<usize> {
    let number_of_signers = get_number_of_signers(threshold, number_of_participants);
    anyhow::ensure!(number_of_signers >= 5, "Robust ECDSA requires the threshold to be at least 2, which implies that the number of signers needs to be at least 5");
    Ok((number_of_signers - 1) / 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // The resulting threshold for robust-ecdsa must always satisfy
    // the underlying invariant that 2 * threshold + 1 <= number of signers
    #[test]
    fn test_translate_threshold() {
        let max_size = 30;
        for threshold in 5..max_size {
            for number_of_participants in threshold..max_size {
                let number_of_signers = get_number_of_signers(threshold, number_of_participants);
                let new_threshold = translate_threshold(threshold, number_of_participants).unwrap();
                assert!(2 * new_threshold < number_of_signers, "Failed for threshold={threshold}, number_of_participants={number_of_participants}");
                assert!(new_threshold >= (threshold - 1) / 2, "The new threshold should not decrease security more than necessary: new_threshold={new_threshold}, threshold={threshold}");
            }
        }
    }

    // Tests that the number of signers is below the threshold,
    // guaranteeing that security is not reduced
    #[test]
    fn test_get_number_of_signers_not_lower_than_threshold() {
        let max_size = 30;
        for threshold in 5..max_size {
            for number_of_participants in threshold..max_size {
                let number_of_signers = get_number_of_signers(threshold, number_of_participants);
                assert!(threshold <= number_of_signers && number_of_signers <= number_of_participants, "Failed for threshold={threshold}, number_of_participants={number_of_participants}");
            }
        }
    }

    #[rstest]
    #[case(0, 10, true, 0)]
    #[case(1, 10, true, 0)]
    #[case(2, 10, true, 0)]
    #[case(3, 10, true, 0)]
    #[case(4, 10, true, 0)]
    #[case(5, 10, false, 2)]
    #[case(6, 10, false, 2)]
    #[case(7, 10, false, 3)]
    fn test_translate_threshold_special_cases(
        #[case] threshold: usize,
        #[case] number_of_participants: usize,
        #[case] is_err: bool,
        #[case] expected_threshold: usize,
    ) {
        let result = translate_threshold(threshold, number_of_participants);
        assert_eq!(result.is_err(), is_err);
        if !is_err {
            assert_eq!(result.unwrap(), expected_threshold);
        }
    }
}
