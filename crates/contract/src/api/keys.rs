//! Key views: the current keyset and its participants, the domain public key and per-account
//! derived keys.

use crate::crypto_shared::derive_key_secp256k1;
use crate::crypto_shared::kdf::derive_public_key_edwards_point_ed25519;
use crate::crypto_shared::types::PublicKeyExtended;
use crate::dto_mapping::IntoInterfaceType;
use crate::errors::{Error, PublicKeyError};
use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::types::kdf::derive_tweak;
use near_mpc_contract_interface::types::{self as dtos};
use near_sdk::{AccountId, env, near};

#[near]
impl MpcContract {
    /// The keyset of the running state, or of the previous running state while resharing;
    /// `None` otherwise.
    ///
    /// The backup-cli, which operators upgrade independently of the contract, depends on this
    /// view's JSON output staying stable across contract versions.
    pub fn current_keyset(&self) -> Option<dtos::Keyset> {
        self.protocol_state
            .current_keyset()
            .map(IntoInterfaceType::into_dto_type)
    }

    /// The account's TLS key and URL among the participants holding [`MpcContract::current_keyset`];
    /// `None` if the account is not one of them.
    ///
    /// Like [`MpcContract::current_keyset`], the backup-cli depends on this view's JSON output
    /// staying stable across contract versions.
    pub fn participant_info(&self, account_id: AccountId) -> Option<dtos::ParticipantInfo> {
        self.protocol_state
            .current_participants()?
            .info(&account_id)
            .map(IntoInterfaceType::into_dto_type)
    }

    /// This is the root public key combined from all the public keys of the participants.
    /// The domain parameter specifies which domain we're querying the public key for;
    /// the default is the first domain.
    #[handle_result]
    pub fn public_key(&self, domain_id: Option<dtos::DomainId>) -> Result<dtos::PublicKey, Error> {
        let domain_id = domain_id.unwrap_or_else(dtos::DomainId::legacy_ecdsa_id);
        self.public_key_extended(domain_id).map(Into::into)
    }

    /// This is the derived public key of the caller given path and predecessor
    /// if predecessor is not provided, it will be the caller of the contract.
    ///
    /// The domain parameter specifies which domain we're deriving the public key for;
    /// the default is the first domain.
    #[handle_result]
    pub fn derived_public_key(
        &self,
        path: String,
        predecessor: Option<AccountId>,
        domain_id: Option<dtos::DomainId>,
    ) -> Result<dtos::PublicKey, Error> {
        let predecessor: AccountId = predecessor.unwrap_or_else(env::predecessor_account_id);
        let tweak = derive_tweak(&predecessor, &path);

        let domain = domain_id.unwrap_or_else(dtos::DomainId::legacy_ecdsa_id);
        let public_key = self.public_key_extended(domain)?;

        let derived_public_key: dtos::PublicKey = match public_key {
            PublicKeyExtended::Secp256k1 { near_public_key } => {
                let affine = *k256::PublicKey::try_from(&near_public_key)
                    .expect("stored key is always valid")
                    .as_affine();
                let derived_public_key =
                    derive_key_secp256k1(&affine, &tweak).map_err(PublicKeyError::from)?;
                derived_public_key.into()
            }
            PublicKeyExtended::Ed25519 { edwards_point, .. } => {
                let derived_public_key_edwards_point =
                    derive_public_key_edwards_point_ed25519(&edwards_point, &tweak);
                dtos::Ed25519PublicKey::from(derived_public_key_edwards_point.compress()).into()
            }
            PublicKeyExtended::Bls12381 { public_key } => public_key.into(),
        };

        Ok(derived_public_key)
    }
}

impl MpcContract {
    pub(crate) fn public_key_extended(
        &self,
        domain_id: dtos::DomainId,
    ) -> Result<PublicKeyExtended, Error> {
        self.protocol_state.public_key(domain_id)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use crate::MpcContract;
    use crate::api::test_utils::{
        contract_with_participants, initializing_state, make_public_key_for_curve,
    };
    use crate::dto_mapping::IntoInterfaceType;
    use crate::primitives::key_state::{AttemptId, EpochId, KeyForDomain, Keyset};
    use crate::primitives::participants::ParticipantInfo;
    use crate::primitives::test_utils::{
        NUM_PROTOCOLS, gen_domain_registry, gen_participant, gen_participant_url,
        gen_threshold_params,
    };
    use crate::primitives::thresholds::{
        GovernanceThreshold, GovernanceThresholdParameters, ProposedGovernanceThresholdParameters,
    };
    use crate::state::ProtocolContractState;
    use crate::state::running::RunningContractState;
    use crate::state::test_utils::{
        RunningStateParams, account_ids, gen_resharing_state, gen_resharing_state_from,
        gen_running_state, gen_running_state_with_params,
    };
    use near_mpc_contract_interface::types::{Curve, Ed25519PublicKey};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rstest::rstest;
    use std::collections::BTreeMap;

    #[test]
    fn current_keyset__should_return_the_running_keyset() {
        // Given
        let running = gen_running_state(2);
        let expected = (&running.keyset).into_dto_type();
        let contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running));

        // When
        let keyset = contract.current_keyset();

        // Then
        assert_eq!(keyset, Some(expected));
    }

    #[test]
    fn current_keyset__should_return_the_previous_keyset_while_resharing() {
        // Given
        let (_env, resharing) = gen_resharing_state(2);
        let expected = resharing.previous_keyset().into_dto_type();
        let contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Resharing(resharing));

        // When
        let keyset = contract.current_keyset();

        // Then
        assert_eq!(keyset, Some(expected));
    }

    #[rstest]
    #[case::not_initialized(ProtocolContractState::NotInitialized)]
    #[case::initializing(initializing_state())]
    fn current_keyset__should_return_none_without_a_concluded_keyset(
        #[case] state: ProtocolContractState,
    ) {
        // Given
        let contract = MpcContract::new_from_protocol_state(state);

        // When
        let keyset = contract.current_keyset();

        // Then
        assert_eq!(keyset, None);
    }

    /// Updating this snapshot is a breaking change for the backup-cli: released binaries parse
    /// this output, and operators upgrade them independently of the contract.
    #[test]
    fn current_keyset__should_keep_its_json_format() {
        // Given
        let mut rng = StdRng::from_seed([42u8; 32]);
        let domains = gen_domain_registry(NUM_PROTOCOLS);
        let keys = domains
            .domains()
            .iter()
            .map(|domain| {
                let (key, _) = make_public_key_for_curve(Curve::from(domain.protocol), &mut rng);
                KeyForDomain {
                    domain_id: domain.id,
                    key: key.try_into().unwrap(),
                    attempt: AttemptId::new().next(),
                }
            })
            .collect();
        let running = RunningContractState::new(
            domains,
            Keyset::new(EpochId::new(5), keys),
            gen_threshold_params(30),
        );
        let contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running));

        // When
        let keyset = contract.current_keyset();

        // Then
        insta::assert_json_snapshot!(keyset);
    }

    #[rstest]
    #[case::running(|running, _: &_| ProtocolContractState::Running(running))]
    #[case::resharing(|running, proposal: &_| {
        ProtocolContractState::Resharing(gen_resharing_state_from(running, proposal).1)
    })]
    fn participant_info__should_return_only_the_info_of_the_current_keysets_participants(
        #[case] into_state: fn(
            RunningContractState,
            &ProposedGovernanceThresholdParameters,
        ) -> ProtocolContractState,
    ) {
        // Given
        let running = gen_running_state_with_params(RunningStateParams {
            num_domains: 1,
            num_participants: 3,
            governance_threshold: GovernanceThreshold::new(2),
        });
        let participants = running.participants().clone();
        let (joining, joining_info) = gen_participant(participants.len());
        let mut proposed_participants = participants.subset(0..participants.len() - 1);
        proposed_participants
            .insert(joining.clone(), joining_info)
            .unwrap();
        let proposal = ProposedGovernanceThresholdParameters::new(
            GovernanceThresholdParameters::new(
                proposed_participants,
                running.parameters.threshold(),
            )
            .unwrap(),
            BTreeMap::new(),
        );
        let contract = MpcContract::new_from_protocol_state(into_state(running, &proposal));

        // When
        let infos: Vec<_> = account_ids(&participants)
            .into_iter()
            .chain([joining])
            .map(|account_id| contract.participant_info(account_id))
            .collect();

        // Then
        let expected: Vec<_> = participants
            .participants()
            .iter()
            .map(|(_, _, info)| Some(info.into_dto_type()))
            .chain([None])
            .collect();
        assert_eq!(infos, expected);
    }

    #[test]
    fn participant_info__should_return_none_while_initializing() {
        // Given
        let (contract, participants) = contract_with_participants(initializing_state());

        // When
        let infos: Vec<_> = participants
            .iter()
            .map(|account_id| contract.participant_info(account_id.clone()))
            .collect();

        // Then
        assert_eq!(infos, vec![None; participants.len()]);
    }

    /// Updating this snapshot is a breaking change for the backup-cli, which parses this output
    /// like the current keyset's.
    #[test]
    fn participant_info__should_keep_its_json_format() {
        // Given
        let mut running = gen_running_state(1);
        let account_id = account_ids(running.participants()).swap_remove(0);
        running
            .update_participant_info(
                account_id.clone(),
                ParticipantInfo {
                    url: gen_participant_url(0),
                    tls_public_key: Ed25519PublicKey::from([7u8; 32]),
                },
            )
            .unwrap();
        let contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running));

        // When
        let info = contract.participant_info(account_id);

        // Then
        insta::assert_json_snapshot!(info);
    }
}
