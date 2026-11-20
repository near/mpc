//! Key views: the current keyset, the domain public key and per-account derived keys.

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
    use crate::api::test_utils::{initializing_state, make_public_key_for_curve};
    use crate::dto_mapping::IntoInterfaceType;
    use crate::primitives::domain::AddDomainsVotes;
    use crate::primitives::key_state::{AttemptId, EpochId, KeyForDomain, Keyset};
    use crate::primitives::test_utils::{NUM_PROTOCOLS, gen_domain_registry, gen_threshold_params};
    use crate::state::ProtocolContractState;
    use crate::state::running::RunningContractState;
    use crate::state::test_utils::{gen_resharing_state, gen_running_state};
    use near_mpc_contract_interface::types::Curve;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rstest::rstest;

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
            AddDomainsVotes::default(),
        );
        let contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running));

        // When
        let keyset = contract.current_keyset();

        // Then
        insta::assert_json_snapshot!(keyset);
    }
}
