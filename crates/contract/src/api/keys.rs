//! Public-key views: the domain public key, per-account derived keys, and the
//! latest key version.

use crate::crypto_shared::derive_key_secp256k1;
use crate::crypto_shared::kdf::derive_public_key_edwards_point_ed25519;
use crate::crypto_shared::types::PublicKeyExtended;
use crate::errors::{Error, PublicKeyError};
use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::types::kdf::derive_tweak;
use near_mpc_contract_interface::types::{self as dtos};
use near_sdk::{AccountId, env, near};

#[near]
impl MpcContract {
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

    /// Key versions refer new versions of the root key that we may choose to generate on cohort
    /// changes. Older key versions will always work but newer key versions were never held by
    /// older signers. Newer key versions may also add new security features, like only existing
    /// within a secure enclave. The signature_scheme parameter specifies which protocol
    /// we're querying the latest version for. The default is Secp256k1. The default is **NOT**
    /// to query across all protocols.
    pub fn latest_key_version(&self, signature_scheme: Option<dtos::Curve>) -> u32 {
        self.protocol_state
            .most_recent_domain_for_curve(signature_scheme.unwrap_or_default())
            .unwrap()
            .0 as u32
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
