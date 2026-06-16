//! Test-only conversions from internal `mpc-contract` types to their
//! `near-mpc-contract-interface` DTO counterparts.
//!
//! This mirrors the contract crate's internal `IntoInterfaceType` impl, which
//! is `pub(crate)` and therefore unreachable from the node. The orphan rule
//! prevents the node from providing a `From`/`Into` impl (both types are
//! foreign), so this is a plain free function.

use k256::elliptic_curve::group::GroupEncoding as _;
use mpc_contract::crypto_shared::types::PublicKeyExtended;
use mpc_contract::primitives::key_state::{KeyForDomain, Keyset};
use near_mpc_contract_interface::types as dtos;

pub(crate) fn keyset_to_dto(keyset: &Keyset) -> dtos::Keyset {
    dtos::Keyset {
        epoch_id: keyset.epoch_id,
        domains: keyset.domains.iter().map(key_for_domain_to_dto).collect(),
    }
}

fn key_for_domain_to_dto(key: &KeyForDomain) -> dtos::KeyForDomain {
    dtos::KeyForDomain {
        domain_id: key.domain_id,
        key: public_key_extended_to_dto(&key.key),
        attempt: key.attempt,
    }
}

fn public_key_extended_to_dto(key: &PublicKeyExtended) -> dtos::PublicKeyExtended {
    match key {
        PublicKeyExtended::Secp256k1 { near_public_key } => dtos::PublicKeyExtended::Secp256k1 {
            near_public_key: String::from(near_public_key),
        },
        PublicKeyExtended::Ed25519 {
            near_public_key_compressed,
            edwards_point,
        } => dtos::PublicKeyExtended::Ed25519 {
            near_public_key_compressed: String::from(near_public_key_compressed),
            edwards_point: edwards_point.to_bytes(),
        },
        PublicKeyExtended::Bls12381 { public_key } => dtos::PublicKeyExtended::Bls12381 {
            public_key: public_key.clone(),
        },
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use mpc_contract::primitives::key_state::{AttemptId, EpochId};
    use mpc_primitives::domain::DomainId;

    fn sample_keyset() -> Keyset {
        let near_public_key: near_sdk::PublicKey =
            "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp"
                .parse()
                .unwrap();
        let key = PublicKeyExtended::try_from(near_public_key).unwrap();
        Keyset::new(
            EpochId::new(7),
            vec![KeyForDomain {
                domain_id: DomainId(0),
                key,
                attempt: AttemptId::new(),
            }],
        )
    }

    /// The DTO produced by `keyset_to_dto` must serialize identically to the
    /// internal `Keyset`, guarding against drift from the contract's own
    /// `IntoInterfaceType` impl.
    #[test]
    fn keyset_to_dto__should_match_internal_serialization() {
        // Given
        let internal = sample_keyset();

        // When
        let dto = keyset_to_dto(&internal);

        // Then
        assert_eq!(
            serde_json::to_value(&internal).unwrap(),
            serde_json::to_value(&dto).unwrap()
        );
    }
}
