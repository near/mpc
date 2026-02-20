//! Conversion functions from contract-interface DTO types to internal contract types.
//!
//! These conversions are used at the chain-reading boundary: the node deserializes
//! chain JSON into DTO types (which have relaxed fields like `purpose: Option<DomainPurpose>`),
//! then converts them into the stricter internal types used by node logic.

use anyhow::Context;
use contract_interface::types as dtos;
use mpc_contract::{
    crypto_shared::types::PublicKeyExtended,
    primitives::{
        domain::{infer_purpose_from_scheme, DomainConfig, DomainId, SignatureScheme},
        key_state::{AttemptId, EpochId, KeyForDomain, Keyset},
    },
};

pub fn convert_epoch_id(dto: &dtos::EpochId) -> EpochId {
    EpochId::new(dto.0)
}

pub fn convert_attempt_id(dto: &dtos::AttemptId) -> AttemptId {
    AttemptId::from_raw(dto.0)
}

pub fn convert_domain_id(dto: &dtos::DomainId) -> DomainId {
    DomainId(dto.0)
}

pub fn convert_signature_scheme(dto: &dtos::SignatureScheme) -> SignatureScheme {
    match dto {
        dtos::SignatureScheme::Secp256k1 => SignatureScheme::Secp256k1,
        dtos::SignatureScheme::Ed25519 => SignatureScheme::Ed25519,
        dtos::SignatureScheme::Bls12381 => SignatureScheme::Bls12381,
        dtos::SignatureScheme::V2Secp256k1 => SignatureScheme::V2Secp256k1,
    }
}

pub fn convert_domain_config(dto: &dtos::DomainConfig) -> DomainConfig {
    let scheme = convert_signature_scheme(&dto.scheme);
    let purpose = dto
        .purpose
        .unwrap_or_else(|| infer_purpose_from_scheme(scheme));
    DomainConfig {
        id: convert_domain_id(&dto.id),
        scheme,
        purpose,
    }
}

/// Convert DTO PublicKeyExtended to internal PublicKeyExtended via serde roundtrip.
/// Both types have compatible JSON representations.
pub fn convert_public_key_extended(
    dto: &dtos::PublicKeyExtended,
) -> anyhow::Result<PublicKeyExtended> {
    let json = serde_json::to_value(dto).context("failed to serialize DTO PublicKeyExtended")?;
    serde_json::from_value(json).context("failed to deserialize internal PublicKeyExtended")
}

pub fn convert_key_for_domain(dto: &dtos::KeyForDomain) -> anyhow::Result<KeyForDomain> {
    Ok(KeyForDomain {
        domain_id: convert_domain_id(&dto.domain_id),
        key: convert_public_key_extended(&dto.key)?,
        attempt: convert_attempt_id(&dto.attempt),
    })
}

pub fn convert_keyset(dto: &dtos::Keyset) -> anyhow::Result<Keyset> {
    let domains = dto
        .domains
        .iter()
        .map(convert_key_for_domain)
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(Keyset::new(convert_epoch_id(&dto.epoch_id), domains))
}
