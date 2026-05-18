//! Legacy wire formats for the contract's `init` call.
//!
//! Each `Legacy*` mirror struct here serializes a current DTO into the JSON
//! shape expected by an older production contract. See [`ContractInitFormat`]
//! for when each variant is needed.
//!
//! [`ContractInitFormat`]: crate::cluster::ContractInitFormat

use near_mpc_contract_interface::types::{
    AccountId as ContractAccountId, Curve, DomainConfig, DomainId, DomainPurpose, Ed25519PublicKey,
    ParticipantId, Protocol, ReconstructionThreshold, Threshold, ThresholdParameters,
};

/// Pre-3.10 mirror of `ThresholdParameters` whose `ParticipantInfo` emits
/// `sign_pk` instead of `tls_public_key`. The 3.9.1 contract's
/// `ParticipantInfo` only knows the legacy field name (no serde alias), so
/// this rewrite is required when calling `init` against that binary.
#[derive(serde::Serialize)]
pub struct LegacyThresholdParameters {
    threshold: Threshold,
    participants: LegacyParticipants,
}

#[derive(serde::Serialize)]
struct LegacyParticipants {
    next_id: ParticipantId,
    participants: Vec<(ContractAccountId, ParticipantId, LegacyParticipantInfo)>,
}

#[derive(serde::Serialize)]
struct LegacyParticipantInfo {
    url: String,
    sign_pk: Ed25519PublicKey,
}

impl From<&ThresholdParameters> for LegacyThresholdParameters {
    fn from(params: &ThresholdParameters) -> Self {
        let participants = params
            .participants
            .participants
            .iter()
            .map(|(account_id, id, info)| {
                (
                    account_id.clone(),
                    *id,
                    LegacyParticipantInfo {
                        url: info.url.clone(),
                        sign_pk: info.tls_public_key.clone(),
                    },
                )
            })
            .collect();
        Self {
            threshold: params.threshold,
            participants: LegacyParticipants {
                next_id: params.participants.next_id,
                participants,
            },
        }
    }
}

/// Pre-curve-removal mirror of `DomainConfig` that still emits the `curve`
/// field. Required when calling `vote_add_domains` against a production
/// contract whose deserializer still requires it; the current contract
/// accepts both shapes via the DTO compat shim. Remove after the 3.10
/// release is the production contract on Mainnet and Testnet.
#[derive(serde::Serialize)]
pub struct LegacyDomainConfig {
    pub id: DomainId,
    pub curve: Curve,
    pub protocol: Protocol,
    pub reconstruction_threshold: ReconstructionThreshold,
    pub purpose: DomainPurpose,
}

impl From<&DomainConfig> for LegacyDomainConfig {
    fn from(domain: &DomainConfig) -> Self {
        Self {
            id: domain.id,
            curve: Curve::from(domain.protocol),
            protocol: domain.protocol,
            reconstruction_threshold: domain.reconstruction_threshold,
            purpose: domain.purpose,
        }
    }
}
