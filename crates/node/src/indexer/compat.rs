//! Converts DTO contract state to internal contract state.
//!
//! The DTO types in `near_mpc_contract_interface` handle backward-compatible
//! deserialization (accepting both old `"scheme"/"Ed25519"` and new
//! `"curve"/"Edwards25519"` formats via serde aliases).
//!
//! This module converts the DTO `ProtocolContractState` to internal
//! `mpc_contract::state::ProtocolContractState`.
//!
//! Remove after #2167.

use anyhow::{Context, Result};
use mpc_contract::{
    crypto_shared::types::PublicKeyExtended,
    primitives::{
        domain::{AddDomainsVotes, Curve, DomainConfig, DomainId, DomainPurpose, DomainRegistry},
        key_state::{
            AttemptId, AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, KeyForDomain,
            Keyset,
        },
        participants::{ParticipantId, ParticipantInfo, Participants},
        thresholds::{Threshold, ThresholdParameters},
        votes::ThresholdParametersVotes,
    },
    state::{
        initializing::InitializingContractState,
        key_event::{KeyEvent, KeyEventInstance},
        resharing::ResharingContractState,
        running::RunningContractState,
        ProtocolContractState,
    },
};
use near_mpc_contract_interface::types as dtos;

pub(super) fn into_internal(dto: dtos::ProtocolContractState) -> Result<ProtocolContractState> {
    Ok(match dto {
        dtos::ProtocolContractState::NotInitialized => ProtocolContractState::NotInitialized,
        dtos::ProtocolContractState::Running(s) => {
            ProtocolContractState::Running(convert_running(s)?)
        }
        dtos::ProtocolContractState::Initializing(s) => {
            ProtocolContractState::Initializing(convert_initializing(s)?)
        }
        dtos::ProtocolContractState::Resharing(s) => {
            ProtocolContractState::Resharing(convert_resharing(s)?)
        }
    })
}

fn convert_running(s: dtos::RunningContractState) -> Result<RunningContractState> {
    Ok(RunningContractState {
        domains: convert_domain_registry(s.domains)?,
        keyset: convert_keyset(s.keyset)?,
        parameters: convert_threshold_params(s.parameters)?,
        parameters_votes: convert_threshold_params_votes(s.parameters_votes)?,
        add_domains_votes: convert_add_domains_votes(s.add_domains_votes)?,
        previously_cancelled_resharing_epoch_id: s
            .previously_cancelled_resharing_epoch_id
            .map(convert_epoch_id),
    })
}

fn convert_initializing(s: dtos::InitializingContractState) -> Result<InitializingContractState> {
    Ok(InitializingContractState {
        domains: convert_domain_registry(s.domains)?,
        epoch_id: convert_epoch_id(s.epoch_id),
        generated_keys: s
            .generated_keys
            .into_iter()
            .map(convert_key_for_domain)
            .collect::<Result<_>>()?,
        generating_key: convert_key_event(s.generating_key)?,
        cancel_votes: s
            .cancel_votes
            .into_iter()
            .map(convert_auth_participant_id)
            .collect(),
    })
}

fn convert_resharing(s: dtos::ResharingContractState) -> Result<ResharingContractState> {
    Ok(ResharingContractState {
        previous_running_state: convert_running(s.previous_running_state)?,
        reshared_keys: s
            .reshared_keys
            .into_iter()
            .map(convert_key_for_domain)
            .collect::<Result<_>>()?,
        resharing_key: convert_key_event(s.resharing_key)?,
        cancellation_requests: s
            .cancellation_requests
            .into_iter()
            .map(convert_auth_account_id)
            .collect::<Result<_>>()?,
    })
}

fn convert_curve(c: dtos::Curve) -> Curve {
    match c {
        dtos::Curve::Secp256k1 => Curve::Secp256k1,
        dtos::Curve::Edwards25519 => Curve::Edwards25519,
        dtos::Curve::Bls12381 => Curve::Bls12381,
        dtos::Curve::V2Secp256k1 => Curve::V2Secp256k1,
    }
}

fn convert_domain_config(d: dtos::DomainConfig) -> DomainConfig {
    DomainConfig {
        id: DomainId::from(d.id),
        curve: convert_curve(d.curve),
        purpose: d.purpose.unwrap_or(DomainPurpose::Sign),
    }
}

fn convert_domain_registry(r: dtos::DomainRegistry) -> Result<DomainRegistry> {
    let domains = r.domains.into_iter().map(convert_domain_config).collect();
    DomainRegistry::from_raw_validated(domains, r.next_domain_id)
        .context("invalid DomainRegistry in contract state")
}

fn convert_add_domains_votes(v: dtos::AddDomainsVotes) -> Result<AddDomainsVotes> {
    Ok(AddDomainsVotes::from_raw(
        v.proposal_by_account
            .into_iter()
            .map(|(k, domains)| {
                (
                    convert_auth_participant_id(k),
                    domains.into_iter().map(convert_domain_config).collect(),
                )
            })
            .collect(),
    ))
}

fn convert_epoch_id(e: dtos::EpochId) -> EpochId {
    EpochId::new(e.0)
}

fn convert_attempt_id(a: dtos::AttemptId) -> AttemptId {
    AttemptId::from_raw(a.0)
}

fn convert_auth_participant_id(a: dtos::AuthenticatedParticipantId) -> AuthenticatedParticipantId {
    AuthenticatedParticipantId::from_raw(ParticipantId(a.0 .0))
}

fn convert_auth_account_id(a: dtos::AuthenticatedAccountId) -> Result<AuthenticatedAccountId> {
    let account_id =
        a.0 .0
            .parse()
            .context("invalid account id in contract state")?;
    Ok(AuthenticatedAccountId::from_raw(account_id))
}

fn convert_key_for_domain(k: dtos::KeyForDomain) -> Result<KeyForDomain> {
    Ok(KeyForDomain {
        domain_id: DomainId::from(k.domain_id),
        key: convert_public_key_extended(k.key)?,
        attempt: convert_attempt_id(k.attempt),
    })
}

fn convert_public_key_extended(pk: dtos::PublicKeyExtended) -> Result<PublicKeyExtended> {
    pk.try_into()
        .map_err(|e| anyhow::anyhow!("invalid PublicKeyExtended in contract state: {e:?}"))
}

fn convert_keyset(k: dtos::Keyset) -> Result<Keyset> {
    Ok(Keyset::new(
        convert_epoch_id(k.epoch_id),
        k.domains
            .into_iter()
            .map(convert_key_for_domain)
            .collect::<Result<_>>()?,
    ))
}

fn convert_participants(p: dtos::Participants) -> Result<Participants> {
    Ok(Participants::init(
        ParticipantId(p.next_id.0),
        p.participants
            .into_iter()
            .map(|(account_id, pid, info)| -> Result<_> {
                Ok((
                    account_id
                        .0
                        .parse()
                        .context("invalid participant account id")?,
                    ParticipantId(pid.0),
                    ParticipantInfo {
                        url: info.url,
                        sign_pk: info
                            .sign_pk
                            .parse()
                            .context("invalid participant sign_pk")?,
                    },
                ))
            })
            .collect::<Result<_>>()?,
    ))
}

fn convert_threshold_params(p: dtos::ThresholdParameters) -> Result<ThresholdParameters> {
    Ok(ThresholdParameters::new_unvalidated(
        convert_participants(p.participants)?,
        Threshold::new(p.threshold.0),
    ))
}

fn convert_threshold_params_votes(
    v: dtos::ThresholdParametersVotes,
) -> Result<ThresholdParametersVotes> {
    Ok(ThresholdParametersVotes::from_raw(
        v.proposal_by_account
            .into_iter()
            .map(|(k, params)| -> Result<_> {
                Ok((
                    convert_auth_account_id(k)?,
                    convert_threshold_params(params)?,
                ))
            })
            .collect::<Result<_>>()?,
    ))
}

fn convert_key_event_instance(i: dtos::KeyEventInstance) -> Result<KeyEventInstance> {
    Ok(KeyEventInstance::from_raw(
        convert_attempt_id(i.attempt_id),
        i.started_in,
        i.expires_on,
        i.completed
            .into_iter()
            .map(convert_auth_participant_id)
            .collect(),
        i.public_key.map(convert_public_key_extended).transpose()?,
    ))
}

fn convert_key_event(e: dtos::KeyEvent) -> Result<KeyEvent> {
    Ok(KeyEvent::from_raw(
        convert_epoch_id(e.epoch_id),
        convert_domain_config(e.domain),
        convert_threshold_params(e.parameters)?,
        e.instance.map(convert_key_event_instance).transpose()?,
        convert_attempt_id(e.next_attempt_id),
    ))
}
