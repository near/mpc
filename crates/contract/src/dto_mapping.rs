//! This module provides convenience methods to map contract interface types
//! from [`contract_interface::types`] to internal types.
//!
//! These types are mapped with the [IntoContractType] trait. We can not use [`From`]
//! and [`Into`] due to the [*orphan rule*](https://doc.rust-lang.org/reference/items/implementations.html#orphan-rules).

use contract_interface::types as dtos;
use curve25519_dalek::edwards::CompressedEdwardsY;
use k256::{
    elliptic_curve::{
        group::GroupEncoding as _,
        sec1::{FromEncodedPoint as _, ToEncodedPoint as _},
        PrimeField as _,
    },
    EncodedPoint,
};
use mpc_attestation::{
    attestation::{Attestation, DstackAttestation, MockAttestation, VerifiedAttestation},
    collateral::{Collateral, QuoteCollateralV3},
    tcb_info::{EventLog, HexBytes, TcbInfo},
};
use near_account_id::AccountId;
use near_sdk::env::sha256_array;
#[cfg(any(test, feature = "test-utils", feature = "dev-utils"))]
use threshold_signatures::confidential_key_derivation as ckd;

use crate::{
    config::Config,
    crypto_shared::{k256_types, types::PublicKeyExtended},
    derive_foreign_tx_tweak,
    errors::{ConversionError, Error},
    primitives::{
        domain::{AddDomainsVotes, DomainConfig, DomainId, DomainRegistry, SignatureScheme},
        key_state::{
            AttemptId, AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, KeyEventId,
            KeyForDomain, Keyset,
        },
        participants::Participants,
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
    update::{ProposedUpdates, Update},
};

pub(crate) trait IntoContractType<ContractType> {
    fn into_contract_type(self) -> ContractType;
}

pub(crate) trait IntoInterfaceType<InterfaceType> {
    fn into_dto_type(self) -> InterfaceType;
}

pub(crate) trait TryIntoContractType<ContractType> {
    type Error;
    fn try_into_contract_type(self) -> Result<ContractType, Self::Error>;
}

pub(crate) trait TryIntoInterfaceType<InterfaceType> {
    type Error;
    fn try_into_dto_type(self) -> Result<InterfaceType, Self::Error>;
}

impl TryIntoContractType<Attestation> for dtos::Attestation {
    type Error = Error;
    fn try_into_contract_type(self) -> Result<Attestation, Self::Error> {
        Ok(match self {
            dtos::Attestation::Dstack(dstack_attestation) => {
                Attestation::Dstack(dstack_attestation.try_into_contract_type()?)
            }
            dtos::Attestation::Mock(mock_attestation) => {
                Attestation::Mock(mock_attestation.into_contract_type())
            }
        })
    }
}

impl IntoContractType<MockAttestation> for dtos::MockAttestation {
    fn into_contract_type(self) -> MockAttestation {
        match self {
            dtos::MockAttestation::Valid => MockAttestation::Valid,
            dtos::MockAttestation::Invalid => MockAttestation::Invalid,
            dtos::MockAttestation::WithConstraints {
                mpc_docker_image_hash,
                launcher_docker_compose_hash,
                expiry_timestamp_seconds,
            } => MockAttestation::WithConstraints {
                mpc_docker_image_hash: mpc_docker_image_hash.map(Into::into),
                launcher_docker_compose_hash: launcher_docker_compose_hash.map(Into::into),
                expiry_timestamp_seconds,
            },
        }
    }
}

impl TryIntoContractType<DstackAttestation> for dtos::DstackAttestation {
    type Error = Error;
    fn try_into_contract_type(self) -> Result<DstackAttestation, Self::Error> {
        let dtos::DstackAttestation {
            quote,
            collateral,
            tcb_info,
        } = self;

        Ok(DstackAttestation {
            quote: quote.into(),
            collateral: collateral.into_contract_type(),
            tcb_info: tcb_info.try_into_contract_type()?,
        })
    }
}

impl IntoContractType<Collateral> for dtos::Collateral {
    fn into_contract_type(self) -> Collateral {
        let dtos::Collateral {
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            tcb_info_issuer_chain,
            tcb_info,
            tcb_info_signature,
            qe_identity_issuer_chain,
            qe_identity,
            qe_identity_signature,
            pck_certificate_chain,
        } = self;

        Collateral::from(QuoteCollateralV3 {
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            tcb_info_issuer_chain,
            tcb_info,
            tcb_info_signature,
            qe_identity_issuer_chain,
            qe_identity,
            qe_identity_signature,
            pck_certificate_chain,
        })
    }
}

impl TryIntoContractType<TcbInfo> for dtos::TcbInfo {
    type Error = Error;
    fn try_into_contract_type(self) -> Result<TcbInfo, Self::Error> {
        let dtos::TcbInfo {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            os_image_hash,
            compose_hash,
            device_id,
            app_compose,
            event_log,
        } = self;

        let event_log = event_log
            .into_iter()
            .map(|event| event.try_into_contract_type())
            .collect::<Result<Vec<_>, _>>()?;

        fn try_convert<const N: usize>(str: String) -> Result<HexBytes<N>, Error> {
            str.try_into().map_err(|err| {
                ConversionError::DataConversion.message(format!("Failed to get digest: {err}"))
            })
        }

        let os_image_hash = if os_image_hash.is_empty() {
            None
        } else {
            Some(try_convert(os_image_hash)?)
        };

        Ok(TcbInfo {
            mrtd: try_convert(mrtd)?,
            rtmr0: try_convert(rtmr0)?,
            rtmr1: try_convert(rtmr1)?,
            rtmr2: try_convert(rtmr2)?,
            rtmr3: try_convert(rtmr3)?,
            os_image_hash,
            compose_hash: try_convert(compose_hash)?,
            device_id: try_convert(device_id)?,
            app_compose,
            event_log,
        })
    }
}

impl TryIntoContractType<EventLog> for dtos::EventLog {
    type Error = Error;
    fn try_into_contract_type(self) -> Result<EventLog, Self::Error> {
        let dtos::EventLog {
            imr,
            event_type,
            digest,
            event,
            event_payload,
        } = self;

        Ok(EventLog {
            imr,
            event_type,
            digest: digest.try_into().map_err(|err| {
                ConversionError::DataConversion.message(format!("Failed to get digest: {err}"))
            })?,
            event,
            event_payload,
        })
    }
}

impl IntoInterfaceType<dtos::VerifiedAttestation> for VerifiedAttestation {
    fn into_dto_type(self) -> dtos::VerifiedAttestation {
        match self {
            VerifiedAttestation::Mock(mock_attestation) => {
                dtos::VerifiedAttestation::Mock(mock_attestation.into_dto_type())
            }
            VerifiedAttestation::Dstack(validated_dstack_attestation) => {
                dtos::VerifiedAttestation::Dstack(dtos::VerifiedDstackAttestation {
                    mpc_image_hash: validated_dstack_attestation.mpc_image_hash.into(),
                    launcher_compose_hash: validated_dstack_attestation
                        .launcher_compose_hash
                        .into(),
                    expiry_timestamp_seconds: validated_dstack_attestation.expiry_timestamp_seconds,
                })
            }
        }
    }
}

impl IntoInterfaceType<dtos::MockAttestation> for MockAttestation {
    fn into_dto_type(self) -> dtos::MockAttestation {
        match self {
            MockAttestation::Valid => dtos::MockAttestation::Valid,
            MockAttestation::Invalid => dtos::MockAttestation::Invalid,
            MockAttestation::WithConstraints {
                mpc_docker_image_hash,
                launcher_docker_compose_hash,
                expiry_timestamp_seconds,
            } => dtos::MockAttestation::WithConstraints {
                mpc_docker_image_hash: mpc_docker_image_hash.map(Into::into),
                launcher_docker_compose_hash: launcher_docker_compose_hash.map(Into::into),
                expiry_timestamp_seconds,
            },
        }
    }
}

impl IntoInterfaceType<dtos::DstackAttestation> for DstackAttestation {
    fn into_dto_type(self) -> dtos::DstackAttestation {
        let DstackAttestation {
            quote,
            collateral,
            tcb_info,
        } = self;

        dtos::DstackAttestation {
            quote: quote.into(),
            collateral: collateral.into_dto_type(),
            tcb_info: tcb_info.into_dto_type(),
        }
    }
}

impl IntoInterfaceType<dtos::Collateral> for Collateral {
    fn into_dto_type(self) -> dtos::Collateral {
        // Collateral is a newtype wrapper around QuoteCollateralV3
        let QuoteCollateralV3 {
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            tcb_info_issuer_chain,
            tcb_info,
            tcb_info_signature,
            qe_identity_issuer_chain,
            qe_identity,
            qe_identity_signature,
            pck_certificate_chain,
        } = self.into();

        dtos::Collateral {
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            tcb_info_issuer_chain,
            tcb_info,
            tcb_info_signature,
            qe_identity_issuer_chain,
            qe_identity,
            qe_identity_signature,
            pck_certificate_chain,
        }
    }
}

impl IntoInterfaceType<dtos::TcbInfo> for TcbInfo {
    fn into_dto_type(self) -> dtos::TcbInfo {
        let TcbInfo {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            os_image_hash,
            compose_hash,
            device_id,
            app_compose,
            event_log,
        } = self;

        let event_log = event_log
            .into_iter()
            .map(IntoInterfaceType::into_dto_type)
            .collect();

        dtos::TcbInfo {
            mrtd: mrtd.into(),
            rtmr0: rtmr0.into(),
            rtmr1: rtmr1.into(),
            rtmr2: rtmr2.into(),
            rtmr3: rtmr3.into(),
            os_image_hash: os_image_hash.map(|v| v.into()).unwrap_or("".into()),
            compose_hash: compose_hash.into(),
            device_id: device_id.into(),
            app_compose,
            event_log,
        }
    }
}

impl IntoInterfaceType<dtos::EventLog> for EventLog {
    fn into_dto_type(self) -> dtos::EventLog {
        let EventLog {
            imr,
            event_type,
            digest,
            event,
            event_payload,
        } = self;

        dtos::EventLog {
            imr,
            event_type,
            digest: digest.into(),
            event,
            event_payload,
        }
    }
}

impl IntoInterfaceType<dtos::Secp256k1PublicKey> for &k256_types::PublicKey {
    fn into_dto_type(self) -> dtos::Secp256k1PublicKey {
        let mut bytes = [0u8; 64];
        // The first byte is the curve type
        bytes.copy_from_slice(&self.to_encoded_point(false).to_bytes()[1..]);
        dtos::Secp256k1PublicKey::from(bytes)
    }
}

// This is not yet used, but will be necessary once we complete the migration from near_sdk::PublicKey
impl TryIntoContractType<k256_types::PublicKey> for dtos::Secp256k1PublicKey {
    type Error = Error;
    fn try_into_contract_type(self) -> Result<k256_types::PublicKey, Error> {
        let mut bytes = [0u8; 65];
        bytes[1..].copy_from_slice(&self.0);
        // The first byte is the curve representation, in this case uncompressed
        bytes[0] = 0x4;
        let point = EncodedPoint::from_bytes(bytes).map_err(|err| {
            ConversionError::DataConversion.message(format!("Failed to get EncodedPoint: {err}"))
        })?;
        k256_types::PublicKey::from_encoded_point(&point)
            .into_option()
            .ok_or(
                ConversionError::DataConversion
                    .message("Failed to convert EncodedPoint to PublicKey"),
            )
    }
}

impl IntoInterfaceType<dtos::Ed25519PublicKey> for &CompressedEdwardsY {
    fn into_dto_type(self) -> dtos::Ed25519PublicKey {
        dtos::Ed25519PublicKey::from(self.to_bytes())
    }
}

#[cfg(any(test, feature = "test-utils", feature = "dev-utils"))]
impl IntoInterfaceType<dtos::Bls12381G1PublicKey> for &ckd::ElementG1 {
    fn into_dto_type(self) -> dtos::Bls12381G1PublicKey {
        dtos::Bls12381G1PublicKey::from(self.to_compressed())
    }
}

// These are temporary conversions to avoid breaking the contract API.
// Once we complete the migration from near_sdk::PublicKey they should not be
// needed anymore
impl TryIntoInterfaceType<dtos::Ed25519PublicKey> for &near_sdk::PublicKey {
    type Error = Error;
    fn try_into_dto_type(self) -> Result<dtos::Ed25519PublicKey, Error> {
        // This function should not be called with any other curve type
        match self.curve_type() {
            near_sdk::CurveType::ED25519 => {
                let mut bytes = [0u8; 32];
                // The first byte is the curve type
                bytes.copy_from_slice(&self.as_bytes()[1..]);
                Ok(dtos::Ed25519PublicKey::from(bytes))
            }
            curve_type => Err(ConversionError::DataConversion
                .message(format!("Wrong curve type was used: {curve_type:?}"))),
        }
    }
}

impl IntoContractType<near_sdk::PublicKey> for &dtos::Ed25519PublicKey {
    fn into_contract_type(self) -> near_sdk::PublicKey {
        // This will never panic, as type Ed25519PublicKey enforces the correct key size
        near_sdk::PublicKey::from_parts(near_sdk::CurveType::ED25519, self.0.into()).unwrap()
    }
}

impl IntoContractType<near_sdk::PublicKey> for &dtos::Secp256k1PublicKey {
    fn into_contract_type(self) -> near_sdk::PublicKey {
        // This will never panic, as type Secp256k1PublicKey enforces the correct key size
        near_sdk::PublicKey::from_parts(near_sdk::CurveType::SECP256K1, self.0.into()).unwrap()
    }
}

impl IntoInterfaceType<dtos::PublicKey> for &near_sdk::PublicKey {
    // This will never panic, because the key sizes match
    fn into_dto_type(self) -> dtos::PublicKey {
        match self.curve_type() {
            near_sdk::CurveType::SECP256K1 => {
                let mut bytes = [0u8; 64];
                // The first byte is the curve type
                bytes.copy_from_slice(&self.as_bytes()[1..]);
                dtos::PublicKey::from(dtos::Secp256k1PublicKey::from(bytes))
            }
            near_sdk::CurveType::ED25519 => {
                let mut bytes = [0u8; 32];
                // The first byte is the curve type
                bytes.copy_from_slice(&self.as_bytes()[1..]);
                dtos::PublicKey::from(dtos::Ed25519PublicKey::from(bytes))
            }
        }
    }
}

impl IntoInterfaceType<dtos::AccountId> for &AccountId {
    fn into_dto_type(self) -> dtos::AccountId {
        dtos::AccountId(self.clone().into())
    }
}

impl IntoInterfaceType<dtos::UpdateHash> for &Update {
    fn into_dto_type(self) -> dtos::UpdateHash {
        match self {
            Update::Contract(code) => dtos::UpdateHash::Code(sha256_array(code)),
            Update::Config(config) => dtos::UpdateHash::Config(sha256_array(
                serde_json::to_vec(config).expect("serde serialization must succeed"),
            )),
        }
    }
}

impl IntoInterfaceType<dtos::ProposedUpdates> for &ProposedUpdates {
    fn into_dto_type(self) -> dtos::ProposedUpdates {
        let all = self.all_updates();

        let votes = all
            .votes
            .into_iter()
            .map(|(account, update_id)| (account.into_dto_type(), update_id.0))
            .collect();

        let updates = all
            .updates
            .into_iter()
            .map(|(update_id, update)| (update_id.0, update))
            .collect();

        dtos::ProposedUpdates { votes, updates }
    }
}

impl From<contract_interface::types::InitConfig> for Config {
    fn from(config_ext: contract_interface::types::InitConfig) -> Self {
        let mut config = super::Config::default();

        if let Some(v) = config_ext.key_event_timeout_blocks {
            config.key_event_timeout_blocks = v;
        }
        if let Some(v) = config_ext.tee_upgrade_deadline_duration_seconds {
            config.tee_upgrade_deadline_duration_seconds = v;
        }
        if let Some(v) = config_ext.contract_upgrade_deposit_tera_gas {
            config.contract_upgrade_deposit_tera_gas = v;
        }
        if let Some(v) = config_ext.sign_call_gas_attachment_requirement_tera_gas {
            config.sign_call_gas_attachment_requirement_tera_gas = v;
        }
        if let Some(v) = config_ext.ckd_call_gas_attachment_requirement_tera_gas {
            config.ckd_call_gas_attachment_requirement_tera_gas = v;
        }
        if let Some(v) = config_ext.return_signature_and_clean_state_on_success_call_tera_gas {
            config.return_signature_and_clean_state_on_success_call_tera_gas = v;
        }
        if let Some(v) = config_ext.return_ck_and_clean_state_on_success_call_tera_gas {
            config.return_ck_and_clean_state_on_success_call_tera_gas = v;
        }
        if let Some(v) = config_ext.fail_on_timeout_tera_gas {
            config.fail_on_timeout_tera_gas = v;
        }
        if let Some(v) = config_ext.clean_tee_status_tera_gas {
            config.clean_tee_status_tera_gas = v;
        }
        if let Some(v) = config_ext.cleanup_orphaned_node_migrations_tera_gas {
            config.cleanup_orphaned_node_migrations_tera_gas = v;
        }
        if let Some(v) = config_ext.remove_non_participant_update_votes_tera_gas {
            config.remove_non_participant_update_votes_tera_gas = v;
        }

        config
    }
}

impl From<&Config> for contract_interface::types::Config {
    fn from(value: &Config) -> Self {
        contract_interface::types::Config {
            key_event_timeout_blocks: value.key_event_timeout_blocks,
            tee_upgrade_deadline_duration_seconds: value.tee_upgrade_deadline_duration_seconds,
            contract_upgrade_deposit_tera_gas: value.contract_upgrade_deposit_tera_gas,
            sign_call_gas_attachment_requirement_tera_gas: value
                .sign_call_gas_attachment_requirement_tera_gas,
            ckd_call_gas_attachment_requirement_tera_gas: value
                .ckd_call_gas_attachment_requirement_tera_gas,
            return_signature_and_clean_state_on_success_call_tera_gas: value
                .return_signature_and_clean_state_on_success_call_tera_gas,
            return_ck_and_clean_state_on_success_call_tera_gas: value
                .return_ck_and_clean_state_on_success_call_tera_gas,
            fail_on_timeout_tera_gas: value.fail_on_timeout_tera_gas,
            clean_tee_status_tera_gas: value.clean_tee_status_tera_gas,
            cleanup_orphaned_node_migrations_tera_gas: value
                .cleanup_orphaned_node_migrations_tera_gas,
            remove_non_participant_update_votes_tera_gas: value
                .remove_non_participant_update_votes_tera_gas,
        }
    }
}

impl From<contract_interface::types::Config> for Config {
    fn from(value: contract_interface::types::Config) -> Self {
        Config {
            key_event_timeout_blocks: value.key_event_timeout_blocks,
            tee_upgrade_deadline_duration_seconds: value.tee_upgrade_deadline_duration_seconds,
            contract_upgrade_deposit_tera_gas: value.contract_upgrade_deposit_tera_gas,
            sign_call_gas_attachment_requirement_tera_gas: value
                .sign_call_gas_attachment_requirement_tera_gas,
            ckd_call_gas_attachment_requirement_tera_gas: value
                .ckd_call_gas_attachment_requirement_tera_gas,
            return_signature_and_clean_state_on_success_call_tera_gas: value
                .return_signature_and_clean_state_on_success_call_tera_gas,
            return_ck_and_clean_state_on_success_call_tera_gas: value
                .return_ck_and_clean_state_on_success_call_tera_gas,
            fail_on_timeout_tera_gas: value.fail_on_timeout_tera_gas,
            clean_tee_status_tera_gas: value.clean_tee_status_tera_gas,
            cleanup_orphaned_node_migrations_tera_gas: value
                .cleanup_orphaned_node_migrations_tera_gas,
            remove_non_participant_update_votes_tera_gas: value
                .remove_non_participant_update_votes_tera_gas,
        }
    }
}

// =============================================================================
// State DTO Conversions
// =============================================================================

// --- Simple wrapper types ---

impl IntoInterfaceType<dtos::EpochId> for EpochId {
    fn into_dto_type(self) -> dtos::EpochId {
        dtos::EpochId(self.get())
    }
}

impl IntoInterfaceType<dtos::AttemptId> for AttemptId {
    fn into_dto_type(self) -> dtos::AttemptId {
        dtos::AttemptId(self.get())
    }
}

impl IntoInterfaceType<dtos::DomainId> for DomainId {
    fn into_dto_type(self) -> dtos::DomainId {
        dtos::DomainId(*self) // DomainId derives Deref
    }
}

impl IntoInterfaceType<dtos::Threshold> for Threshold {
    fn into_dto_type(self) -> dtos::Threshold {
        dtos::Threshold(self.value())
    }
}

impl IntoInterfaceType<dtos::AuthenticatedParticipantId> for &AuthenticatedParticipantId {
    fn into_dto_type(self) -> dtos::AuthenticatedParticipantId {
        dtos::AuthenticatedParticipantId(dtos::ParticipantId(self.get().get()))
    }
}

impl IntoInterfaceType<dtos::AuthenticatedAccountId> for &AuthenticatedAccountId {
    fn into_dto_type(self) -> dtos::AuthenticatedAccountId {
        dtos::AuthenticatedAccountId(dtos::AccountId(self.get().to_string()))
    }
}

// --- Domain types ---

impl IntoInterfaceType<dtos::SignatureScheme> for SignatureScheme {
    fn into_dto_type(self) -> dtos::SignatureScheme {
        match self {
            SignatureScheme::Secp256k1 => dtos::SignatureScheme::Secp256k1,
            SignatureScheme::Ed25519 => dtos::SignatureScheme::Ed25519,
            SignatureScheme::Bls12381 => dtos::SignatureScheme::Bls12381,
            SignatureScheme::V2Secp256k1 => dtos::SignatureScheme::V2Secp256k1,
        }
    }
}

impl IntoInterfaceType<dtos::DomainPurpose> for crate::primitives::domain::DomainPurpose {
    fn into_dto_type(self) -> dtos::DomainPurpose {
        match self {
            crate::primitives::domain::DomainPurpose::Sign => dtos::DomainPurpose::Sign,
            crate::primitives::domain::DomainPurpose::ForeignTx => dtos::DomainPurpose::ForeignTx,
            crate::primitives::domain::DomainPurpose::CKD => dtos::DomainPurpose::CKD,
        }
    }
}

impl IntoInterfaceType<dtos::DomainConfig> for &DomainConfig {
    fn into_dto_type(self) -> dtos::DomainConfig {
        dtos::DomainConfig {
            id: self.id.into_dto_type(),
            scheme: self.scheme.into_dto_type(),
            purpose: self.purpose.into_dto_type(),
        }
    }
}

impl IntoInterfaceType<dtos::DomainRegistry> for &DomainRegistry {
    fn into_dto_type(self) -> dtos::DomainRegistry {
        dtos::DomainRegistry {
            domains: self.domains().iter().map(|d| d.into_dto_type()).collect(),
            next_domain_id: self.next_domain_id(),
        }
    }
}

// --- PublicKeyExtended ---

impl IntoInterfaceType<dtos::PublicKeyExtended> for &PublicKeyExtended {
    fn into_dto_type(self) -> dtos::PublicKeyExtended {
        match self {
            PublicKeyExtended::Secp256k1 { near_public_key } => {
                dtos::PublicKeyExtended::Secp256k1 {
                    near_public_key: String::from(near_public_key),
                }
            }
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
}

// --- Key state types ---

impl IntoInterfaceType<dtos::KeyForDomain> for &KeyForDomain {
    fn into_dto_type(self) -> dtos::KeyForDomain {
        dtos::KeyForDomain {
            domain_id: self.domain_id.into_dto_type(),
            key: (&self.key).into_dto_type(),
            attempt: self.attempt.into_dto_type(),
        }
    }
}

impl IntoInterfaceType<dtos::Keyset> for &Keyset {
    fn into_dto_type(self) -> dtos::Keyset {
        dtos::Keyset {
            epoch_id: self.epoch_id.into_dto_type(),
            domains: self.domains.iter().map(|k| k.into_dto_type()).collect(),
        }
    }
}

impl IntoInterfaceType<dtos::KeyEventId> for &KeyEventId {
    fn into_dto_type(self) -> dtos::KeyEventId {
        dtos::KeyEventId {
            epoch_id: self.epoch_id.into_dto_type(),
            domain_id: self.domain_id.into_dto_type(),
            attempt_id: self.attempt_id.into_dto_type(),
        }
    }
}

// --- Participants types ---

impl IntoInterfaceType<dtos::Participants> for &Participants {
    fn into_dto_type(self) -> dtos::Participants {
        dtos::Participants {
            next_id: dtos::ParticipantId(self.next_id().get()),
            participants: self
                .participants()
                .iter()
                .map(|(account_id, participant_id, info)| {
                    (
                        dtos::AccountId(account_id.to_string()),
                        dtos::ParticipantId(participant_id.get()),
                        dtos::ParticipantInfo {
                            url: info.url.clone(),
                            sign_pk: String::from(&info.sign_pk),
                        },
                    )
                })
                .collect(),
        }
    }
}

impl IntoInterfaceType<dtos::ThresholdParameters> for &ThresholdParameters {
    fn into_dto_type(self) -> dtos::ThresholdParameters {
        dtos::ThresholdParameters {
            participants: self.participants().into_dto_type(),
            threshold: self.threshold().into_dto_type(),
        }
    }
}

// --- Voting types ---

impl IntoInterfaceType<dtos::ThresholdParametersVotes> for &ThresholdParametersVotes {
    fn into_dto_type(self) -> dtos::ThresholdParametersVotes {
        dtos::ThresholdParametersVotes {
            proposal_by_account: self
                .proposal_by_account
                .iter()
                .map(|(account, params)| (account.into_dto_type(), params.into_dto_type()))
                .collect(),
        }
    }
}

impl IntoInterfaceType<dtos::AddDomainsVotes> for &AddDomainsVotes {
    fn into_dto_type(self) -> dtos::AddDomainsVotes {
        dtos::AddDomainsVotes {
            proposal_by_account: self
                .proposal_by_account
                .iter()
                .map(|(participant, domains)| {
                    (
                        participant.into_dto_type(),
                        domains.iter().map(|d| d.into_dto_type()).collect(),
                    )
                })
                .collect(),
        }
    }
}

// --- Key event types ---

impl IntoInterfaceType<dtos::KeyEventInstance> for &KeyEventInstance {
    fn into_dto_type(self) -> dtos::KeyEventInstance {
        dtos::KeyEventInstance {
            attempt_id: self.attempt_id().into_dto_type(),
            started_in: self.started_in(),
            expires_on: self.expires_on(),
            completed: self.completed().iter().map(|p| p.into_dto_type()).collect(),
            public_key: self.public_key().map(|pk| pk.into_dto_type()),
        }
    }
}

impl IntoInterfaceType<dtos::KeyEvent> for &KeyEvent {
    fn into_dto_type(self) -> dtos::KeyEvent {
        dtos::KeyEvent {
            epoch_id: self.epoch_id().into_dto_type(),
            domain: (&self.domain()).into_dto_type(),
            parameters: self.proposed_parameters().into_dto_type(),
            instance: self.instance().as_ref().map(|i| i.into_dto_type()),
            next_attempt_id: self.next_attempt_id().into_dto_type(),
        }
    }
}

// --- Contract state types ---

impl IntoInterfaceType<dtos::InitializingContractState> for &InitializingContractState {
    fn into_dto_type(self) -> dtos::InitializingContractState {
        dtos::InitializingContractState {
            domains: (&self.domains).into_dto_type(),
            epoch_id: self.epoch_id.into_dto_type(),
            generated_keys: self
                .generated_keys
                .iter()
                .map(|k| k.into_dto_type())
                .collect(),
            generating_key: (&self.generating_key).into_dto_type(),
            cancel_votes: self
                .cancel_votes
                .iter()
                .map(|p| p.into_dto_type())
                .collect(),
        }
    }
}

impl IntoInterfaceType<dtos::RunningContractState> for &RunningContractState {
    fn into_dto_type(self) -> dtos::RunningContractState {
        dtos::RunningContractState {
            domains: (&self.domains).into_dto_type(),
            keyset: (&self.keyset).into_dto_type(),
            parameters: (&self.parameters).into_dto_type(),
            parameters_votes: (&self.parameters_votes).into_dto_type(),
            add_domains_votes: (&self.add_domains_votes).into_dto_type(),
            previously_cancelled_resharing_epoch_id: self
                .previously_cancelled_resharing_epoch_id
                .map(|e| e.into_dto_type()),
        }
    }
}

impl IntoInterfaceType<dtos::ResharingContractState> for &ResharingContractState {
    fn into_dto_type(self) -> dtos::ResharingContractState {
        dtos::ResharingContractState {
            previous_running_state: (&self.previous_running_state).into_dto_type(),
            reshared_keys: self
                .reshared_keys
                .iter()
                .map(|k| k.into_dto_type())
                .collect(),
            resharing_key: (&self.resharing_key).into_dto_type(),
            cancellation_requests: self
                .cancellation_requests
                .iter()
                .map(|a| a.into_dto_type())
                .collect(),
        }
    }
}

impl IntoInterfaceType<dtos::ProtocolContractState> for &ProtocolContractState {
    fn into_dto_type(self) -> dtos::ProtocolContractState {
        match self {
            ProtocolContractState::NotInitialized => dtos::ProtocolContractState::NotInitialized,
            ProtocolContractState::Initializing(state) => {
                dtos::ProtocolContractState::Initializing(state.into_dto_type())
            }
            ProtocolContractState::Running(state) => {
                dtos::ProtocolContractState::Running(state.into_dto_type())
            }
            ProtocolContractState::Resharing(state) => {
                dtos::ProtocolContractState::Resharing(state.into_dto_type())
            }
        }
    }
}

impl TryIntoContractType<k256::AffinePoint> for dtos::K256AffinePoint {
    type Error = Error;
    fn try_into_contract_type(self) -> Result<k256::AffinePoint, Self::Error> {
        k256::AffinePoint::from_bytes(&self.affine_point.into())
            .into_option()
            .ok_or(ConversionError::DataConversion.message("Failed to convert k256 affine point"))
    }
}

impl TryIntoContractType<k256::Scalar> for dtos::K256Scalar {
    type Error = Error;
    fn try_into_contract_type(self) -> Result<k256::Scalar, Self::Error> {
        k256::Scalar::from_repr_vartime(self.scalar.into())
            .ok_or(ConversionError::DataConversion.message("Failed to convert k256 scalar"))
    }
}

// Temporary location of this logic until we decide where it should live

pub fn args_into_verify_foreign_tx_request(
    args: dtos::VerifyForeignTransactionRequestArgs,
    predecessor_id: &AccountId,
) -> dtos::VerifyForeignTransactionRequest {
    let tweak = derive_foreign_tx_tweak(predecessor_id, &args.derivation_path);
    dtos::VerifyForeignTransactionRequest {
        domain_id: args.domain_id,
        tweak,
        request: args.request,
        payload_version: args.payload_version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_THRESHOLD: u64 = 2;

    fn test_participants() -> Participants {
        let mut participants = Participants::new();
        participants
            .insert(
                "alice.near".parse().unwrap(),
                crate::primitives::participants::ParticipantInfo {
                    url: "https://alice.near.org".to_string(),
                    sign_pk: "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp"
                        .parse()
                        .unwrap(),
                },
            )
            .unwrap();
        participants
            .insert(
                "bob.near".parse().unwrap(),
                crate::primitives::participants::ParticipantInfo {
                    url: "https://bob.near.org".to_string(),
                    sign_pk: "ed25519:HghFShDXwniWaV3CbMmPJsUjeLZBJ2jjCq6rM3AQYbx7"
                        .parse()
                        .unwrap(),
                },
            )
            .unwrap();
        participants
    }

    /// Ensures that the JSON produced by serializing the internal [`Participants`]
    /// type can be deserialized into the DTO [`dtos::Participants`] type and
    /// vice versa, producing identical JSON in both directions.
    #[test]
    fn participants_serde_is_compatible_with_dto() {
        let internal = test_participants();
        let json = serde_json::to_value(&internal).unwrap();

        // Internal JSON → DTO type.
        let dto: dtos::Participants = serde_json::from_value(json.clone()).unwrap();

        // DTO → JSON must match the original.
        let dto_json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json, dto_json, "Internal and DTO JSON must be identical");

        // Full round-trip back to the internal type.
        let roundtrip: Participants = serde_json::from_value(dto_json).unwrap();
        assert_eq!(internal, roundtrip);
    }

    /// Ensures that the JSON produced by serializing the internal
    /// [`ThresholdParameters`] type can be deserialized into the DTO
    /// [`dtos::ThresholdParameters`] type and vice versa, producing identical
    /// JSON in both directions.
    #[test]
    fn threshold_parameters_serde_is_compatible_with_dto() {
        let internal =
            ThresholdParameters::new(test_participants(), Threshold::new(TEST_THRESHOLD)).unwrap();
        let json = serde_json::to_value(&internal).unwrap();

        let dto: dtos::ThresholdParameters = serde_json::from_value(json.clone()).unwrap();

        let dto_json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json, dto_json, "Internal and DTO JSON must be identical");

        let roundtrip: ThresholdParameters = serde_json::from_value(dto_json).unwrap();
        assert_eq!(internal, roundtrip);
    }

    /// Verify that [`IntoInterfaceType::into_dto_type`] produces a DTO whose
    /// serialization matches the internal type's serialization.
    #[test]
    fn into_dto_type_preserves_serialization() {
        let internal =
            ThresholdParameters::new(test_participants(), Threshold::new(TEST_THRESHOLD)).unwrap();
        let internal_json = serde_json::to_value(&internal).unwrap();

        let dto: dtos::ThresholdParameters = internal.into_dto_type();
        let dto_json = serde_json::to_value(&dto).unwrap();

        assert_eq!(internal_json, dto_json);
    }
}
