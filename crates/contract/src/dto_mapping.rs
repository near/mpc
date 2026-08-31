//! This module provides convenience methods to map contract interface types
//! from [`near_mpc_contract_interface::types`] to internal types.
//!
//! These types are mapped with the [IntoContractType] trait. We can not use [`From`]
//! and [`Into`] due to the [*orphan rule*](https://doc.rust-lang.org/reference/items/implementations.html#orphan-rules).

use k256::elliptic_curve::group::GroupEncoding as _;
use mpc_attestation::{
    EventLog, HexBytes, TcbInfo,
    attestation::{
        Attestation, DstackAttestation, ExpectedMeasurements, Measurements, MockAttestation,
        VerifiedAttestation,
    },
    collateral::Collateral,
};
use near_mpc_contract_interface::types as dtos;
use near_sdk::env::sha256_array;

use crate::{
    config::Config,
    crypto_shared::types::{PublicKeyExtended, serializable::SerializableEdwardsPoint},
    errors::{ConversionError, Error},
    primitives::{
        domain::{AddDomainsVotes, DomainRegistry},
        key_state::{AuthenticatedAccountId, AuthenticatedParticipantId, KeyForDomain, Keyset},
        participants::{ParticipantInfo, Participants},
        threshold_votes::GovernanceThresholdParametersVotes,
        thresholds::{GovernanceThresholdParameters, ProposedGovernanceThresholdParameters},
    },
    state::{
        ProtocolContractState,
        initializing::InitializingContractState,
        key_event::{KeyEvent, KeyEventInstance},
        resharing::ResharingContractState,
        running::RunningContractState,
    },
    update::{ProposedUpdates, Update, UpdateId},
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
                expected_measurements,
            } => MockAttestation::WithConstraints {
                mpc_docker_image_hash,
                launcher_docker_compose_hash,
                expiry_timestamp_seconds,
                expected_measurements: expected_measurements.map(|m| ExpectedMeasurements {
                    rtmrs: Measurements {
                        mrtd: m.mrtd.into(),
                        rtmr0: m.rtmr0.into(),
                        rtmr1: m.rtmr1.into(),
                        rtmr2: m.rtmr2.into(),
                    },
                    key_provider_event_digest: m.key_provider_event_digest.into(),
                }),
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
            quote: Vec::from(quote).into(),
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

        // TODO(#3494): drop this conversion once `dtos::DstackAttestation`
        // carries `tee_verifier_interface::Collateral` directly.
        Collateral {
            pck_crl_issuer_chain,
            root_ca_crl: root_ca_crl.into(),
            pck_crl: pck_crl.into(),
            tcb_info_issuer_chain,
            tcb_info,
            tcb_info_signature: tcb_info_signature.into(),
            qe_identity_issuer_chain,
            qe_identity,
            qe_identity_signature: qe_identity_signature.into(),
            pck_certificate_chain,
        }
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
                ConversionError::DataConversion {
                    reason: format!("Failed to get digest: {err}"),
                }
                .into()
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

impl IntoContractType<ParticipantInfo> for dtos::ParticipantInfo {
    fn into_contract_type(self) -> ParticipantInfo {
        ParticipantInfo {
            url: self.url,
            tls_public_key: self.tls_public_key,
        }
    }
}

impl IntoContractType<Participants> for dtos::Participants {
    fn into_contract_type(self) -> Participants {
        let participants = self
            .participants
            .into_iter()
            .map(|(account_id, participant_id, info)| {
                (account_id, participant_id, info.into_contract_type())
            })
            .collect();
        Participants::init(self.next_id, participants)
    }
}

impl TryIntoContractType<GovernanceThresholdParameters> for dtos::GovernanceThresholdParameters {
    type Error = Error;

    fn try_into_contract_type(self) -> Result<GovernanceThresholdParameters, Self::Error> {
        // Validate eagerly at the DTO boundary so invalid proposal parameters are rejected here.
        GovernanceThresholdParameters::new(self.participants.into_contract_type(), self.threshold)
    }
}

impl TryIntoContractType<ProposedGovernanceThresholdParameters>
    for dtos::ProposedGovernanceThresholdParameters
{
    type Error = Error;

    fn try_into_contract_type(self) -> Result<ProposedGovernanceThresholdParameters, Self::Error> {
        // Validates the inner threshold parameters; see the conversion above.
        Ok(ProposedGovernanceThresholdParameters::new(
            self.parameters.try_into_contract_type()?,
            self.per_domain_thresholds,
        ))
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
            digest: digest
                .try_into()
                .map_err(|err| ConversionError::DataConversion {
                    reason: format!("Failed to get digest: {err}"),
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
            VerifiedAttestation::Dstack(v) => {
                dtos::VerifiedAttestation::Dstack(dtos::VerifiedDstackAttestation {
                    mpc_image_hash: v.mpc_image_hash,
                    launcher_compose_hash: v.launcher_compose_hash,
                    expiry_timestamp_seconds: v.expiry_timestamp_seconds,
                    measurements: dtos::VerifiedMeasurements {
                        mrtd: v.measurements.rtmrs.mrtd.into(),
                        rtmr0: v.measurements.rtmrs.rtmr0.into(),
                        rtmr1: v.measurements.rtmrs.rtmr1.into(),
                        rtmr2: v.measurements.rtmrs.rtmr2.into(),
                        key_provider_event_digest: v.measurements.key_provider_event_digest.into(),
                    },
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
                expected_measurements,
            } => dtos::MockAttestation::WithConstraints {
                mpc_docker_image_hash,
                launcher_docker_compose_hash,
                expiry_timestamp_seconds,
                expected_measurements: expected_measurements.map(|m| dtos::VerifiedMeasurements {
                    mrtd: m.rtmrs.mrtd.into(),
                    rtmr0: m.rtmrs.rtmr0.into(),
                    rtmr1: m.rtmrs.rtmr1.into(),
                    rtmr2: m.rtmrs.rtmr2.into(),
                    key_provider_event_digest: m.key_provider_event_digest.into(),
                }),
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
            quote: Vec::from(quote).into(),
            collateral: collateral.into_dto_type(),
            tcb_info: tcb_info.into_dto_type(),
        }
    }
}

impl IntoInterfaceType<dtos::Collateral> for Collateral {
    fn into_dto_type(self) -> dtos::Collateral {
        // TODO(#3494): drop this conversion once `dtos` carries the interface
        // `Collateral` directly.
        let Collateral {
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

        dtos::Collateral {
            pck_crl_issuer_chain,
            root_ca_crl: root_ca_crl.into(),
            pck_crl: pck_crl.into(),
            tcb_info_issuer_chain,
            tcb_info,
            tcb_info_signature: tcb_info_signature.into(),
            qe_identity_issuer_chain,
            qe_identity,
            qe_identity_signature: qe_identity_signature.into(),
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

impl IntoInterfaceType<dtos::UpdateId> for UpdateId {
    fn into_dto_type(self) -> dtos::UpdateId {
        dtos::UpdateId(self.0)
    }
}

impl IntoContractType<UpdateId> for dtos::UpdateId {
    fn into_contract_type(self) -> UpdateId {
        UpdateId(self.0)
    }
}

impl IntoInterfaceType<dtos::UpdateHash> for &Update {
    fn into_dto_type(self) -> dtos::UpdateHash {
        match self {
            Update::Contract(code) => dtos::UpdateHash::Code(sha256_array(code)),
            Update::Config(config) => dtos::UpdateHash::Config(sha256_array(
                serde_json::to_vec(&config.into_dto_type())
                    .expect("serde serialization must succeed"),
            )),
        }
    }
}

impl IntoInterfaceType<dtos::Config> for &Config {
    fn into_dto_type(self) -> dtos::Config {
        dtos::Config {
            key_event_timeout_blocks: self.key_event_timeout_blocks,
            tee_upgrade_deadline_duration_seconds: self.tee_upgrade_deadline_duration_seconds,
            contract_upgrade_deposit_tera_gas: self.contract_upgrade_deposit_tera_gas,
            sign_call_gas_attachment_requirement_tera_gas: self
                .sign_call_gas_attachment_requirement_tera_gas,
            ckd_call_gas_attachment_requirement_tera_gas: self
                .ckd_call_gas_attachment_requirement_tera_gas,
            return_signature_and_clean_state_on_success_call_tera_gas: self
                .return_signature_and_clean_state_on_success_call_tera_gas,
            return_ck_and_clean_state_on_success_call_tera_gas: self
                .return_ck_and_clean_state_on_success_call_tera_gas,
            fail_on_timeout_tera_gas: self.fail_on_timeout_tera_gas,
            fail_attestation_submission_tera_gas: self.fail_attestation_submission_tera_gas,
            clean_tee_status_tera_gas: self.clean_tee_status_tera_gas,
            clean_invalid_attestations_tera_gas: self.clean_invalid_attestations_tera_gas,
            cleanup_orphaned_node_migrations_tera_gas: self
                .cleanup_orphaned_node_migrations_tera_gas,
            remove_non_participant_update_votes_tera_gas: self
                .remove_non_participant_update_votes_tera_gas,
            clean_foreign_chain_data_tera_gas: self.clean_foreign_chain_data_tera_gas,
            remove_non_participant_tee_verifier_votes_tera_gas: self
                .remove_non_participant_tee_verifier_votes_tera_gas,
            verifier_tera_gas: self.verifier_tera_gas,
            resolve_verification_tera_gas: self.resolve_verification_tera_gas,
            launcher_hash_unused_ttl_seconds: self.launcher_hash_unused_ttl_seconds,
            attestation_storage_fee_millinear: self.attestation_storage_fee_millinear,
        }
    }
}

impl IntoInterfaceType<dtos::ProposedUpdates> for &ProposedUpdates {
    fn into_dto_type(self) -> dtos::ProposedUpdates {
        let all = self.all_updates();

        let votes = all
            .votes
            .into_iter()
            .map(|(account, update_id)| (account, update_id.into_dto_type()))
            .collect();

        let updates = all
            .updates
            .into_iter()
            .map(|(update_id, update)| (update_id.into_dto_type(), update))
            .collect();

        dtos::ProposedUpdates { votes, updates }
    }
}

impl TryFrom<near_mpc_contract_interface::types::InitConfig> for Config {
    type Error = Error;

    fn try_from(
        config_ext: near_mpc_contract_interface::types::InitConfig,
    ) -> Result<Self, Self::Error> {
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
        if let Some(v) = config_ext.fail_attestation_submission_tera_gas {
            config.fail_attestation_submission_tera_gas = v;
        }
        if let Some(v) = config_ext.clean_tee_status_tera_gas {
            config.clean_tee_status_tera_gas = v;
        }
        if let Some(v) = config_ext.clean_invalid_attestations_tera_gas {
            config.clean_invalid_attestations_tera_gas = v;
        }
        if let Some(v) = config_ext.cleanup_orphaned_node_migrations_tera_gas {
            config.cleanup_orphaned_node_migrations_tera_gas = v;
        }
        if let Some(v) = config_ext.remove_non_participant_update_votes_tera_gas {
            config.remove_non_participant_update_votes_tera_gas = v;
        }
        if let Some(v) = config_ext.clean_foreign_chain_data_tera_gas {
            config.clean_foreign_chain_data_tera_gas = v;
        }
        if let Some(v) = config_ext.remove_non_participant_tee_verifier_votes_tera_gas {
            config.remove_non_participant_tee_verifier_votes_tera_gas = v;
        }
        if let Some(v) = config_ext.verifier_tera_gas {
            config.verifier_tera_gas = v;
        }
        if let Some(v) = config_ext.resolve_verification_tera_gas {
            config.resolve_verification_tera_gas = v;
        }
        if let Some(v) = config_ext.attestation_storage_fee_millinear {
            config.attestation_storage_fee_millinear = v;
        }
        if let Some(v) = config_ext.launcher_hash_unused_ttl_seconds {
            config.launcher_hash_unused_ttl_seconds = v;
        }

        config
            .validate()
            .map_err(|reason| ConversionError::DataConversion {
                reason: reason.to_string(),
            })?;
        Ok(config)
    }
}

impl From<&Config> for near_mpc_contract_interface::types::Config {
    fn from(value: &Config) -> Self {
        near_mpc_contract_interface::types::Config {
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
            fail_attestation_submission_tera_gas: value.fail_attestation_submission_tera_gas,
            clean_tee_status_tera_gas: value.clean_tee_status_tera_gas,
            clean_invalid_attestations_tera_gas: value.clean_invalid_attestations_tera_gas,
            cleanup_orphaned_node_migrations_tera_gas: value
                .cleanup_orphaned_node_migrations_tera_gas,
            remove_non_participant_update_votes_tera_gas: value
                .remove_non_participant_update_votes_tera_gas,
            clean_foreign_chain_data_tera_gas: value.clean_foreign_chain_data_tera_gas,
            remove_non_participant_tee_verifier_votes_tera_gas: value
                .remove_non_participant_tee_verifier_votes_tera_gas,
            verifier_tera_gas: value.verifier_tera_gas,
            resolve_verification_tera_gas: value.resolve_verification_tera_gas,
            attestation_storage_fee_millinear: value.attestation_storage_fee_millinear,
            launcher_hash_unused_ttl_seconds: value.launcher_hash_unused_ttl_seconds,
        }
    }
}

impl TryFrom<near_mpc_contract_interface::types::Config> for Config {
    type Error = Error;

    fn try_from(value: near_mpc_contract_interface::types::Config) -> Result<Self, Self::Error> {
        let config = Config {
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
            fail_attestation_submission_tera_gas: value.fail_attestation_submission_tera_gas,
            clean_tee_status_tera_gas: value.clean_tee_status_tera_gas,
            clean_invalid_attestations_tera_gas: value.clean_invalid_attestations_tera_gas,
            cleanup_orphaned_node_migrations_tera_gas: value
                .cleanup_orphaned_node_migrations_tera_gas,
            remove_non_participant_update_votes_tera_gas: value
                .remove_non_participant_update_votes_tera_gas,
            clean_foreign_chain_data_tera_gas: value.clean_foreign_chain_data_tera_gas,
            remove_non_participant_tee_verifier_votes_tera_gas: value
                .remove_non_participant_tee_verifier_votes_tera_gas,
            verifier_tera_gas: value.verifier_tera_gas,
            resolve_verification_tera_gas: value.resolve_verification_tera_gas,
            attestation_storage_fee_millinear: value.attestation_storage_fee_millinear,
            launcher_hash_unused_ttl_seconds: value.launcher_hash_unused_ttl_seconds,
        };

        config
            .validate()
            .map_err(|reason| ConversionError::DataConversion {
                reason: reason.to_string(),
            })?;
        Ok(config)
    }
}

// =============================================================================
// State DTO Conversions
// =============================================================================

// Test-only `From` conversions consumed outside this crate: the node (via its
// dev-dependency) and the contract's own integration tests, neither of which
// can reach the `pub(crate)` `into_dto_type` / `into_contract_type` traits.
// Gated behind `test-utils` so they stay out of the production/WASM surface.
#[cfg(feature = "test-utils")]
mod test_conversions {
    use super::*;

    impl From<ProtocolContractState> for dtos::ProtocolContractState {
        fn from(state: ProtocolContractState) -> Self {
            (&state).into_dto_type()
        }
    }

    impl From<GovernanceThresholdParameters> for dtos::GovernanceThresholdParameters {
        fn from(params: GovernanceThresholdParameters) -> Self {
            (&params).into_dto_type()
        }
    }

    impl From<ProposedGovernanceThresholdParameters> for dtos::ProposedGovernanceThresholdParameters {
        fn from(params: ProposedGovernanceThresholdParameters) -> Self {
            (&params).into_dto_type()
        }
    }

    impl From<ParticipantInfo> for dtos::ParticipantInfo {
        fn from(info: ParticipantInfo) -> Self {
            dtos::ParticipantInfo {
                url: info.url,
                tls_public_key: info.tls_public_key,
            }
        }
    }

    impl From<dtos::ParticipantInfo> for ParticipantInfo {
        fn from(info: dtos::ParticipantInfo) -> Self {
            info.into_contract_type()
        }
    }
}

// --- Simple wrapper types ---

impl IntoInterfaceType<dtos::AuthenticatedParticipantId> for &AuthenticatedParticipantId {
    fn into_dto_type(self) -> dtos::AuthenticatedParticipantId {
        dtos::AuthenticatedParticipantId(self.get())
    }
}

impl IntoInterfaceType<dtos::AuthenticatedAccountId> for &AuthenticatedAccountId {
    fn into_dto_type(self) -> dtos::AuthenticatedAccountId {
        dtos::AuthenticatedAccountId(self.get().clone())
    }
}

impl IntoInterfaceType<dtos::DomainRegistry> for &DomainRegistry {
    fn into_dto_type(self) -> dtos::DomainRegistry {
        dtos::DomainRegistry {
            domains: self.domains().to_vec(),
            next_domain_id: self.next_domain_id(),
        }
    }
}

// --- PublicKeyExtended ---

impl TryIntoContractType<PublicKeyExtended> for dtos::PublicKeyExtended {
    type Error = Error;
    fn try_into_contract_type(self) -> Result<PublicKeyExtended, Self::Error> {
        let parse_failed = |err| ConversionError::DataConversion {
            reason: format!("Failed to parse public key: {err}"),
        };

        match self {
            dtos::PublicKeyExtended::Secp256k1 { near_public_key } => {
                Ok(PublicKeyExtended::Secp256k1 {
                    near_public_key: near_public_key.parse().map_err(parse_failed)?,
                })
            }
            dtos::PublicKeyExtended::Ed25519 {
                near_public_key_compressed,
                edwards_point,
            } => {
                let near_public_key_compressed: dtos::Ed25519PublicKey =
                    near_public_key_compressed.parse().map_err(parse_failed)?;
                let derived = SerializableEdwardsPoint::from_bytes(&near_public_key_compressed)
                    .into_option()
                    .ok_or_else(|| ConversionError::DataConversion {
                        reason: "The compressed key is not a valid Edwards point.".to_string(),
                    })?;
                // The DTO carries the Edwards point alongside the compressed key; the contract
                // type derives it, so a pair that disagrees is rejected rather than dropped.
                if derived.to_bytes() != edwards_point {
                    return Err(ConversionError::DataConversion {
                        reason: "The Edwards point does not match the compressed public key."
                            .to_string(),
                    }
                    .into());
                }

                Ok(PublicKeyExtended::Ed25519 {
                    near_public_key_compressed,
                    edwards_point: derived,
                })
            }
            dtos::PublicKeyExtended::Bls12381 { public_key } => {
                let dtos::PublicKey::Bls12381(public_key) = public_key else {
                    return Err(ConversionError::DataConversion {
                        reason: "Expected a bls12381g2 public key.".to_string(),
                    }
                    .into());
                };

                Ok(PublicKeyExtended::Bls12381 { public_key })
            }
        }
    }
}

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
                public_key: dtos::PublicKey::Bls12381(public_key.clone()),
            },
        }
    }
}

// --- Participants types ---

impl IntoInterfaceType<dtos::Participants> for &Participants {
    fn into_dto_type(self) -> dtos::Participants {
        let participants = self
            .participants()
            .iter()
            .map(|(account_id, participant_id, info)| {
                (
                    account_id.clone(),
                    dtos::ParticipantId(participant_id.get()),
                    dtos::ParticipantInfo {
                        url: info.url.clone(),
                        tls_public_key: info.tls_public_key.clone(),
                    },
                )
            })
            .collect();
        dtos::Participants {
            next_id: dtos::ParticipantId(self.next_id().get()),
            participants,
        }
    }
}

impl IntoInterfaceType<dtos::GovernanceThresholdParameters> for &GovernanceThresholdParameters {
    fn into_dto_type(self) -> dtos::GovernanceThresholdParameters {
        dtos::GovernanceThresholdParameters {
            participants: self.participants().into_dto_type(),
            threshold: self.threshold(),
        }
    }
}

impl IntoInterfaceType<dtos::ProposedGovernanceThresholdParameters>
    for &ProposedGovernanceThresholdParameters
{
    fn into_dto_type(self) -> dtos::ProposedGovernanceThresholdParameters {
        dtos::ProposedGovernanceThresholdParameters {
            parameters: self.parameters().into_dto_type(),
            per_domain_thresholds: self.per_domain_thresholds().clone(),
        }
    }
}

// --- Voting types ---

impl IntoInterfaceType<dtos::GovernanceThresholdParametersVotes>
    for &GovernanceThresholdParametersVotes
{
    fn into_dto_type(self) -> dtos::GovernanceThresholdParametersVotes {
        let proposal_by_account = self
            .proposal_by_account
            .iter()
            .map(|(account, params)| (account.into_dto_type(), params.into_dto_type()))
            .collect();
        dtos::GovernanceThresholdParametersVotes {
            proposal_by_account,
        }
    }
}

impl IntoInterfaceType<dtos::AddDomainsVotes> for &AddDomainsVotes {
    fn into_dto_type(self) -> dtos::AddDomainsVotes {
        dtos::AddDomainsVotes {
            proposal_by_account: self
                .proposal_by_account
                .iter()
                .map(|(participant, domains)| (participant.into_dto_type(), domains.clone()))
                .collect(),
        }
    }
}

// --- Key state types ---

impl TryIntoContractType<KeyForDomain> for dtos::KeyForDomain {
    type Error = Error;
    fn try_into_contract_type(self) -> Result<KeyForDomain, Self::Error> {
        let dtos::KeyForDomain {
            domain_id,
            key,
            attempt,
        } = self;

        Ok(KeyForDomain {
            domain_id,
            key: key.try_into_contract_type()?,
            attempt,
        })
    }
}

impl TryIntoContractType<Keyset> for dtos::Keyset {
    type Error = Error;
    fn try_into_contract_type(self) -> Result<Keyset, Self::Error> {
        let dtos::Keyset { epoch_id, domains } = self;

        let domains = domains
            .into_iter()
            .map(TryIntoContractType::try_into_contract_type)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Keyset::new(epoch_id, domains))
    }
}

impl IntoInterfaceType<dtos::KeyForDomain> for &KeyForDomain {
    fn into_dto_type(self) -> dtos::KeyForDomain {
        dtos::KeyForDomain {
            domain_id: self.domain_id,
            key: (&self.key).into_dto_type(),
            attempt: self.attempt,
        }
    }
}

impl IntoInterfaceType<dtos::Keyset> for &Keyset {
    fn into_dto_type(self) -> dtos::Keyset {
        dtos::Keyset {
            epoch_id: self.epoch_id,
            domains: self.domains.iter().map(|k| k.into_dto_type()).collect(),
        }
    }
}

// --- Key event types ---

impl IntoInterfaceType<dtos::KeyEventInstance> for &KeyEventInstance {
    fn into_dto_type(self) -> dtos::KeyEventInstance {
        dtos::KeyEventInstance {
            attempt_id: self.attempt_id(),
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
            epoch_id: self.epoch_id(),
            domain: self.domain().clone(),
            parameters: self.proposed_parameters().into_dto_type(),
            instance: self.instance().as_ref().map(|i| i.into_dto_type()),
            next_attempt_id: self.next_attempt_id(),
        }
    }
}

// --- Contract state types ---

impl IntoInterfaceType<dtos::InitializingContractState> for &InitializingContractState {
    fn into_dto_type(self) -> dtos::InitializingContractState {
        dtos::InitializingContractState {
            domains: (&self.domains).into_dto_type(),
            epoch_id: self.epoch_id,
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
            previously_cancelled_resharing_epoch_id: self.previously_cancelled_resharing_epoch_id,
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
            per_domain_thresholds: self.per_domain_thresholds.clone(),
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

// Temporary location of this logic until we decide where it should live

pub fn args_into_verify_foreign_tx_request(
    args: dtos::VerifyForeignTransactionRequestArgs,
) -> dtos::VerifyForeignTransactionRequest {
    dtos::VerifyForeignTransactionRequest {
        domain_id: args.domain_id,
        request: args.request,
        payload_version: args.payload_version,
        expected_payload_hash: args.expected_payload_hash,
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::test_utils::make_public_key_for_curve;
    use crate::errors::InvalidThreshold;
    use crate::primitives::key_state::{AttemptId, EpochId};
    use crate::primitives::test_utils::{
        bogus_ed25519_public_key, bogus_ed25519_public_key_extended, gen_participants,
    };
    use crate::primitives::thresholds::GovernanceThreshold;
    use assert_matches::assert_matches;
    use rand::rngs::OsRng;
    use rstest::rstest;

    const TEST_THRESHOLD: u64 = 2;

    fn test_participants() -> Participants {
        let mut participants = Participants::new();
        participants
            .insert(
                "alice.near".parse().unwrap(),
                crate::primitives::participants::ParticipantInfo {
                    url: "https://alice.near.org".to_string(),
                    tls_public_key: "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp"
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
                    tls_public_key: "ed25519:HghFShDXwniWaV3CbMmPJsUjeLZBJ2jjCq6rM3AQYbx7"
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
    /// [`GovernanceThresholdParameters`] type can be deserialized into the DTO
    /// [`dtos::GovernanceThresholdParameters`] type and vice versa, producing identical
    /// JSON in both directions.
    #[test]
    fn threshold_parameters_serde_is_compatible_with_dto() {
        let internal = GovernanceThresholdParameters::new(
            test_participants(),
            GovernanceThreshold::new(TEST_THRESHOLD),
        )
        .unwrap();
        let json = serde_json::to_value(&internal).unwrap();

        let dto: dtos::GovernanceThresholdParameters =
            serde_json::from_value(json.clone()).unwrap();

        let dto_json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json, dto_json, "Internal and DTO JSON must be identical");

        let roundtrip: GovernanceThresholdParameters = serde_json::from_value(dto_json).unwrap();
        assert_eq!(internal, roundtrip);
    }

    /// Verify that [`IntoInterfaceType::into_dto_type`] produces a DTO whose
    /// serialization matches the internal type's serialization.
    #[test]
    fn into_dto_type_preserves_serialization() {
        let internal = GovernanceThresholdParameters::new(
            test_participants(),
            GovernanceThreshold::new(TEST_THRESHOLD),
        )
        .unwrap();
        let internal_json = serde_json::to_value(&internal).unwrap();

        let dto: dtos::GovernanceThresholdParameters = (&internal).into_dto_type();
        let dto_json = serde_json::to_value(&dto).unwrap();

        assert_eq!(internal_json, dto_json);
    }

    #[rstest]
    #[case(dtos::Curve::Secp256k1)]
    #[case(dtos::Curve::Edwards25519)]
    #[case(dtos::Curve::Bls12381)]
    fn keyset__should_round_trip_through_the_dto(#[case] curve: dtos::Curve) {
        // Given
        let (public_key, _) = make_public_key_for_curve(curve, &mut OsRng);
        let internal = Keyset::new(
            EpochId::new(7),
            vec![KeyForDomain {
                domain_id: dtos::DomainId(3),
                key: public_key.try_into().unwrap(),
                attempt: AttemptId::new(),
            }],
        );

        // When
        let dto: dtos::Keyset = (&internal).into_dto_type();
        let roundtrip: Keyset = dto.clone().try_into_contract_type().unwrap();

        // Then
        assert_eq!(internal, roundtrip);
        assert_eq!(
            serde_json::to_value(&internal).unwrap(),
            serde_json::to_value(&dto).unwrap()
        );
    }

    #[test]
    fn public_key_extended__should_reject_an_edwards_point_that_is_not_the_compressed_key() {
        // Given
        let dtos::PublicKeyExtended::Ed25519 {
            near_public_key_compressed,
            ..
        } = (&bogus_ed25519_public_key_extended()).into_dto_type()
        else {
            panic!("expected an ed25519 key");
        };
        let dto = dtos::PublicKeyExtended::Ed25519 {
            near_public_key_compressed,
            edwards_point: bogus_ed25519_public_key().0,
        };

        // When
        let result: Result<PublicKeyExtended, Error> = dto.try_into_contract_type();

        // Then
        assert_matches!(
            result,
            Err(Error::ConversionError(
                ConversionError::DataConversion { .. }
            ))
        );
    }

    #[rstest]
    #[case::ed25519_tag_holding_a_secp256k1_key(dtos::PublicKeyExtended::Ed25519 {
        near_public_key_compressed: String::from(&dtos::Secp256k1PublicKey([1u8; 64])),
        edwards_point: [0u8; 32],
    })]
    #[case::bls12381_tag_holding_an_ed25519_key(dtos::PublicKeyExtended::Bls12381 {
        public_key: dtos::PublicKey::Ed25519(bogus_ed25519_public_key()),
    })]
    fn public_key_extended__should_reject_a_variant_tag_that_disagrees_with_the_key(
        #[case] dto: dtos::PublicKeyExtended,
    ) {
        // When
        let result: Result<PublicKeyExtended, Error> = dto.try_into_contract_type();

        // Then
        assert_matches!(
            result,
            Err(Error::ConversionError(
                ConversionError::DataConversion { .. }
            ))
        );
    }

    /// A threshold below the relative (>= 60%) requirement must be rejected at the
    /// DTO boundary rather than deferred to a later validation step.
    #[test]
    fn try_into_contract_type__should_reject_threshold_below_relative_requirement() {
        // Given a DTO with 5 participants and a threshold of 2 (below the 60% bound of 3).
        let dto = dtos::GovernanceThresholdParameters {
            participants: (&gen_participants(5)).into_dto_type(),
            threshold: GovernanceThreshold::new(2),
        };

        // When converting the DTO into the contract type.
        let result: Result<GovernanceThresholdParameters, Error> = dto.try_into_contract_type();

        // Then conversion fails with the relative-threshold error.
        assert_matches!(
            result,
            Err(Error::InvalidThreshold(
                InvalidThreshold::MinRelRequirementFailed {
                    required: 3,
                    found: 2
                }
            ))
        );
    }
}
