//! This module provides convenience methods to map internal node types
//! into contract interface types from the [`near_mpc_contract_interface::types`] module.
//!
//! Crypto type conversions (e.g. `k256`, `ed25519-dalek`, `blstrs`, `near-sdk`)
//! have been moved to `near-mpc-contract-interface` as standard `From`/`TryFrom` impls.
//! This module retains attestation conversions where the orphan rule applies.

use mpc_attestation::{
    attestation::{Attestation, DstackAttestation, MockAttestation},
    collateral::Collateral,
    tcb_info::{EventLog, TcbInfo},
};

use near_mpc_contract_interface::types as dtos;

pub(crate) trait IntoContractInterfaceType<InterfaceType> {
    fn into_contract_interface_type(self) -> InterfaceType;
}

impl IntoContractInterfaceType<near_mpc_contract_interface::types::Attestation> for Attestation {
    fn into_contract_interface_type(self) -> near_mpc_contract_interface::types::Attestation {
        match self {
            Attestation::Dstack(dstack_attestation) => {
                near_mpc_contract_interface::types::Attestation::Dstack(
                    dstack_attestation.into_contract_interface_type(),
                )
            }
            Attestation::Mock(mock_attestation) => {
                near_mpc_contract_interface::types::Attestation::Mock(
                    mock_attestation.into_contract_interface_type(),
                )
            }
        }
    }
}

impl IntoContractInterfaceType<near_mpc_contract_interface::types::MockAttestation>
    for MockAttestation
{
    fn into_contract_interface_type(self) -> near_mpc_contract_interface::types::MockAttestation {
        match self {
            MockAttestation::Valid => near_mpc_contract_interface::types::MockAttestation::Valid,
            MockAttestation::Invalid => {
                near_mpc_contract_interface::types::MockAttestation::Invalid
            }
            MockAttestation::WithConstraints {
                mpc_docker_image_hash,
                launcher_docker_compose_hash,
                expiry_timestamp_seconds,
                expected_measurements,
            } => near_mpc_contract_interface::types::MockAttestation::WithConstraints {
                mpc_docker_image_hash,
                launcher_docker_compose_hash,
                expiry_timestamp_seconds,
                expected_measurements: expected_measurements.map(|m| {
                    near_mpc_contract_interface::types::VerifiedMeasurements {
                        mrtd: m.rtmrs.mrtd.into(),
                        rtmr0: m.rtmrs.rtmr0.into(),
                        rtmr1: m.rtmrs.rtmr1.into(),
                        rtmr2: m.rtmrs.rtmr2.into(),
                        key_provider_event_digest: m.key_provider_event_digest.into(),
                    }
                }),
            },
        }
    }
}

impl IntoContractInterfaceType<near_mpc_contract_interface::types::DstackAttestation>
    for DstackAttestation
{
    fn into_contract_interface_type(self) -> near_mpc_contract_interface::types::DstackAttestation {
        let DstackAttestation {
            quote,
            collateral,
            tcb_info,
        } = self;

        near_mpc_contract_interface::types::DstackAttestation {
            quote: Vec::from(quote).into(),
            collateral: collateral.into_contract_interface_type(),
            tcb_info: tcb_info.into_contract_interface_type(),
        }
    }
}

impl IntoContractInterfaceType<near_mpc_contract_interface::types::Collateral> for Collateral {
    fn into_contract_interface_type(self) -> near_mpc_contract_interface::types::Collateral {
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

        near_mpc_contract_interface::types::Collateral {
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

impl IntoContractInterfaceType<near_mpc_contract_interface::types::TcbInfo> for TcbInfo {
    fn into_contract_interface_type(self) -> near_mpc_contract_interface::types::TcbInfo {
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
            .map(IntoContractInterfaceType::into_contract_interface_type)
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

impl IntoContractInterfaceType<near_mpc_contract_interface::types::EventLog> for EventLog {
    fn into_contract_interface_type(self) -> near_mpc_contract_interface::types::EventLog {
        let EventLog {
            imr,
            event_type,
            digest,
            event,
            event_payload,
        } = self;

        near_mpc_contract_interface::types::EventLog {
            imr,
            event_type,
            digest: digest.into(),
            event,
            event_payload,
        }
    }
}
