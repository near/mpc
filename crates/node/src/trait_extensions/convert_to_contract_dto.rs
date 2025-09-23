//! This module provides convenience methods to map internal node types
//! into `data transfer object`s from the [`dtos_contract`] crate.
//!
//! These types are mapped with the [IntoDtoType] trait. We can not use [`From`]
//! and [`Into`] due to the [*orphan rule*](https://doc.rust-lang.org/reference/items/implementations.html#orphan-rules).

use attestation::{
    attestation::{Attestation, DstackAttestation, MockAttestation},
    collateral::{Collateral, QuoteCollateralV3},
    EventLog, TcbInfo,
};

pub(crate) trait IntoDtoType<DtoType> {
    fn into_dto_type(self) -> DtoType;
}

impl IntoDtoType<dtos_contract::Attestation> for Attestation {
    fn into_dto_type(self) -> dtos_contract::Attestation {
        match self {
            Attestation::Dstack(dstack_attestation) => {
                dtos_contract::Attestation::Dstack(dstack_attestation.into_dto_type())
            }
            Attestation::Mock(mock_attestation) => {
                dtos_contract::Attestation::Mock(mock_attestation.into_dto_type())
            }
        }
    }
}

impl IntoDtoType<dtos_contract::MockAttestation> for MockAttestation {
    fn into_dto_type(self) -> dtos_contract::MockAttestation {
        match self {
            MockAttestation::Valid => dtos_contract::MockAttestation::Valid,
            MockAttestation::Invalid => dtos_contract::MockAttestation::Invalid,
            MockAttestation::WithConstraints {
                mpc_docker_image_hash,
                launcher_docker_compose_hash,
                expiry_time_stamp_seconds,
            } => dtos_contract::MockAttestation::WithConstraints {
                mpc_docker_image_hash: mpc_docker_image_hash.map(Into::into),
                launcher_docker_compose_hash: launcher_docker_compose_hash.map(Into::into),
                expiry_time_stamp_seconds,
            },
        }
    }
}

impl IntoDtoType<dtos_contract::DstackAttestation> for DstackAttestation {
    fn into_dto_type(self) -> dtos_contract::DstackAttestation {
        let DstackAttestation {
            quote,
            collateral,
            tcb_info,
        } = self;

        dtos_contract::DstackAttestation {
            quote: quote.into(),
            collateral: collateral.into_dto_type(),
            tcb_info: tcb_info.into_dto_type(),
        }
    }
}

impl IntoDtoType<dtos_contract::Collateral> for Collateral {
    fn into_dto_type(self) -> dtos_contract::Collateral {
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
        } = self.into();

        dtos_contract::Collateral {
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            tcb_info_issuer_chain,
            tcb_info,
            tcb_info_signature,
            qe_identity_issuer_chain,
            qe_identity,
            qe_identity_signature,
        }
    }
}

impl IntoDtoType<dtos_contract::TcbInfo> for TcbInfo {
    fn into_dto_type(self) -> dtos_contract::TcbInfo {
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
            .map(IntoDtoType::into_dto_type)
            .collect();

        dtos_contract::TcbInfo {
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
        }
    }
}

impl IntoDtoType<dtos_contract::EventLog> for EventLog {
    fn into_dto_type(self) -> dtos_contract::EventLog {
        let EventLog {
            imr,
            event_type,
            digest,
            event,
            event_payload,
        } = self;

        dtos_contract::EventLog {
            imr,
            event_type,
            digest,
            event,
            event_payload,
        }
    }
}
