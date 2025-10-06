//! This module provides convenience methods to map `data transfer object`s
//! from the [`dtos_contract`] crate to internal types that the contract uses.
//!
//! These types are mapped with the [IntoContractType] trait. We can not use [`From`]
//! and [`Into`] due to the [*orphan rule*](https://doc.rust-lang.org/reference/items/implementations.html#orphan-rules).

use anyhow::{anyhow, Result};
use attestation::{
    attestation::{Attestation, DstackAttestation, MockAttestation},
    collateral::{Collateral, QuoteCollateralV3},
    EventLog, TcbInfo,
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use k256::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint,
};

use crate::crypto_shared::k256_types;

pub(crate) trait IntoContractType<ContractType> {
    fn into_contract_type(self) -> ContractType;
}

impl IntoContractType<Attestation> for dtos_contract::Attestation {
    fn into_contract_type(self) -> Attestation {
        match self {
            dtos_contract::Attestation::Dstack(dstack_attestation) => {
                Attestation::Dstack(dstack_attestation.into_contract_type())
            }
            dtos_contract::Attestation::Mock(mock_attestation) => {
                Attestation::Mock(mock_attestation.into_contract_type())
            }
        }
    }
}

impl IntoContractType<MockAttestation> for dtos_contract::MockAttestation {
    fn into_contract_type(self) -> MockAttestation {
        match self {
            dtos_contract::MockAttestation::Valid => MockAttestation::Valid,
            dtos_contract::MockAttestation::Invalid => MockAttestation::Invalid,
            dtos_contract::MockAttestation::WithConstraints {
                mpc_docker_image_hash,
                launcher_docker_compose_hash,
                expiry_time_stamp_seconds,
            } => MockAttestation::WithConstraints {
                mpc_docker_image_hash: mpc_docker_image_hash.map(Into::into),
                launcher_docker_compose_hash: launcher_docker_compose_hash.map(Into::into),
                expiry_time_stamp_seconds,
            },
        }
    }
}

impl IntoContractType<DstackAttestation> for dtos_contract::DstackAttestation {
    fn into_contract_type(self) -> DstackAttestation {
        let dtos_contract::DstackAttestation {
            quote,
            collateral,
            tcb_info,
        } = self;

        DstackAttestation {
            quote: quote.into(),
            collateral: collateral.into_contract_type(),
            tcb_info: tcb_info.into_contract_type(),
        }
    }
}

impl IntoContractType<Collateral> for dtos_contract::Collateral {
    fn into_contract_type(self) -> Collateral {
        let dtos_contract::Collateral {
            pck_crl_issuer_chain,
            root_ca_crl,
            pck_crl,
            tcb_info_issuer_chain,
            tcb_info,
            tcb_info_signature,
            qe_identity_issuer_chain,
            qe_identity,
            qe_identity_signature,
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
        })
    }
}

impl IntoContractType<TcbInfo> for dtos_contract::TcbInfo {
    fn into_contract_type(self) -> TcbInfo {
        let dtos_contract::TcbInfo {
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
            .map(IntoContractType::into_contract_type)
            .collect();

        TcbInfo {
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

impl IntoContractType<EventLog> for dtos_contract::EventLog {
    fn into_contract_type(self) -> EventLog {
        let dtos_contract::EventLog {
            imr,
            event_type,
            digest,
            event,
            event_payload,
        } = self;

        EventLog {
            imr,
            event_type,
            digest,
            event,
            event_payload,
        }
    }
}

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

impl IntoDtoType<dtos_contract::Secp256k1PublicKey> for &k256_types::PublicKey {
    fn into_dto_type(self) -> dtos_contract::Secp256k1PublicKey {
        let mut bytes = [0u8; 64];
        // The first byte is the curve type
        bytes.copy_from_slice(&self.to_encoded_point(false).to_bytes()[1..]);
        dtos_contract::Secp256k1PublicKey::from(bytes)
    }
}

// This is not yet used, but will be necessary once we complete the migration from near_sdk::PublicKey
impl IntoContractType<Result<k256_types::PublicKey>> for dtos_contract::Secp256k1PublicKey {
    fn into_contract_type(self) -> Result<k256_types::PublicKey> {
        let mut bytes = [0u8; 65];
        bytes[1..].copy_from_slice(&self.0);
        // The first byte is the curve representation, in this case uncompressed
        bytes[0] = 0x4;
        let point = EncodedPoint::from_bytes(bytes)?;
        k256_types::PublicKey::from_encoded_point(&point)
            .into_option()
            .ok_or(anyhow!("Error decoding point"))
    }
}

impl IntoDtoType<dtos_contract::Ed25519PublicKey> for &CompressedEdwardsY {
    fn into_dto_type(self) -> dtos_contract::Ed25519PublicKey {
        dtos_contract::Ed25519PublicKey::from(self.to_bytes())
    }
}

// These are temporary conversions to avoid breaking the contract API

impl IntoDtoType<Result<dtos_contract::Ed25519PublicKey>> for &near_sdk::PublicKey {
    fn into_dto_type(self) -> Result<dtos_contract::Ed25519PublicKey> {
        // This function should not be called with any other curve type
        match self.curve_type() {
            near_sdk::CurveType::ED25519 => {
                let mut bytes = [0u8; 32];
                // The first byte is the curve type
                bytes.copy_from_slice(&self.as_bytes()[1..]);
                Ok(dtos_contract::Ed25519PublicKey::from(bytes))
            }
            _ => Err(anyhow!("Wrong key type used")),
        }
    }
}

impl IntoContractType<near_sdk::PublicKey> for &dtos_contract::Ed25519PublicKey {
    fn into_contract_type(self) -> near_sdk::PublicKey {
        // This will never panic, as type Ed25519PublicKey enforces the correct key size
        near_sdk::PublicKey::from_parts(near_sdk::CurveType::ED25519, self.0.into()).unwrap()
    }
}
