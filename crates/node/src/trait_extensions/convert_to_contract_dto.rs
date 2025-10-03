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
use derive_more::Display;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{elliptic_curve::group::GroupEncoding, EncodedPoint};

#[derive(Debug, Display)]
pub struct ParsePublicKeyError {}
impl std::error::Error for ParsePublicKeyError {}

pub(crate) trait IntoDtoType<DtoType> {
    fn into_dto_type(self) -> DtoType;
}

pub(crate) trait IntoNodeType<NodeType> {
    fn into_node_type(self) -> NodeType;
}

impl IntoDtoType<dtos_contract::Ed25519PublicKey> for &ed25519_dalek::VerifyingKey {
    fn into_dto_type(self) -> dtos_contract::Ed25519PublicKey {
        dtos_contract::Ed25519PublicKey::from(self.to_bytes())
    }
}

impl IntoDtoType<dtos_contract::PublicKey> for &threshold_signatures::frost_ed25519::VerifyingKey {
    fn into_dto_type(self) -> dtos_contract::PublicKey {
        dtos_contract::PublicKey::Ed25519(dtos_contract::Ed25519PublicKey::from(
            self.to_element().to_bytes(),
        ))
    }
}

impl IntoDtoType<dtos_contract::PublicKey>
    for &threshold_signatures::frost_secp256k1::VerifyingKey
{
    fn into_dto_type(self) -> dtos_contract::PublicKey {
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&self.to_element().to_encoded_point(false).to_bytes()[1..]);
        dtos_contract::PublicKey::Secp256k1(dtos_contract::Secp256k1PublicKey::from(bytes))
    }
}

impl IntoNodeType<Result<threshold_signatures::frost_ed25519::VerifyingKey, ParsePublicKeyError>>
    for dtos_contract::Ed25519PublicKey
{
    fn into_node_type(
        self,
    ) -> Result<threshold_signatures::frost_ed25519::VerifyingKey, ParsePublicKeyError> {
        threshold_signatures::frost_ed25519::VerifyingKey::deserialize(self.as_bytes())
            .map_err(|_| ParsePublicKeyError {})
    }
}

impl IntoNodeType<Result<threshold_signatures::frost_secp256k1::VerifyingKey, ParsePublicKeyError>>
    for dtos_contract::Secp256k1PublicKey
{
    fn into_node_type(
        self,
    ) -> Result<threshold_signatures::frost_secp256k1::VerifyingKey, ParsePublicKeyError> {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x4;
        bytes[1..].copy_from_slice(&self.0);
        let point = EncodedPoint::from_bytes(bytes).map_err(|_| ParsePublicKeyError {})?;
        Ok(threshold_signatures::frost_secp256k1::VerifyingKey::new(
            k256::ProjectivePoint::from_encoded_point(&point)
                .into_option()
                .ok_or(ParsePublicKeyError {})?,
        ))
    }
}

impl IntoNodeType<Result<ed25519_dalek::VerifyingKey, ParsePublicKeyError>>
    for dtos_contract::Ed25519PublicKey
{
    fn into_node_type(self) -> Result<ed25519_dalek::VerifyingKey, ParsePublicKeyError> {
        ed25519_dalek::VerifyingKey::from_bytes(self.as_bytes()).map_err(|_| ParsePublicKeyError {})
    }
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

// This is only needed temporarily

// This is needed as it is only used in tests
#[allow(dead_code)]
pub(crate) trait IntoContractType<ContractType> {
    fn into_contract_type(self) -> ContractType;
}

impl IntoContractType<near_sdk::PublicKey> for &dtos_contract::PublicKey {
    // If the original data is correct, this will never panic
    fn into_contract_type(self) -> near_sdk::PublicKey {
        match self {
            dtos_contract::PublicKey::Secp256k1(secp256k1_public_key) => {
                near_sdk::PublicKey::from_parts(
                    near_sdk::CurveType::SECP256K1,
                    secp256k1_public_key.as_bytes().to_vec(),
                )
                .unwrap()
            }
            dtos_contract::PublicKey::Ed25519(ed25519_public_key) => {
                near_sdk::PublicKey::from_parts(
                    near_sdk::CurveType::ED25519,
                    ed25519_public_key.as_bytes().to_vec(),
                )
                .unwrap()
            }
        }
    }
}

impl IntoDtoType<dtos_contract::PublicKey> for &near_sdk::PublicKey {
    // If the original data is correct, this will never panic
    fn into_dto_type(self) -> dtos_contract::PublicKey {
        match self.curve_type() {
            near_sdk::CurveType::SECP256K1 => {
                let mut bytes = [0u8; 64];
                bytes.copy_from_slice(&self.as_bytes()[1..]);
                dtos_contract::PublicKey::from(dtos_contract::Secp256k1PublicKey::from(bytes))
            }
            near_sdk::CurveType::ED25519 => {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&self.as_bytes()[1..]);
                dtos_contract::PublicKey::from(dtos_contract::Ed25519PublicKey::from(bytes))
            }
        }
    }
}
