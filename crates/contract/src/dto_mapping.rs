//! This module provides convenience methods to map contract interface types
//! from [`contract_interface::types`] to internal types.
//!
//! These types are mapped with the [IntoContractType] trait. We can not use [`From`]
//! and [`Into`] due to the [*orphan rule*](https://doc.rust-lang.org/reference/items/implementations.html#orphan-rules).

use attestation::{
    attestation::{Attestation, DstackAttestation, MockAttestation},
    collateral::{Collateral, QuoteCollateralV3},
    EventLog, TcbInfo,
};
use contract_interface::types as dtos;

use k256::{
    elliptic_curve::sec1::{FromEncodedPoint as _, ToEncodedPoint as _},
    EncodedPoint,
};

use curve25519_dalek::edwards::CompressedEdwardsY;

use near_sdk::env::sha256_array;
#[cfg(any(test, feature = "test-utils", feature = "dev-utils"))]
use threshold_signatures::confidential_key_derivation as ckd;

use crate::{
    crypto_shared::k256_types,
    update::{ProposedUpdates, Update},
};

use crate::errors::{ConversionError, Error};
pub(crate) trait IntoContractType<ContractType> {
    fn into_contract_type(self) -> ContractType;
}

pub(crate) trait IntoInterfaceType<InterfaceType> {
    fn into_dto_type(self) -> InterfaceType;
}

#[allow(dead_code)]
pub(crate) trait TryIntoContractType<ContractType> {
    type Error;
    fn try_into_contract_type(self) -> Result<ContractType, Self::Error>;
}

pub(crate) trait TryIntoInterfaceType<InterfaceType> {
    type Error;
    fn try_into_dto_type(self) -> Result<InterfaceType, Self::Error>;
}

impl IntoContractType<Attestation> for dtos::Attestation {
    fn into_contract_type(self) -> Attestation {
        match self {
            dtos::Attestation::Dstack(dstack_attestation) => {
                Attestation::Dstack(dstack_attestation.into_contract_type())
            }
            dtos::Attestation::Mock(mock_attestation) => {
                Attestation::Mock(mock_attestation.into_contract_type())
            }
        }
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
                expiry_time_stamp_seconds,
            } => MockAttestation::WithConstraints {
                mpc_docker_image_hash: mpc_docker_image_hash.map(Into::into),
                launcher_docker_compose_hash: launcher_docker_compose_hash.map(Into::into),
                expiry_time_stamp_seconds,
            },
        }
    }
}

impl IntoContractType<DstackAttestation> for dtos::DstackAttestation {
    fn into_contract_type(self) -> DstackAttestation {
        let dtos::DstackAttestation {
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

impl IntoContractType<TcbInfo> for dtos::TcbInfo {
    fn into_contract_type(self) -> TcbInfo {
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

impl IntoContractType<EventLog> for dtos::EventLog {
    fn into_contract_type(self) -> EventLog {
        let dtos::EventLog {
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

impl IntoInterfaceType<dtos::Attestation> for Attestation {
    fn into_dto_type(self) -> dtos::Attestation {
        match self {
            Attestation::Dstack(dstack_attestation) => {
                dtos::Attestation::Dstack(dstack_attestation.into_dto_type())
            }
            Attestation::Mock(mock_attestation) => {
                dtos::Attestation::Mock(mock_attestation.into_dto_type())
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
                expiry_time_stamp_seconds,
            } => dtos::MockAttestation::WithConstraints {
                mpc_docker_image_hash: mpc_docker_image_hash.map(Into::into),
                launcher_docker_compose_hash: launcher_docker_compose_hash.map(Into::into),
                expiry_time_stamp_seconds,
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
            digest,
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

impl IntoInterfaceType<dtos::AccountId> for &near_sdk::AccountId {
    fn into_dto_type(self) -> dtos::AccountId {
        dtos::AccountId(self.clone().into())
    }
}

impl IntoInterfaceType<dtos::UpdateHash> for &Update {
    fn into_dto_type(self) -> dtos::UpdateHash {
        match self {
            Update::Contract(code) => dtos::UpdateHash::Code(sha256_array(code)),
            Update::Config(config) => dtos::UpdateHash::Config(sha256_array(
                &serde_json::to_vec(config).expect("serde serialization must succeed"),
            )),
        }
    }
}

impl IntoInterfaceType<dtos::ProposedUpdates> for &ProposedUpdates {
    fn into_dto_type(self) -> dtos::ProposedUpdates {
        let updates = self
            .all_updates()
            .iter()
            .map(|(update_id, update, votes)| dtos::Update {
                update_id: update_id.0,
                update_hash: update.into_dto_type(),
                votes: votes
                    .iter()
                    .map(|account_id| account_id.into_dto_type())
                    .collect(),
            })
            .collect();
        dtos::ProposedUpdates(updates)
    }
}
