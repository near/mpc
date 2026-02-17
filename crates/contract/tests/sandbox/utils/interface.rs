// These are temporary conversions to avoid breaking the contract API.
// Once we complete the migration from near_sdk::PublicKey they should not be
// needed anymore
use contract_interface::types::{self as dtos};
use mpc_contract::primitives::{
    domain::SignatureScheme,
    participants::{ParticipantId, ParticipantInfo, Participants},
};
use threshold_signatures::confidential_key_derivation::{self as ckd};

pub trait IntoInterfaceType<InterfaceType> {
    fn into_interface_type(self) -> InterfaceType;
}

pub(crate) trait IntoContractType<ContractType> {
    fn into_contract_type(self) -> ContractType;
}

pub(crate) trait TryIntoContractType<ContractType> {
    type Error;
    fn try_into_contract_type(self) -> Result<ContractType, Self::Error>;
}

impl IntoInterfaceType<dtos::Ed25519PublicKey> for &near_sdk::PublicKey {
    fn into_interface_type(self) -> dtos::Ed25519PublicKey {
        // This function should not be called with any other type
        assert!(self.curve_type() == near_sdk::CurveType::ED25519);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.as_bytes()[1..]);
        dtos::Ed25519PublicKey::from(bytes)
    }
}

impl IntoInterfaceType<dtos::Bls12381G1PublicKey> for &ckd::ElementG1 {
    fn into_interface_type(self) -> dtos::Bls12381G1PublicKey {
        dtos::Bls12381G1PublicKey::from(self.to_compressed())
    }
}

impl IntoContractType<near_sdk::PublicKey> for &dtos::Ed25519PublicKey {
    fn into_contract_type(self) -> near_sdk::PublicKey {
        near_sdk::PublicKey::from_parts(near_sdk::CurveType::ED25519, self.0.into()).unwrap()
    }
}

impl IntoContractType<ckd::ElementG1> for &dtos::Bls12381G1PublicKey {
    fn into_contract_type(self) -> ckd::ElementG1 {
        ckd::ElementG1::from_compressed(&self.0).unwrap()
    }
}

impl IntoContractType<near_sdk::PublicKey> for &dtos::PublicKey {
    fn into_contract_type(self) -> near_sdk::PublicKey {
        match self {
            dtos::PublicKey::Secp256k1(secp256k1_public_key) => near_sdk::PublicKey::from_parts(
                near_sdk::CurveType::SECP256K1,
                secp256k1_public_key.as_bytes().to_vec(),
            )
            .unwrap(),
            dtos::PublicKey::Ed25519(ed25519_public_key) => near_sdk::PublicKey::from_parts(
                near_sdk::CurveType::ED25519,
                ed25519_public_key.as_bytes().to_vec(),
            )
            .unwrap(),
            dtos::PublicKey::Bls12381(_bls12381_public_key) => {
                // This conversion is not possible
                unreachable!()
            }
        }
    }
}

impl TryIntoContractType<near_sdk::PublicKey> for &dtos::PublicKeyExtended {
    type Error = String;
    fn try_into_contract_type(self) -> Result<near_sdk::PublicKey, Self::Error> {
        match self {
            dtos::PublicKeyExtended::Secp256k1 { near_public_key } => {
                near_public_key.parse().map_err(|e| format!("{e}"))
            }
            dtos::PublicKeyExtended::Ed25519 {
                near_public_key_compressed,
                ..
            } => near_public_key_compressed
                .parse()
                .map_err(|e| format!("{e}")),
            dtos::PublicKeyExtended::Bls12381 { .. } => {
                Err("BLS12-381 cannot convert to near_sdk::PublicKey".into())
            }
        }
    }
}

impl IntoInterfaceType<dtos::SignatureScheme> for SignatureScheme {
    fn into_interface_type(self) -> dtos::SignatureScheme {
        match self {
            SignatureScheme::Secp256k1 => dtos::SignatureScheme::Secp256k1,
            SignatureScheme::Ed25519 => dtos::SignatureScheme::Ed25519,
            SignatureScheme::Bls12381 => dtos::SignatureScheme::Bls12381,
            SignatureScheme::V2Secp256k1 => dtos::SignatureScheme::V2Secp256k1,
        }
    }
}

impl IntoContractType<Participants> for &dtos::Participants {
    fn into_contract_type(self) -> Participants {
        let participants = self
            .participants
            .iter()
            .map(|(a, data)| {
                (
                    a.0.parse::<near_sdk::AccountId>().unwrap(),
                    ParticipantId(data.id.0),
                    ParticipantInfo {
                        url: data.info.url.clone(),
                        sign_pk: data.info.sign_pk.parse().unwrap(),
                    },
                )
            })
            .collect();
        Participants::init(ParticipantId(self.next_id.0), participants).unwrap()
    }
}

impl IntoContractType<mpc_contract::primitives::thresholds::ThresholdParameters>
    for &dtos::ThresholdParameters
{
    fn into_contract_type(self) -> mpc_contract::primitives::thresholds::ThresholdParameters {
        let participants: Participants = (&self.participants).into_contract_type();
        mpc_contract::primitives::thresholds::ThresholdParameters::new(
            participants,
            mpc_contract::primitives::thresholds::Threshold::new(self.threshold.0),
        )
        .unwrap()
    }
}
