// These are temporary conversions to avoid breaking the contract API.
// Once we complete the migration from near_sdk::PublicKey they should not be
// needed anymore
use contract_interface::types::{self as dtos};
use mpc_contract::primitives::{
    domain::SignatureScheme,
    participants::{ParticipantInfo, Participants},
};
use threshold_signatures::confidential_key_derivation::{self as ckd};

pub trait IntoInterfaceType<InterfaceType> {
    fn into_interface_type(self) -> InterfaceType;
}

pub(crate) trait IntoContractType<ContractType> {
    fn into_contract_type(self) -> ContractType;
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

impl IntoContractType<near_sdk::PublicKey> for &dtos::PublicKeyExtended {
    fn into_contract_type(self) -> near_sdk::PublicKey {
        match self {
            dtos::PublicKeyExtended::Secp256k1 { near_public_key } => {
                near_public_key.parse().unwrap()
            }
            dtos::PublicKeyExtended::Ed25519 {
                near_public_key_compressed,
                ..
            } => near_public_key_compressed.parse().unwrap(),
            dtos::PublicKeyExtended::Bls12381 { .. } => {
                unreachable!("BLS12-381 cannot convert to near_sdk::PublicKey")
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

impl IntoContractType<Participants> for &dtos::ParticipantsJson {
    fn into_contract_type(self) -> Participants {
        let mut participants = Participants::new();
        for (account_id, participant_id, info) in &self.participants {
            participants
                .insert_with_id(
                    account_id.0.parse().unwrap(),
                    ParticipantInfo {
                        url: info.url.clone(),
                        sign_pk: info.sign_pk.parse().unwrap(),
                    },
                    mpc_contract::primitives::participants::ParticipantId((*participant_id).into()),
                )
                .unwrap();
        }
        participants
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
