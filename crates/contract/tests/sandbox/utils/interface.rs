// These are temporary conversions to avoid breaking the contract API.
// Once we complete the migration from near_sdk::PublicKey they should not be
// needed anymore
use contract_interface::types::{self as dtos};
use mpc_contract::primitives::{
    domain::Curve,
    participants::{ParticipantInfo, Participants},
};

pub trait IntoInterfaceType<InterfaceType> {
    fn into_interface_type(self) -> InterfaceType;
}

pub(crate) trait IntoContractType<ContractType> {
    fn into_contract_type(self) -> ContractType;
}

impl IntoInterfaceType<dtos::SignatureScheme> for Curve {
    fn into_interface_type(self) -> dtos::SignatureScheme {
        match self {
            Curve::Secp256k1 => dtos::SignatureScheme::Secp256k1,
            Curve::Edwards25519 => dtos::SignatureScheme::Ed25519,
            Curve::Bls12381 => dtos::SignatureScheme::Bls12381,
            Curve::V2Secp256k1 => dtos::SignatureScheme::V2Secp256k1,
        }
    }
}

impl IntoContractType<Participants> for &dtos::Participants {
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
