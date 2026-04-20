// These are temporary conversions to avoid breaking the contract API.
// Once we complete the migration from near_sdk::PublicKey they should not be
// needed anymore
use mpc_contract::primitives::participants::{ParticipantInfo, Participants};
use near_mpc_contract_interface::types::{self as dtos};

pub(crate) trait IntoContractType<ContractType> {
    fn into_contract_type(self) -> ContractType;
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
                        sign_pk: info.sign_pk.clone().into(),
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
