// These are temporary conversions to avoid breaking the contract API.
// Once we complete the migration from near_sdk::PublicKey they should not be
// needed anymore
use mpc_contract::primitives::participants::Participants;
use near_mpc_contract_interface::types::{self as dtos};

pub(crate) trait IntoContractType<ContractType> {
    fn into_contract_type(self) -> ContractType;
}

impl IntoContractType<Participants> for &dtos::Participants {
    fn into_contract_type(self) -> Participants {
        let participants = self
            .participants
            .iter()
            .map(|(account_id, participant_id, info)| {
                (account_id.clone(), *participant_id, info.clone().into())
            })
            .collect();
        Participants::init(self.next_id, participants)
    }
}

impl IntoContractType<mpc_contract::primitives::thresholds::GovernanceThresholdParameters>
    for &dtos::GovernanceThresholdParameters
{
    fn into_contract_type(
        self,
    ) -> mpc_contract::primitives::thresholds::GovernanceThresholdParameters {
        let participants: Participants = (&self.participants).into_contract_type();
        mpc_contract::primitives::thresholds::GovernanceThresholdParameters::new(
            participants,
            mpc_contract::primitives::thresholds::GovernanceThreshold::new(self.threshold.0),
        )
        .unwrap()
    }
}
