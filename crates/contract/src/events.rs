//! The [NEP 297](https://github.com/near/NEPs/blob/master/neps/nep-0297.md) events
//! the contract logs. [`near_mpc_contract_interface::events`] holds their data
//! types and names for readers outside the contract.

use near_mpc_contract_interface::events::VerifyForeignTxV2YieldCreated;
use near_sdk::near;

/// The standard and the versions must match the constants in
/// [`near_mpc_contract_interface::events`].
#[near(event_json(standard = "mpc"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpcContractEvent {
    #[event_version("1.0.0")]
    VerifyForeignTxV2YieldCreated(VerifyForeignTxV2YieldCreated),
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use near_mpc_contract_interface::events::MPC_CONTRACT_EVENT_STANDARD;
    use near_mpc_contract_interface::types::YieldId;
    use serde_json::json;

    #[test]
    fn verify_foreign_tx_v2_yield_created__should_match_the_interface_names() {
        // Given
        let data = VerifyForeignTxV2YieldCreated {
            yield_id: YieldId([0xab; 32]),
        };
        let event = MpcContractEvent::VerifyForeignTxV2YieldCreated(data.clone());

        // When
        let encoded = event.to_json();

        // Then
        assert_eq!(
            encoded,
            json!({
                "standard": MPC_CONTRACT_EVENT_STANDARD,
                "version": VerifyForeignTxV2YieldCreated::VERSION,
                "event": VerifyForeignTxV2YieldCreated::EVENT,
                "data": serde_json::to_value(&data).unwrap(),
            })
        );
    }
}
