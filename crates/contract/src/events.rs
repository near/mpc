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
    use near_mpc_contract_interface::types::YieldId;
    use near_sdk::AsNep297Event;

    #[test]
    fn verify_foreign_tx_v2_yield_created__should_parse_with_the_interface_parser() {
        // Given
        let data = VerifyForeignTxV2YieldCreated {
            yield_id: YieldId([0xab; 32]),
        };
        let event = MpcContractEvent::VerifyForeignTxV2YieldCreated(data.clone());

        // When
        let line = event.to_nep297_event().to_event_log();

        // Then
        assert_eq!(
            VerifyForeignTxV2YieldCreated::from_log_line(&line),
            Some(data)
        );
    }
}
