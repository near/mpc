//! Data of the [NEP 297](https://github.com/near/NEPs/blob/master/neps/nep-0297.md)
//! events the MPC contract logs.

use serde::{Deserialize, Serialize};

use crate::types::YieldId;

/// The `standard` field of every event the MPC contract logs.
pub const MPC_CONTRACT_EVENT_STANDARD: &str = "mpc";

/// The `data` of the event that announces the [`YieldId`] the contract picked
/// for a [`VerifyForeignTransactionRequestV2`](crate::types::VerifyForeignTransactionRequestV2).
/// The contract logs it in the receipt of the request call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyForeignTxV2YieldCreated {
    pub yield_id: YieldId,
}

impl VerifyForeignTxV2YieldCreated {
    /// The `event` field of this event.
    pub const EVENT: &str = "verify_foreign_tx_v2_yield_created";
    /// The `version` field of this event.
    pub const VERSION: &str = "1.0.0";
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn verify_foreign_tx_v2_yield_created__should_encode_the_yield_id_as_hex() {
        // Given
        let event = VerifyForeignTxV2YieldCreated {
            yield_id: YieldId([0xab; 32]),
        };

        // When
        let encoded = serde_json::to_value(&event).unwrap();

        // Then
        assert_eq!(encoded, json!({ "yield_id": "ab".repeat(32) }));
        assert_eq!(
            serde_json::from_value::<VerifyForeignTxV2YieldCreated>(encoded).unwrap(),
            event
        );
    }
}
