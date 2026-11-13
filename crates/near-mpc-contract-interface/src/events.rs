//! Data of the [NEP 297](https://github.com/near/NEPs/blob/master/neps/nep-0297.md)
//! events the MPC contract logs.

use serde::{Deserialize, Serialize};

use crate::types::YieldId;

/// The `standard` field of every event the MPC contract logs.
pub const MPC_CONTRACT_EVENT_STANDARD: &str = "mpc";

/// The prefix of a log line that holds an event.
pub const EVENT_JSON_PREFIX: &str = "EVENT_JSON:";

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

    /// Parses one log line of the MPC contract. Returns `None` for a line
    /// that is not this event at [`Self::VERSION`].
    ///
    /// ```
    /// # use near_mpc_contract_interface::events::VerifyForeignTxV2YieldCreated;
    /// let line = format!(
    ///     r#"EVENT_JSON:{{"standard":"mpc","version":"1.0.0","event":"verify_foreign_tx_v2_yield_created","data":{{"yield_id":"{}"}}}}"#,
    ///     "ab".repeat(32)
    /// );
    /// assert!(VerifyForeignTxV2YieldCreated::from_log_line(&line).is_some());
    /// assert!(VerifyForeignTxV2YieldCreated::from_log_line("refund 1 yoctoNEAR").is_none());
    /// ```
    pub fn from_log_line(line: &str) -> Option<Self> {
        let event: Nep297Event<Self> =
            serde_json::from_str(line.strip_prefix(EVENT_JSON_PREFIX)?).ok()?;
        let is_this_event = event.standard == MPC_CONTRACT_EVENT_STANDARD
            && event.event == Self::EVENT
            && event.version == Self::VERSION;
        is_this_event.then_some(event.data)
    }
}

#[derive(Deserialize)]
struct Nep297Event<T> {
    standard: String,
    version: String,
    event: String,
    data: T,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    fn yield_id_hex() -> String {
        "ab".repeat(32)
    }

    fn log_line(standard: &str, version: &str, event: &str) -> String {
        let event = json!({
            "standard": standard,
            "version": version,
            "event": event,
            "data": { "yield_id": yield_id_hex() },
        });
        format!("{EVENT_JSON_PREFIX}{event}")
    }

    #[test]
    fn verify_foreign_tx_v2_yield_created__should_encode_the_yield_id_as_hex() {
        // Given
        let event = VerifyForeignTxV2YieldCreated {
            yield_id: YieldId([0xab; 32]),
        };

        // When
        let encoded = serde_json::to_value(&event).unwrap();

        // Then
        assert_eq!(encoded, json!({ "yield_id": yield_id_hex() }));
        assert_eq!(
            serde_json::from_value::<VerifyForeignTxV2YieldCreated>(encoded).unwrap(),
            event
        );
    }

    #[test]
    fn from_log_line__should_parse_the_event() {
        // Given
        let line = log_line(
            MPC_CONTRACT_EVENT_STANDARD,
            VerifyForeignTxV2YieldCreated::VERSION,
            VerifyForeignTxV2YieldCreated::EVENT,
        );

        // When
        let event = VerifyForeignTxV2YieldCreated::from_log_line(&line);

        // Then
        assert_eq!(
            event,
            Some(VerifyForeignTxV2YieldCreated {
                yield_id: YieldId([0xab; 32]),
            })
        );
    }

    #[rstest]
    #[case::other_standard(log_line("nep171", "1.0.0", "verify_foreign_tx_v2_yield_created"))]
    #[case::other_version(log_line("mpc", "2.0.0", "verify_foreign_tx_v2_yield_created"))]
    #[case::other_event(log_line("mpc", "1.0.0", "some_other_event"))]
    #[case::no_prefix(log_line("mpc", "1.0.0", "verify_foreign_tx_v2_yield_created").replacen(EVENT_JSON_PREFIX, "", 1))]
    #[case::bad_json("EVENT_JSON:{".to_string())]
    #[case::bad_yield_id(log_line("mpc", "1.0.0", "verify_foreign_tx_v2_yield_created").replace(&yield_id_hex(), "abcd"))]
    #[case::plain_log("read_rpc: predecessor=alice.near".to_string())]
    fn from_log_line__should_skip_other_lines(#[case] line: String) {
        // When
        let event = VerifyForeignTxV2YieldCreated::from_log_line(&line);

        // Then
        assert_eq!(event, None);
    }
}
