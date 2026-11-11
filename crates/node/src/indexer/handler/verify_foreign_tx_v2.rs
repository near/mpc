use crate::indexer::handler::VerifyForeignTxRequestV2FromChain;
use crate::types::VerifyForeignTxId;
use near_contract_transport::BlockHeight;
use near_indexer_primitives::types::FunctionArgs;
use near_indexer_primitives::views::ReceiptView;
use near_mpc_contract_interface::events::{
    MPC_CONTRACT_EVENT_STANDARD, VerifyForeignTxV2YieldCreated,
};
use near_mpc_contract_interface::method_names::READ_RPC;
use near_mpc_contract_interface::types::{VerifyForeignTransactionRequestV2, YieldId};
use serde::Deserialize;

/// The prefix of a log line that holds a
/// [NEP 297](https://github.com/near/NEPs/blob/master/neps/nep-0297.md) event.
const EVENT_JSON_PREFIX: &str = "EVENT_JSON:";

#[derive(Deserialize)]
struct UnvalidatedReadRpcArgs {
    request: VerifyForeignTransactionRequestV2,
}

/// A NEP 297 event, with its data not yet parsed.
#[derive(Deserialize)]
struct ContractEvent {
    standard: String,
    version: String,
    event: String,
    data: serde_json::Value,
}

impl ContractEvent {
    fn is_yield_created(&self) -> bool {
        self.standard == MPC_CONTRACT_EVENT_STANDARD
            && self.event == VerifyForeignTxV2YieldCreated::EVENT
            && self.version == VerifyForeignTxV2YieldCreated::VERSION
    }
}

#[derive(Debug, thiserror::Error)]
enum AnnouncedYieldIdError {
    #[error("the receipt logs no yield created event")]
    NoEvent,
    #[error("the receipt logs {0} yield created events")]
    SeveralEvents(usize),
    #[error("the yield created event has invalid data: {0}")]
    InvalidData(serde_json::Error),
}

/// Parses a [`READ_RPC`] call. `logs` are the logs of the call's receipt, and
/// `block_height` is the height of the block that executed it.
pub(crate) fn try_get_verify_foreign_tx_v2_request(
    receipt: &ReceiptView,
    logs: &[String],
    next_receipt_id: VerifyForeignTxId,
    block_height: BlockHeight,
    args: &FunctionArgs,
) -> Option<VerifyForeignTxRequestV2FromChain> {
    let args = match serde_json::from_slice::<UnvalidatedReadRpcArgs>(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::warn!(target: "mpc", %err, "failed to parse `{READ_RPC}` arguments");
            return None;
        }
    };
    let yield_id = match find_announced_yield_id(logs) {
        Ok(yield_id) => yield_id,
        Err(err) => {
            tracing::warn!(
                target: "mpc",
                %err,
                receipt_id = %receipt.receipt_id,
                "skipping `{READ_RPC}` call without a single yield id",
            );
            return None;
        }
    };

    tracing::info!(
        target: "mpc",
        receipt_id = %receipt.receipt_id,
        next_receipt_id = %next_receipt_id,
        caller_id = receipt.predecessor_id.to_string(),
        ?yield_id,
        request = ?args.request.request,
        domain_id = ?args.request.domain_id,
        "indexed new `{READ_RPC}` function call",
    );
    Some(VerifyForeignTxRequestV2FromChain {
        verify_foreign_tx_id: next_receipt_id,
        receipt_id: receipt.receipt_id,
        yield_id,
        request_block_height: block_height,
        request: args.request,
    })
}

/// Finds the [`YieldId`] that the contract announces in the logs of a
/// [`READ_RPC`] receipt. The logs must hold exactly one yield created event.
fn find_announced_yield_id(logs: &[String]) -> Result<YieldId, AnnouncedYieldIdError> {
    let events: Vec<ContractEvent> = logs
        .iter()
        .filter_map(|line| line.strip_prefix(EVENT_JSON_PREFIX))
        .filter_map(|json| serde_json::from_str::<ContractEvent>(json).ok())
        .filter(ContractEvent::is_yield_created)
        .collect();
    let [event] = <[ContractEvent; 1]>::try_from(events).map_err(|events| {
        if events.is_empty() {
            AnnouncedYieldIdError::NoEvent
        } else {
            AnnouncedYieldIdError::SeveralEvents(events.len())
        }
    })?;
    serde_json::from_value::<VerifyForeignTxV2YieldCreated>(event.data)
        .map(|data| data.yield_id)
        .map_err(AnnouncedYieldIdError::InvalidData)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;
    use std::assert_matches;

    fn event_line(standard: &str, event: &str, version: &str, data: serde_json::Value) -> String {
        let event = json!({
            "standard": standard,
            "version": version,
            "event": event,
            "data": data,
        });
        format!("{EVENT_JSON_PREFIX}{event}")
    }

    fn yield_created_line(yield_id: YieldId) -> String {
        event_line(
            MPC_CONTRACT_EVENT_STANDARD,
            VerifyForeignTxV2YieldCreated::EVENT,
            VerifyForeignTxV2YieldCreated::VERSION,
            serde_json::to_value(VerifyForeignTxV2YieldCreated { yield_id }).unwrap(),
        )
    }

    fn yield_created_data() -> serde_json::Value {
        serde_json::to_value(VerifyForeignTxV2YieldCreated {
            yield_id: YieldId([1; 32]),
        })
        .unwrap()
    }

    #[test]
    fn find_announced_yield_id__should_return_the_id_of_the_one_yield_created_event() {
        // Given
        let logs = vec![
            "read_rpc: predecessor=caller.near".to_string(),
            format!("{EVENT_JSON_PREFIX}not json"),
            event_line(
                MPC_CONTRACT_EVENT_STANDARD,
                "other_event",
                "1.0.0",
                json!({}),
            ),
            format!(
                r#"EVENT_JSON:{{"standard":"mpc","version":"1.0.0","event":"verify_foreign_tx_v2_yield_created","data":{{"yield_id":"{}"}}}}"#,
                "07".repeat(32)
            ),
        ];

        // When
        let found = find_announced_yield_id(&logs);

        // Then
        assert_eq!(found.unwrap(), YieldId([7; 32]));
    }

    #[test]
    fn find_announced_yield_id__should_fail_without_a_yield_created_event() {
        // Given
        let logs = vec!["read_rpc: predecessor=caller.near".to_string()];

        // When
        let found = find_announced_yield_id(&logs);

        // Then
        assert_matches!(found, Err(AnnouncedYieldIdError::NoEvent));
    }

    #[test]
    fn find_announced_yield_id__should_fail_with_several_yield_created_events() {
        // Given
        let logs = vec![
            yield_created_line(YieldId([1; 32])),
            yield_created_line(YieldId([2; 32])),
        ];

        // When
        let found = find_announced_yield_id(&logs);

        // Then
        assert_matches!(found, Err(AnnouncedYieldIdError::SeveralEvents(2)));
    }

    #[rstest]
    #[case::wrong_standard(
        "nep171",
        VerifyForeignTxV2YieldCreated::EVENT,
        VerifyForeignTxV2YieldCreated::VERSION
    )]
    #[case::wrong_event(
        MPC_CONTRACT_EVENT_STANDARD,
        "yield_created",
        VerifyForeignTxV2YieldCreated::VERSION
    )]
    #[case::unsupported_version(
        MPC_CONTRACT_EVENT_STANDARD,
        VerifyForeignTxV2YieldCreated::EVENT,
        "2.0.0"
    )]
    fn find_announced_yield_id__should_ignore_events_it_does_not_support(
        #[case] standard: &str,
        #[case] event: &str,
        #[case] version: &str,
    ) {
        // Given
        let logs = vec![event_line(standard, event, version, yield_created_data())];

        // When
        let found = find_announced_yield_id(&logs);

        // Then
        assert_matches!(found, Err(AnnouncedYieldIdError::NoEvent));
    }

    #[test]
    fn find_announced_yield_id__should_ignore_an_event_without_the_prefix() {
        // Given
        let line = yield_created_line(YieldId([1; 32]));
        let logs = vec![line.strip_prefix(EVENT_JSON_PREFIX).unwrap().to_string()];

        // When
        let found = find_announced_yield_id(&logs);

        // Then
        assert_matches!(found, Err(AnnouncedYieldIdError::NoEvent));
    }

    #[test]
    fn find_announced_yield_id__should_fail_on_invalid_event_data() {
        // Given
        let logs = vec![event_line(
            MPC_CONTRACT_EVENT_STANDARD,
            VerifyForeignTxV2YieldCreated::EVENT,
            VerifyForeignTxV2YieldCreated::VERSION,
            json!({ "yield_id": "not hex" }),
        )];

        // When
        let found = find_announced_yield_id(&logs);

        // Then
        assert_matches!(found, Err(AnnouncedYieldIdError::InvalidData(_)));
    }
}
