use foreign_chain_inspector::{
    ForeignChainInspector,
    aptos::{
        AptosExtractedValue, AptosTransactionHash,
        inspector::{AptosExtractor, AptosFinality, AptosInspector},
    },
};
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use near_mpc_contract_interface::types::AptosAddress;
use std::time::Duration;

const PUBLIC_NODE_URL: &str = "https://fullnode.mainnet.aptoslabs.com/v1";

/// A committed Aptos mainnet transaction (ledger version 5667962944) whose first event is
/// `0x1::block::NewBlockEvent` emitted by the framework account `0x1`.
/// https://explorer.aptoslabs.com/txn/0xadc6b85a0931fc7f0d7e3839b52d63105e22cec1cb1cdee48aa2065773098c3c?network=mainnet
const COMMITTED_TX_HASH: &str = "adc6b85a0931fc7f0d7e3839b52d63105e22cec1cb1cdee48aa2065773098c3c";
const EXPECTED_EVENT_TYPE_TAG: &str = "0x1::block::NewBlockEvent";
const EXPECTED_EVENT_SEQUENCE_NUMBER: u64 = 822_198_006;

#[ignore = "manual test: extract an event against the live mainnet RPC provider"]
#[tokio::test]
async fn inspector_extracts_event_against_live_rpc_provider() {
    // given
    let client =
        ReqwestAptosClient::new(PUBLIC_NODE_URL.to_string(), None, Duration::from_secs(10));
    let inspector = AptosInspector::new(client);
    let tx_id = parse_tx_hash(COMMITTED_TX_HASH);

    // when
    let extracted_values = inspector
        .extract(
            tx_id,
            AptosFinality::Committed,
            vec![AptosExtractor::Event { event_index: 0 }],
        )
        .await
        .expect("extract should succeed");

    // then
    assert_eq!(extracted_values.len(), 1);
    let AptosExtractedValue::Event(event) = &extracted_values[0];
    assert_eq!(event.type_tag, EXPECTED_EVENT_TYPE_TAG);
    assert_eq!(event.sequence_number, EXPECTED_EVENT_SEQUENCE_NUMBER);
    let mut framework_address = [0u8; 32];
    framework_address[31] = 1;
    assert_eq!(event.account_address, AptosAddress(framework_address));
    // The normalized data payload of a NewBlockEvent carries the block metadata fields.
    assert!(
        event.data.contains("\"epoch\""),
        "normalized event data should contain the epoch field: {}",
        event.data
    );
}

fn parse_tx_hash(hash: &str) -> AptosTransactionHash {
    let bytes = hex::decode(hash).expect("transaction hash should be valid hex");
    let array: [u8; 32] = bytes
        .try_into()
        .expect("transaction hash should be 32 bytes");
    AptosTransactionHash::from(array)
}
