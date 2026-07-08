use foreign_chain_inspector::{
    ForeignChainInspector, RpcAuthentication, build_http_client,
    sui::{
        SuiExtractedValue, SuiTransactionDigest,
        inspector::{SuiExtractor, SuiFinality, SuiInspector},
    },
};
use near_mpc_contract_interface::types::SuiAddress;

const PUBLIC_NODE_URL: &str = "https://fullnode.mainnet.sui.io:443";

/// The first epoch-change transaction on Sui mainnet (checkpoint 9769), whose first event
/// is `0x3::validator_set::ValidatorEpochInfoEventV2` emitted by the system package `0x3`.
/// https://suiscan.xyz/mainnet/tx/8eBMXpC8Np7RNDwwiGwSmeev1cSoc7w3fPXdikhH7RZo
const CHECKPOINTED_TX_DIGEST: &str = "8eBMXpC8Np7RNDwwiGwSmeev1cSoc7w3fPXdikhH7RZo";
const EXPECTED_EVENT_MODULE: &str = "sui_system";

#[ignore = "manual test: extract an event against the live mainnet RPC provider"]
#[tokio::test]
async fn inspector_extracts_event_against_live_rpc_provider() {
    // given
    let client =
        build_http_client(PUBLIC_NODE_URL.to_string(), RpcAuthentication::KeyInUrl).unwrap();
    let inspector = SuiInspector::new(client);
    let tx_id = parse_tx_digest(CHECKPOINTED_TX_DIGEST);

    // when
    let extracted_values = inspector
        .extract(
            tx_id,
            SuiFinality::Checkpointed,
            vec![SuiExtractor::Event { event_index: 0 }],
        )
        .await
        .expect("extract should succeed");

    // then
    assert_eq!(extracted_values.len(), 1);
    let SuiExtractedValue::Event(event) = &extracted_values[0];
    assert_eq!(
        event.type_tag,
        format!(
            "0x{}3::validator_set::ValidatorEpochInfoEventV2",
            "0".repeat(63)
        )
    );
    assert_eq!(event.transaction_module, EXPECTED_EVENT_MODULE);
    let mut system_package = [0u8; 32];
    system_package[31] = 3;
    assert_eq!(event.package_id, SuiAddress(system_package));
    assert_eq!(event.sender, SuiAddress([0u8; 32]));
    assert!(
        !event.bcs.is_empty(),
        "event bcs payload should carry the epoch metrics"
    );
}

fn parse_tx_digest(digest: &str) -> SuiTransactionDigest {
    let bytes = bs58::decode(digest)
        .into_vec()
        .expect("transaction digest should be valid base58");
    let array: [u8; 32] = bytes
        .try_into()
        .expect("transaction digest should be 32 bytes");
    SuiTransactionDigest::from(array)
}
