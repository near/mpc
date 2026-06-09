use foreign_chain_inspector::ton::inspector::TonInspector;
use foreign_chain_inspector::ton::rpc_client::build_ton_http_client;
use foreign_chain_inspector::ton::types::{
    TonAddress, TonExtractedValue, TonExtractor, TonFinality, TonLog, TonTransactionId,
    TonWorkchain,
};
use foreign_chain_inspector::{ForeignChainInspector, RpcAuthentication};
use near_mpc_contract_interface::types::{Hash256, TonCellBody};

/// A public TON HTTP API v3 instance. Any provider that implements the v3 spec
/// works here; this one needs no API key (rate-limited).
const PUBLIC_TON_V3_URL: &str = "https://toncenter.com/api/v3/";

/// A known mainnet basechain transaction (committed under masterchain block
/// 71_985_552) that emitted a single ext-out log message. Masterchain inclusion
/// is permanent, so this transaction stays finalized and queryable indefinitely.
///
/// Account `0:3e5ffca8…a5588`, transaction hash below (hex). The expected log
/// body/refs are the deterministic decoding of the message's BoC.
///
/// Explorer: <https://tonviewer.com/transaction/d2b05190a1dc2341ccc648175736c8fb225b36eb3293e46fdd7bfefea9fd8a36>
const TX_ACCOUNT_HEX: &str = "3e5ffca8ddfcf36c36c9ff46f31562aab51b9914845ad6c26cbde649d58a5588";
const TX_HASH_HEX: &str = "d2b05190a1dc2341ccc648175736c8fb225b36eb3293e46fdd7bfefea9fd8a36";

/// The ext-out message body: a byte-aligned 368-bit (46-byte) cell with one
/// reference. `EXPECTED_REF_HASH_HEX` is that reference cell's representation hash.
const EXPECTED_BODY_HEX: &str =
    "9c610de30100b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe422a1d00b30f55e1";
const EXPECTED_BODY_BIT_LENGTH: u16 = 368;
const EXPECTED_REF_HASH_HEX: &str =
    "e3c9c5b35da2f173e1a235e9206705db7881acfbd8fe0bcaceb39ee0a66f6f48";

#[ignore = "manual test: extract a log against a live TON v3 RPC provider"]
#[tokio::test]
async fn inspector_extracts_log_against_live_rpc_provider() {
    // given
    let account = hash32(TX_ACCOUNT_HEX);
    let tx_id = TonTransactionId {
        workchain: TonWorkchain::Basechain,
        account,
        tx_hash: hash32(TX_HASH_HEX),
    };
    let client =
        build_ton_http_client(PUBLIC_TON_V3_URL.to_string(), RpcAuthentication::KeyInUrl).unwrap();
    let inspector = TonInspector::new(client);

    // when
    let extracted_values = inspector
        .extract(
            tx_id,
            TonFinality::MasterchainIncluded,
            vec![TonExtractor::Log { message_index: 0 }],
        )
        .await
        .expect("extract should succeed against live provider");

    // then
    assert_eq!(
        extracted_values,
        vec![TonExtractedValue::Log(TonLog {
            from_address: TonAddress {
                workchain: TonWorkchain::Basechain,
                hash: Hash256(account),
            },
            body: TonCellBody::new(
                hex::decode(EXPECTED_BODY_HEX).unwrap().try_into().unwrap(),
                EXPECTED_BODY_BIT_LENGTH,
            )
            .unwrap(),
            body_refs: vec![Hash256(hash32(EXPECTED_REF_HASH_HEX))]
                .try_into()
                .unwrap(),
        })],
    );
}

fn hash32(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str)
        .expect("valid hex")
        .try_into()
        .expect("32 bytes")
}
