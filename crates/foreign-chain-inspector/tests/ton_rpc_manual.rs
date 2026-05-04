#![allow(non_snake_case)]

use foreign_chain_inspector::{
    ForeignChainInspector, RpcAuthentication,
    ton::{
        TonExtractedValue,
        inspector::{TonExtractor, TonFinality, TonInspector, TonTransactionId},
        rpc_client::build_ton_http_client,
    },
};
use http::{HeaderName, HeaderValue};

fn env(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("env var {name} is required for this manual test"))
}

fn hex_to_32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "expected 64-char hex, got {}", s.len());
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex digit"))
        .collect();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

#[tokio::test]
#[ignore = "manual RPC test — set TONCENTER_BASE_URL/ACCOUNT_HEX/TX_HASH_HEX env vars"]
async fn inspector_extracts_log_against_live_toncenter() {
    // given
    let base_url = env("TONCENTER_BASE_URL");
    let account = hex_to_32(&env("TONCENTER_ACCOUNT_HEX"));
    let tx_hash = hex_to_32(&env("TONCENTER_TX_HASH_HEX"));

    let auth = match std::env::var("TONCENTER_API_KEY") {
        Ok(key) if !key.is_empty() => RpcAuthentication::CustomHeader {
            header_name: HeaderName::from_static("x-api-key"),
            header_value: HeaderValue::from_str(&key).expect("invalid API key value"),
        },
        _ => RpcAuthentication::KeyInUrl,
    };

    let client = build_ton_http_client(base_url, auth).expect("toncenter client should build");
    let inspector = TonInspector::new(client);

    // when
    let extracted = inspector
        .extract(
            TonTransactionId {
                workchain: 0,
                account,
                tx_hash,
            },
            TonFinality::MasterchainIncluded,
            vec![TonExtractor::Log { message_index: 0 }],
        )
        .await
        .expect("extract should succeed against a finalized tx with an ext-out at message_index 0");

    // then
    assert_eq!(extracted.len(), 1, "expected exactly one extracted value");
    let TonExtractedValue::Log(log) = extracted.into_iter().next().unwrap();
    assert_eq!(
        log.from_address.0, account,
        "from_address should match the configured account"
    );
    assert!(
        !log.body_bits.is_empty() || !log.body_refs.is_empty(),
        "ext-out body should not be entirely empty for a useful tx; \
         if this tx emits an empty body, pick a different fixture tx"
    );

    // Sanity echo so the operator can eyeball the output.
    println!(
        "TON log: from_address={} body_bits_len={} body_refs={}",
        hex_string(&log.from_address.0),
        log.body_bits.len(),
        log.body_refs.len()
    );
}

fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
