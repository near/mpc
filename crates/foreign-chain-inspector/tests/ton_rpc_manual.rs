//! Manual tests that run the TON inspector against a live public v3 RPC
//! provider. Ignored by default (network access + provider rate limits); run
//! with `--run-ignored all`.
//!
//! Two layers of coverage:
//!
//! * [`inspector_extracts_log_against_live_rpc_provider`] — full end-to-end
//!   check that `extract` decodes a known ext-out log into the exact, hand-
//!   verified [`TonLog`].
//! * [`boc_decoder_matches_provider_reported_hashes`] — parameterized over a
//!   spread of real transactions, it decodes *every* message body and asserts
//!   our computed cell representation hash equals the one the provider reports
//!   in `message_content.hash`. That field is an independent oracle (the
//!   provider computes it from the real cell), so a match across diverse bodies
//!   — single cells through 6-cell trees, byte-aligned and not, both BoC
//!   encodings — is strong evidence the hand-rolled decoder is correct without
//!   hand-curating expected bytes per case.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use foreign_chain_inspector::ton::boc;
use foreign_chain_inspector::ton::inspector::TonInspector;
use foreign_chain_inspector::ton::rpc_client::ReqwestTonClient;
use foreign_chain_inspector::ton::types::{
    TonAddress, TonExtractedValue, TonExtractor, TonFinality, TonLog, TonTransactionId,
    TonWorkchain,
};
use foreign_chain_inspector::{ForeignChainInspector, RpcAuthentication};
use near_mpc_contract_interface::types::{Hash256, TonCellBody};
use test_utils::ton::hash32;

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
        account: account.into(),
        tx_hash: hash32(TX_HASH_HEX).into(),
    };
    let client =
        ReqwestTonClient::new(PUBLIC_TON_V3_URL.to_string(), RpcAuthentication::KeyInUrl).unwrap();
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

/// Real mainnet basechain transactions chosen for body diversity: bodies whose
/// BoCs hold 1 through 6 cells, plus the ext-out log transaction above (which
/// has a reference). `(account_hex, tx_hash_hex)`.
const ORACLE_CASES: &[(&str, &str)] = &[
    // 1-cell body.
    (
        "9266885799489346fb33b1c66d553cd4672769f2146a4a83d4d4cd49ebe334f5",
        "925924384f0f5ccda559de9bd856d7fb8978b40a7600f27fd2734f9de74226c7",
    ),
    // 2-cell body.
    (
        "e6f3d8824f46b1efbab9afc684793428c55fed69b46a15a49be69a29bc49e530",
        "cda9bd26668261e7dd478556c0623db7c46cbadbb75784d13ea25c22a956bc39",
    ),
    // 3-cell body.
    (
        "4464d42d7baf29b2d57b3c6e55ae2b0b2c0d34c54b7a081cb18aef75a6e393a5",
        "3d72251f869d63baef3b801d00d692d4087647a3620e0036567204a6a5bd4262",
    ),
    // 4-cell body.
    (
        "299388021444ef820557d6f133192d63ddc3e7bedb59f95c2c0cf584d35b9a8b",
        "8ac51c3cdd877e0c39ee521d995d5665b9bd3a0ff7f059ca2c51bea77e9359c3",
    ),
    // 5-cell body.
    (
        "92e1411ae546892f33b2c8a89ea90390d8ff4cfbb917a643b91e73f706fdb9d1",
        "d2252788bde029a91c23cf2c6611c8b087439ade12036210a77e8e117939db3e",
    ),
    // 6-cell body.
    (
        "18aa8e2eed51747dae033c079b93883d941cad8f65459f2ee9cd7474b6b8ed5d",
        "5dc411885b889d52a6e28cf190155feefadc41d5d3f6e3962b09ce9f73c94ff2",
    ),
    // The ext-out log transaction (byte-aligned body with a reference).
    (TX_ACCOUNT_HEX, TX_HASH_HEX),
];

/// For every message body across all [`ORACLE_CASES`], assert our decoder
/// computes the same cell representation hash the provider reports — an
/// independent oracle.
///
/// The cases are checked sequentially (with a pause between requests) rather
/// than as parallel `rstest` cases: the public endpoint is rate-limited, and
/// hammering it concurrently just yields `429`s.
#[ignore = "manual test: cross-check the BoC decoder against a live TON v3 RPC provider"]
#[tokio::test]
async fn boc_decoder_matches_provider_reported_hashes() {
    let mut total_messages = 0;
    for (account_hex, tx_hash_hex) in ORACLE_CASES {
        total_messages += assert_body_hashes_match(account_hex, tx_hash_hex).await;
    }
    assert!(
        total_messages >= ORACLE_CASES.len(),
        "expected at least one message body per case",
    );
}

/// Fetch one transaction and assert every message body's decoded hash matches
/// the provider's reported `message_content.hash`. Returns the number of bodies
/// checked.
async fn assert_body_hashes_match(account_hex: &str, tx_hash_hex: &str) -> usize {
    let transaction = fetch_transaction(account_hex, tx_hash_hex).await;
    let messages = transaction["out_msgs"]
        .as_array()
        .unwrap_or_else(|| panic!("transaction {tx_hash_hex} should have an out_msgs array"));

    let mut checked = 0;
    for message in messages {
        let content = &message["message_content"];
        if content.is_null() {
            continue;
        }
        let body = content["body"].as_str().expect("body should be a string");
        let provider_hash = STANDARD
            .decode(content["hash"].as_str().expect("hash should be a string"))
            .expect("provider hash should be base64");

        let decoded = boc::parse_single_root_boc(body).expect("body BoC should decode");

        assert_eq!(
            decoded.hash.as_slice(),
            provider_hash.as_slice(),
            "decoded cell hash disagrees with provider's message_content.hash for {tx_hash_hex}",
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "expected at least one message with content for {tx_hash_hex}",
    );
    checked
}

/// GET a single transaction, retrying a few times to ride out the public
/// endpoint's rate limiting, and return its JSON object.
async fn fetch_transaction(account_hex: &str, tx_hash_hex: &str) -> serde_json::Value {
    let url = format!(
        "{PUBLIC_TON_V3_URL}transactions?account=0:{account_hex}&hash={tx_hash_hex}\
         &include_msgs=true&limit=1"
    );

    for attempt in 0..5 {
        // Space out requests so the shared rate limit doesn't reject us.
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;

        let response = reqwest::get(&url).await.expect("request should be sent");
        if response.status().is_success()
            && let Ok(json) = response.json::<serde_json::Value>().await
            && let Some(tx) = json["transactions"].as_array().and_then(|t| t.first())
        {
            return tx.clone();
        }
        eprintln!("attempt {attempt} for {tx_hash_hex} did not return a transaction; retrying");
    }
    panic!("could not fetch transaction {tx_hash_hex} from {PUBLIC_TON_V3_URL}");
}
