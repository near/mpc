#![allow(non_snake_case)]

use std::time::Duration;

use foreign_chain_inspector::svm::inspector::{SolanaInspector, SvmExtractor, SvmFinality};
use foreign_chain_inspector::svm::{SvmExtractedValue, SvmTransactionSignature};
use foreign_chain_inspector::{
    ForeignChainInspector, NetworkFingerprintInspector, RpcAuthentication, build_http_client,
};
use foreign_chain_rpc_interfaces::svm::{Commitment, GetTransactionArgs, GetTransactionResponse};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::rpc_params;
use serde::Deserialize;

const PUBLIC_NODE_URL: &str = "https://api.mainnet-beta.solana.com";

/// Solana mainnet's genesis hash, the value operators put into
/// `expected_network_fingerprint`.
const EXPECTED_NETWORK_FINGERPRINT: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

/// The USDC mint: a heavily referenced, permanently live account.
/// <https://solscan.io/token/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v>
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// The SPL Token program that owns the USDC mint account.
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

fn live_client() -> HttpClient {
    build_http_client(PUBLIC_NODE_URL.to_string(), RpcAuthentication::KeyInUrl).unwrap()
}

fn parse_pubkey(base58: &str) -> [u8; 32] {
    bs58::decode(base58).into_vec().unwrap().try_into().unwrap()
}

#[derive(Debug, Deserialize)]
struct SignatureEntry {
    signature: String,
    err: Option<serde_json::Value>,
}

/// Signatures of the mint's recent finalized transactions that did not fail. The window
/// is wide because failing transactions arrive in bursts: a handful of the most recent
/// signatures can legitimately contain none that succeeded.
async fn recent_successful_signatures(client: &HttpClient) -> Vec<String> {
    let entries: Vec<SignatureEntry> = client
        .request(
            "getSignaturesForAddress",
            rpc_params![
                USDC_MINT,
                serde_json::json!({ "limit": 50, "commitment": "finalized" })
            ],
        )
        .await
        .unwrap();
    let signatures: Vec<String> = entries
        .into_iter()
        .filter(|entry| entry.err.is_none())
        .map(|entry| entry.signature)
        .collect();
    assert!(
        !signatures.is_empty(),
        "no successful transaction among the mint's 50 most recent; re-run"
    );
    signatures
}

/// Providers prune history, so instead of pinning a signature the test discovers a
/// recent finalized transaction that produced inner instructions.
#[tokio::test]
#[ignore = "manual test: extract an inner instruction against the live mainnet RPC provider"]
async fn inspector_extracts_inner_instruction_against_live_rpc_provider() {
    // given
    let client = live_client();
    let inspector = SolanaInspector::new(client.clone());
    let signatures = recent_successful_signatures(&client).await;

    for signature in &signatures {
        let tx: Option<GetTransactionResponse> = client
            .request(
                "getTransaction",
                &GetTransactionArgs {
                    signature: signature.clone(),
                    commitment: Commitment::Finalized,
                },
            )
            .await
            .unwrap();
        let Some(first_inner) = tx.and_then(|tx| tx.meta).and_then(|meta| {
            meta.inner_instructions
                .unwrap_or_default()
                .into_iter()
                .next()
        }) else {
            continue;
        };

        let tx_id = SvmTransactionSignature::from(
            <[u8; 64]>::try_from(bs58::decode(signature).into_vec().unwrap()).unwrap(),
        );

        // when
        let values = inspector
            .extract(
                tx_id,
                SvmFinality::Finalized,
                vec![SvmExtractor::InnerInstruction {
                    instruction_index: usize::from(first_inner.index),
                    inner_instruction_index: 0,
                }],
            )
            .await
            .unwrap();

        // then
        let [SvmExtractedValue::InnerInstruction(instruction)] = values.as_slice() else {
            panic!("expected exactly one inner-instruction value, got {values:?}");
        };
        println!(
            "extracted inner instruction of {signature}: program {}, {} accounts, {} data bytes",
            bs58::encode(instruction.program_id.0).into_string(),
            instruction.accounts.len(),
            instruction.data.len(),
        );
        return;
    }
    panic!("no recent finalized USDC transaction with inner instructions found; re-run");
}

#[tokio::test]
#[ignore = "manual test: extract account state against the live mainnet RPC provider"]
async fn inspector_extracts_account_state_against_live_rpc_provider() {
    // given
    let client = live_client();
    let inspector = SolanaInspector::new(client.clone());

    // The transaction gates still run, so anchor on a recent finalized signature.
    let signature = recent_successful_signatures(&client).await.swap_remove(0);
    let tx_id = SvmTransactionSignature::from(
        <[u8; 64]>::try_from(bs58::decode(&signature).into_vec().unwrap()).unwrap(),
    );

    // when
    let values = inspector
        .extract(
            tx_id,
            SvmFinality::Finalized,
            vec![SvmExtractor::AccountState {
                pubkey: parse_pubkey(USDC_MINT),
            }],
        )
        .await
        .unwrap();

    // then — the mint account is owned by the SPL Token program and carries its data.
    let [SvmExtractedValue::AccountState(account)] = values.as_slice() else {
        panic!("expected exactly one account value, got {values:?}");
    };
    assert_eq!(account.owner.0, parse_pubkey(TOKEN_PROGRAM));
    assert!(!account.data.is_empty());
}

#[tokio::test]
#[ignore = "manual test to sanity check against live Solana RPC provider"]
async fn network_fingerprint_matches_the_shipped_config_value_against_live_rpc_provider() {
    // given
    let inspector = SolanaInspector::new(live_client());

    // when
    let fingerprint =
        tokio::time::timeout(Duration::from_secs(10), inspector.network_fingerprint())
            .await
            .unwrap()
            .unwrap();

    // then
    assert_eq!(fingerprint.to_string(), EXPECTED_NETWORK_FINGERPRINT);
}
