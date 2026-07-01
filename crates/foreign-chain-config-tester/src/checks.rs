//! Per-provider golden checks: run a fixed request and verify the extracted value.

use std::time::Duration;

use anyhow::{Context, bail, ensure};
use foreign_chain_inspector::{
    BlockConfirmations, EthereumFinality, ForeignChainInspector,
    aptos::{
        AptosExtractedValue, AptosTransactionHash,
        inspector::{AptosExtractor, AptosFinality, AptosInspector},
    },
    bitcoin::{
        BitcoinExtractedValue, BitcoinTransactionHash,
        inspector::{BitcoinExtractor, BitcoinInspector},
    },
    evm::inspector::{EvmChain, EvmExtractedValue, EvmExtractor, EvmInspector},
    http_client::HttpClient,
    starknet::{
        StarknetExtractedValue, StarknetTransactionHash,
        inspector::{StarknetExtractor, StarknetFinality, StarknetInspector},
    },
};
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use http::{HeaderName, HeaderValue};

fn verify_block_hash(expected: [u8; 32], got: [u8; 32]) -> anyhow::Result<()> {
    if got != expected {
        return Err(anyhow::anyhow!(
            "block hash mismatch: expected 0x{}, got 0x{} — is this provider on the expected network?",
            hex::encode(expected),
            hex::encode(got),
        ));
    }
    Ok(())
}

pub async fn check_evm<Chain>(
    client: HttpClient,
    tx: [u8; 32],
    expected_block_hash: [u8; 32],
) -> anyhow::Result<()>
where
    Chain: EvmChain + Send + Sync,
{
    let inspector = EvmInspector::<HttpClient, Chain>::new(client);
    let values = inspector
        .extract(
            Chain::TransactionHash::from(tx),
            EthereumFinality::Finalized,
            vec![EvmExtractor::BlockHash],
        )
        .await?;
    match values.into_iter().next().context("RPC returned no value")? {
        EvmExtractedValue::BlockHash(hash) => {
            let got: [u8; 32] = hash.into();
            verify_block_hash(expected_block_hash, got)
        }
        EvmExtractedValue::Log(_) => bail!("expected a block hash, got a log"),
    }
}

pub async fn check_bitcoin(
    client: HttpClient,
    tx: [u8; 32],
    expected_block_hash: [u8; 32],
) -> anyhow::Result<()> {
    let inspector = BitcoinInspector::new(client);
    let values = inspector
        .extract(
            BitcoinTransactionHash::from(tx),
            BlockConfirmations::from(1),
            vec![BitcoinExtractor::BlockHash],
        )
        .await?;
    match values.into_iter().next().context("RPC returned no value")? {
        BitcoinExtractedValue::BlockHash(hash) => {
            let got: [u8; 32] = hash.into();
            verify_block_hash(expected_block_hash, got)
        }
    }
}

pub async fn check_starknet(
    client: HttpClient,
    tx: [u8; 32],
    expected_block_hash: [u8; 32],
) -> anyhow::Result<()> {
    let inspector = StarknetInspector::new(client);
    let values = inspector
        .extract(
            StarknetTransactionHash::from(tx),
            StarknetFinality::AcceptedOnL1,
            vec![StarknetExtractor::BlockHash],
        )
        .await?;
    match values.into_iter().next().context("RPC returned no value")? {
        StarknetExtractedValue::BlockHash(hash) => {
            let got: [u8; 32] = hash.into();
            verify_block_hash(expected_block_hash, got)
        }
        StarknetExtractedValue::Log(_) => bail!("expected a block hash, got a log"),
    }
}

pub async fn check_aptos(
    url: String,
    auth_header: Option<(HeaderName, HeaderValue)>,
    timeout: Duration,
    tx: [u8; 32],
    expected_type_tag: &str,
    expected_sequence_number: u64,
) -> anyhow::Result<()> {
    let inspector = AptosInspector::new(ReqwestAptosClient::new(url, auth_header, timeout));
    let values = inspector
        .extract(
            AptosTransactionHash::from(tx),
            AptosFinality::Committed,
            vec![AptosExtractor::Event { event_index: 0 }],
        )
        .await?;
    match values.into_iter().next().context("RPC returned no value")? {
        AptosExtractedValue::Event(event) => {
            ensure!(
                event.type_tag == expected_type_tag,
                "event type tag mismatch: expected {expected_type_tag}, got {} — is this provider on the expected network?",
                event.type_tag,
            );
            ensure!(
                event.sequence_number == expected_sequence_number,
                "event sequence number mismatch: expected {expected_sequence_number}, got {}",
                event.sequence_number,
            );
            Ok(())
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::golden;
    use httpmock::prelude::*;

    fn golden_aptos_body(tx: &str, type_tag: &str, sequence_number: u64) -> serde_json::Value {
        serde_json::json!({
            "type": "block_metadata_transaction",
            "hash": format!("0x{tx}"),
            "success": true,
            "events": [{
                "guid": { "creation_number": "0", "account_address": "0x1" },
                "sequence_number": sequence_number.to_string(),
                "type": type_tag,
                "data": { "epoch": "7510" }
            }]
        })
    }

    #[tokio::test]
    async fn check_aptos__should_pass_when_provider_returns_golden_event() {
        // Given
        let server = MockServer::start_async().await;
        let aptos = golden::golden_set(golden::Network::Mainnet).aptos.unwrap();
        let tx = aptos.tx;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(format!("/transactions/by_hash/0x{tx}"));
                then.status(200).json_body(golden_aptos_body(
                    tx,
                    aptos.event_type_tag,
                    aptos.event_sequence_number,
                ));
            })
            .await;

        // When
        let result = check_aptos(
            server.base_url(),
            None,
            Duration::from_secs(5),
            golden::hex32(tx).unwrap(),
            aptos.event_type_tag,
            aptos.event_sequence_number,
        )
        .await;

        // Then
        result.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn check_aptos__should_fail_when_event_type_tag_differs() {
        // Given
        let server = MockServer::start_async().await;
        let aptos = golden::golden_set(golden::Network::Mainnet).aptos.unwrap();
        let tx = aptos.tx;
        server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(format!("/transactions/by_hash/0x{tx}"));
                then.status(200).json_body(golden_aptos_body(
                    tx,
                    "0xdead::wrong::Event",
                    aptos.event_sequence_number,
                ));
            })
            .await;

        // When
        let result = check_aptos(
            server.base_url(),
            None,
            Duration::from_secs(5),
            golden::hex32(tx).unwrap(),
            aptos.event_type_tag,
            aptos.event_sequence_number,
        )
        .await;

        // Then
        let error = result.unwrap_err().to_string();
        assert!(error.contains("event type tag mismatch"), "{error}");
    }
}
