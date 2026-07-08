//! Per-provider golden checks: run a fixed request and verify the extracted value.

use std::time::Duration;

use anyhow::{Context, bail, ensure};
use foreign_chain_inspector::ForeignChainInspectionError;
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
    sui::{
        SuiTransactionDigest,
        inspector::{SuiFinality, SuiInspector},
    },
};
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use foreign_chain_rpc_interfaces::sui::SuiRpcClient;
use http::{HeaderName, HeaderValue};

use crate::golden;

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

/// Sui providers prune the gRPC read path after a few weeks, so unlike the other chains
/// there is no long-lived reference transaction to pin extracted values against. Instead
/// this verifies the provider's chain identity (the genesis digest never changes) and runs
/// the real inspector over a transaction from the provider's latest checkpoint.
pub async fn check_sui(client: impl SuiRpcClient, expected_chain_id: &str) -> anyhow::Result<()> {
    let info = client
        .get_service_info()
        .await
        .context("failed to fetch service info")?;
    let chain_id = info
        .chain_id
        .as_deref()
        .context("provider returned no chain id")?;
    ensure!(
        chain_id == expected_chain_id,
        "chain id mismatch: expected {expected_chain_id}, got {chain_id} — is this provider on the expected network?",
    );
    let height = info
        .checkpoint_height
        .context("provider returned no checkpoint height")?;

    let checkpoint = client
        .get_checkpoint(height)
        .await
        .context("failed to fetch the latest checkpoint")?
        .checkpoint
        .context("provider returned no checkpoint")?;
    let digest = checkpoint
        .transactions
        .first()
        .and_then(|tx| tx.digest.as_deref())
        .context("latest checkpoint carries no transaction digest")?;
    let tx = golden::base58_32(digest)?;

    let inspector = SuiInspector::new(client);
    match inspector
        .extract(
            SuiTransactionDigest::from(tx),
            SuiFinality::Checkpointed,
            vec![],
        )
        .await
    {
        // A failed transaction still proves the provider serves canonical checkpointed data.
        Ok(_) | Err(ForeignChainInspectionError::TransactionFailed) => Ok(()),
        Err(e) => Err(e).context("failed to inspect a transaction from the latest checkpoint"),
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

    use foreign_chain_rpc_interfaces::sui::proto::{
        Checkpoint, ExecutedTransaction, ExecutionStatus, GetCheckpointResponse,
        GetServiceInfoResponse, GetTransactionResponse, TransactionEffects,
    };
    use foreign_chain_rpc_interfaces::sui::{Status, SuiRpcClient};

    const CHECKPOINT_HEIGHT: u64 = 296_112_296;

    struct MockSuiClient {
        chain_id: String,
    }

    impl MockSuiClient {
        fn probe_digest() -> String {
            bs58::encode([0xab; 32]).into_string()
        }
    }

    impl SuiRpcClient for MockSuiClient {
        async fn get_transaction(&self, digest: &str) -> Result<GetTransactionResponse, Status> {
            Ok(GetTransactionResponse::default().with_transaction(
                ExecutedTransaction::default()
                    .with_digest(digest)
                    .with_effects(
                        TransactionEffects::default()
                            .with_status(ExecutionStatus::default().with_success(true)),
                    )
                    .with_checkpoint(CHECKPOINT_HEIGHT),
            ))
        }

        async fn get_service_info(&self) -> Result<GetServiceInfoResponse, Status> {
            Ok(GetServiceInfoResponse::default()
                .with_chain_id(self.chain_id.clone())
                .with_checkpoint_height(CHECKPOINT_HEIGHT))
        }

        async fn get_checkpoint(
            &self,
            sequence_number: u64,
        ) -> Result<GetCheckpointResponse, Status> {
            Ok(GetCheckpointResponse::default().with_checkpoint(
                Checkpoint::default()
                    .with_sequence_number(sequence_number)
                    .with_transactions(vec![
                        ExecutedTransaction::default().with_digest(Self::probe_digest()),
                    ]),
            ))
        }
    }

    #[tokio::test]
    async fn check_sui__should_pass_when_provider_is_on_the_expected_network() {
        // Given
        let sui = golden::golden_set(golden::Network::Mainnet).sui.unwrap();
        let client = MockSuiClient {
            chain_id: sui.chain_id.to_string(),
        };

        // When
        let result = check_sui(client, sui.chain_id).await;

        // Then
        result.unwrap();
    }

    #[tokio::test]
    async fn check_sui__should_fail_when_chain_id_differs() {
        // Given — a provider on a different network.
        let client = MockSuiClient {
            chain_id: golden::golden_set(golden::Network::Testnet)
                .sui
                .unwrap()
                .chain_id
                .to_string(),
        };
        let expected = golden::golden_set(golden::Network::Mainnet).sui.unwrap();

        // When
        let result = check_sui(client, expected.chain_id).await;

        // Then
        let error = result.unwrap_err().to_string();
        assert!(error.contains("chain id mismatch"), "{error}");
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
