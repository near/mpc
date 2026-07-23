//! Per-provider checks. Golden-transaction chains run a fixed request and verify the
//! extracted value; identity-based chains (Sui, Starknet) verify the chain identity and
//! inspect a dynamically discovered recent transaction instead.

use std::time::Duration;

use anyhow::{Context, bail};
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
        StarknetTransactionHash,
        inspector::{StarknetExtractor, StarknetFinality, StarknetInspector},
    },
    sui::{
        SuiTransactionDigest,
        inspector::{SuiExtractor, SuiFinality, SuiInspector},
    },
};
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use foreign_chain_rpc_interfaces::starknet::{BlockId, BlockTag};
use foreign_chain_rpc_interfaces::sui::SuiRpcClient;
use http::{HeaderName, HeaderValue};
use jsonrpsee::core::client::ClientT;

use crate::golden;

/// Typed "wrong network / wrong value" failures, so tests can assert on the kind instead of
/// matching error-message substrings. Wrapped into `anyhow::Error` on the way out, so the
/// operator-facing report (`{e:#}`) still renders the `Display` text below.
#[derive(Debug)]
pub enum Mismatch {
    ChainId { expected: String, got: String },
    BlockHash { expected: [u8; 32], got: [u8; 32] },
    EventTypeTag { expected: String, got: String },
    EventSequenceNumber { expected: u64, got: u64 },
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChainId { expected, got } => write!(
                f,
                "chain id mismatch: expected {expected}, got {got} — is this provider on the expected network?"
            ),
            Self::BlockHash { expected, got } => write!(
                f,
                "block hash mismatch: expected 0x{}, got 0x{} — is this provider on the expected network?",
                hex::encode(expected),
                hex::encode(got),
            ),
            Self::EventTypeTag { expected, got } => write!(
                f,
                "event type tag mismatch: expected {expected}, got {got} — is this provider on the expected network?"
            ),
            Self::EventSequenceNumber { expected, got } => write!(
                f,
                "event sequence number mismatch: expected {expected}, got {got}"
            ),
        }
    }
}

impl std::error::Error for Mismatch {}

/// Accepts any inspection outcome that proves the provider served the probe transaction's
/// data: a clean extract, a reverted transaction (`TransactionFailed`), or one without the
/// probed log/event (`LogIndexOutOfBounds`).
fn accept_probe_outcome<T>(
    outcome: Result<T, ForeignChainInspectionError>,
    context: &'static str,
) -> anyhow::Result<()> {
    match outcome {
        Ok(_)
        | Err(ForeignChainInspectionError::TransactionFailed)
        | Err(ForeignChainInspectionError::LogIndexOutOfBounds) => Ok(()),
        Err(e) => Err(e).context(context),
    }
}

fn verify_block_hash(expected: [u8; 32], got: [u8; 32]) -> anyhow::Result<()> {
    if got != expected {
        return Err(Mismatch::BlockHash { expected, got }.into());
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

/// How far behind the reported head an identity probe takes its transaction, so slightly
/// lagging backends behind the same provider URL still agree the probe block is final.
const HEAD_PROBE_OFFSET: u64 = 10;

/// How many earlier blocks an identity probe scans when the probe block carries no
/// transactions (quiet networks produce blocks on a timer, so empty blocks are normal).
const EMPTY_BLOCK_WALKBACK_LIMIT: u64 = 10;

/// Like [`check_sui`], Starknet is probed by chain identity plus a dynamically discovered
/// transaction rather than a pinned golden. `starknet_chainId` identifies the network (a
/// genesis-derived constant that is never pruned); the real inspector then runs over a
/// transaction from a block [`HEAD_PROBE_OFFSET`] below the latest L1-accepted head —
/// walking back up to [`EMPTY_BLOCK_WALKBACK_LIMIT`] blocks past empty ones — proving the
/// provider serves canonical, finalized receipts without depending on months-old archived
/// history.
///
/// Requires a provider speaking JSON-RPC v0.9+ (the `l1_accepted` block tag).
pub async fn check_starknet<C>(client: C, expected_chain_id: &str) -> anyhow::Result<()>
where
    C: ClientT + Send + Sync,
{
    let inspector = StarknetInspector::new(client);

    let got = inspector
        .chain_id()
        .await
        .context("failed to fetch chain id")?;
    let expected = golden::felt32(expected_chain_id).context("invalid expected chain id")?;
    if golden::felt32(&got).ok() != Some(expected) {
        return Err(Mismatch::ChainId {
            expected: expected_chain_id.to_string(),
            got,
        }
        .into());
    }

    let head = inspector
        .block_with_tx_hashes(BlockId::Tag(BlockTag::L1Accepted))
        .await
        .context("failed to fetch the latest L1-accepted block")?;
    let probe_number = head
        .block_number
        .checked_sub(HEAD_PROBE_OFFSET)
        .with_context(|| {
            format!(
                "L1-accepted height {} is below the probe offset {HEAD_PROBE_OFFSET}",
                head.block_number
            )
        })?;
    let mut block = inspector
        .block_with_tx_hashes(BlockId::Number {
            block_number: probe_number,
        })
        .await
        .context("failed to fetch the probe block")?;
    let mut walked_back = 0;
    let tx = loop {
        if let Some(tx) = block.transactions.first() {
            break StarknetTransactionHash::from(*tx.as_fixed_bytes());
        }
        walked_back += 1;
        if walked_back > EMPTY_BLOCK_WALKBACK_LIMIT {
            bail!(
                "no transactions in the probe block or the {EMPTY_BLOCK_WALKBACK_LIMIT} \
                 blocks before it"
            );
        }
        let block_number = block
            .block_number
            .checked_sub(1)
            .context("walked back past the genesis block without finding a transaction")?;
        block = inspector
            .block_with_tx_hashes(BlockId::Number { block_number })
            .await
            .context("failed to fetch an earlier L1-accepted block")?;
    };

    let outcome = inspector
        .extract(
            tx,
            StarknetFinality::AcceptedOnL1,
            vec![StarknetExtractor::Log { log_index: 0 }],
        )
        .await;
    accept_probe_outcome(
        outcome,
        "failed to inspect a transaction from the latest L1-accepted block",
    )
}

/// How far behind the reported tip the Sui probe transaction is taken from.
const CHECKPOINT_PROBE_OFFSET: u64 = 10;

/// Sui providers prune the gRPC read path after a few weeks, so unlike the other chains
/// there is no long-lived reference transaction to pin extracted values against. Instead
/// this verifies the provider's chain identity (the genesis digest never changes) and runs
/// the real inspector over a transaction [`CHECKPOINT_PROBE_OFFSET`] checkpoints behind the tip.
pub async fn check_sui(client: impl SuiRpcClient, expected_chain_id: &str) -> anyhow::Result<()> {
    let info = client
        .get_service_info()
        .await
        .context("failed to fetch service info")?;
    let chain_id = info
        .chain_id
        .as_deref()
        .context("provider returned no chain id")?;
    if chain_id != expected_chain_id {
        return Err(Mismatch::ChainId {
            expected: expected_chain_id.to_string(),
            got: chain_id.to_string(),
        }
        .into());
    }
    let height = info
        .checkpoint_height
        .context("provider returned no checkpoint height")?;
    let probe_height = height
        .checked_sub(CHECKPOINT_PROBE_OFFSET)
        .with_context(|| {
            format!(
                "checkpoint height {height} is below the probe offset {CHECKPOINT_PROBE_OFFSET}"
            )
        })?;

    let checkpoint = client
        .get_checkpoint(probe_height)
        .await
        .context("failed to fetch the probe checkpoint")?
        .checkpoint
        .context("provider returned no checkpoint")?;
    let digest = checkpoint
        .transactions
        .first()
        .and_then(|tx| tx.digest.as_deref())
        .context("latest checkpoint carries no transaction digest")?;
    let tx = golden::base58_32(digest)?;

    let inspector = SuiInspector::new(client);
    let outcome = inspector
        .extract(
            SuiTransactionDigest::from(tx),
            SuiFinality::Checkpointed,
            vec![SuiExtractor::Event { event_index: 0 }],
        )
        .await;
    accept_probe_outcome(
        outcome,
        "failed to inspect a transaction from the latest checkpoint",
    )
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
            if event.type_tag != expected_type_tag {
                return Err(Mismatch::EventTypeTag {
                    expected: expected_type_tag.to_string(),
                    got: event.type_tag.clone(),
                }
                .into());
            }
            if event.sequence_number != expected_sequence_number {
                return Err(Mismatch::EventSequenceNumber {
                    expected: expected_sequence_number,
                    got: event.sequence_number,
                }
                .into());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::golden;
    use crate::network::Network;
    use assert_matches::assert_matches;
    use foreign_chain_rpc_interfaces::starknet::{
        GetBlockWithTxHashesResponse, GetTransactionReceiptResponse, H256, StarknetEvent,
        StarknetExecutionStatus, StarknetFinalityStatus,
    };
    use httpmock::prelude::*;
    use jsonrpsee::core::client::{BatchResponse, error::Error as RpcError};
    use jsonrpsee::core::params::BatchRequestBuilder;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A [`ClientT`] that returns queued JSON values in call order, ignoring method and params
    /// (mirrors the inspector crate's sequential mock). Lets `check_starknet`'s fixed call
    /// sequence — chainId, l1-accepted block, receipt, canonical block — be scripted.
    struct SequentialMockClient {
        responses: Vec<serde_json::Value>,
        calls: AtomicUsize,
    }

    impl SequentialMockClient {
        fn new(responses: Vec<serde_json::Value>) -> Self {
            Self {
                responses,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl ClientT for SequentialMockClient {
        async fn request<R, Params>(&self, _method: &str, _params: Params) -> Result<R, RpcError>
        where
            R: serde::de::DeserializeOwned,
        {
            let i = self.calls.fetch_add(1, Ordering::SeqCst);
            let value = self.responses.get(i).cloned().unwrap_or_else(|| {
                panic!(
                    "mock received call #{} but only {} responses were queued",
                    i + 1,
                    self.responses.len()
                )
            });
            serde_json::from_value(value).map_err(RpcError::ParseError)
        }

        async fn notification<Params>(
            &self,
            _method: &str,
            _params: Params,
        ) -> Result<(), RpcError> {
            unimplemented!("notification() not used in tests")
        }

        async fn batch_request<'a, R>(
            &self,
            _batch: BatchRequestBuilder<'a>,
        ) -> Result<BatchResponse<'a, R>, RpcError>
        where
            R: serde::de::DeserializeOwned + std::fmt::Debug + 'a,
        {
            unimplemented!("batch_request() not used in tests")
        }
    }

    const STARKNET_MAINNET_CHAIN_ID: &str = "0x534e5f4d41494e";

    fn starknet_receipt() -> GetTransactionReceiptResponse {
        GetTransactionReceiptResponse {
            block_hash: H256::from([4; 32]),
            block_number: 842_750,
            events: vec![StarknetEvent {
                data: vec![H256::from([0xab; 32])],
                from_address: H256::from([0x11; 32]),
                keys: vec![H256::from([0xcc; 32])],
            }],
            finality_status: StarknetFinalityStatus::AcceptedOnL1,
            execution_status: StarknetExecutionStatus::Succeeded,
        }
    }

    fn json(value: impl serde::Serialize) -> serde_json::Value {
        serde_json::to_value(value).unwrap()
    }

    #[tokio::test]
    async fn check_starknet__should_pass_when_chain_id_matches_and_a_recent_tx_verifies() {
        // Given a provider on the expected network whose probe block (10 below the L1-accepted
        // head) carries a transaction the inspector can verify (finalized, canonical, succeeded).
        let receipt = starknet_receipt();
        let head = GetBlockWithTxHashesResponse {
            block_hash: H256::from([9; 32]),
            block_number: 900_000,
            transactions: vec![],
        };
        let probe = GetBlockWithTxHashesResponse {
            block_hash: H256::from([8; 32]),
            block_number: 899_990,
            transactions: vec![H256::from([3; 32])],
        };
        let canonical = GetBlockWithTxHashesResponse {
            block_hash: receipt.block_hash,
            block_number: receipt.block_number,
            transactions: vec![],
        };
        let client = SequentialMockClient::new(vec![
            json(STARKNET_MAINNET_CHAIN_ID),
            json(&head),
            json(&probe),
            json(&receipt),
            json(&canonical),
        ]);

        // When
        let result = check_starknet(client, STARKNET_MAINNET_CHAIN_ID).await;

        // Then
        result.unwrap();
    }

    #[tokio::test]
    async fn check_starknet__should_fail_when_chain_id_differs() {
        // Given a provider reporting a different network's chain id; the probe must reject it
        // before spending any further calls.
        let client = SequentialMockClient::new(vec![json("0x534e5f5345504f4c4941")]);

        // When
        let result = check_starknet(client, STARKNET_MAINNET_CHAIN_ID).await;

        // Then
        assert_matches!(
            result.unwrap_err().downcast_ref::<Mismatch>(),
            Some(Mismatch::ChainId { .. })
        );
    }

    #[tokio::test]
    async fn check_starknet__should_walk_back_when_the_probe_block_is_empty() {
        // Given the right network, an empty probe block, and a verifiable transaction in the
        // block before it.
        let receipt = starknet_receipt();
        let head = GetBlockWithTxHashesResponse {
            block_hash: H256::from([9; 32]),
            block_number: 900_000,
            transactions: vec![],
        };
        let empty_probe = GetBlockWithTxHashesResponse {
            block_hash: H256::from([8; 32]),
            block_number: 899_990,
            transactions: vec![],
        };
        let earlier = GetBlockWithTxHashesResponse {
            block_hash: H256::from([7; 32]),
            block_number: 899_989,
            transactions: vec![H256::from([3; 32])],
        };
        let canonical = GetBlockWithTxHashesResponse {
            block_hash: receipt.block_hash,
            block_number: receipt.block_number,
            transactions: vec![],
        };
        let client = SequentialMockClient::new(vec![
            json(STARKNET_MAINNET_CHAIN_ID),
            json(&head),
            json(&empty_probe),
            json(&earlier),
            json(&receipt),
            json(&canonical),
        ]);

        // When
        let result = check_starknet(client, STARKNET_MAINNET_CHAIN_ID).await;

        // Then
        result.unwrap();
    }

    #[tokio::test]
    async fn check_starknet__should_fail_when_no_recent_block_carries_transactions() {
        // Given the right network but only empty blocks within the walk-back limit.
        let head = GetBlockWithTxHashesResponse {
            block_hash: H256::from([9; 32]),
            block_number: 900_000,
            transactions: vec![],
        };
        let empty_blocks = (0..=EMPTY_BLOCK_WALKBACK_LIMIT).map(|i| {
            json(GetBlockWithTxHashesResponse {
                block_hash: H256::from([8; 32]),
                block_number: 899_990 - i,
                transactions: vec![],
            })
        });
        let responses = [json(STARKNET_MAINNET_CHAIN_ID), json(&head)]
            .into_iter()
            .chain(empty_blocks)
            .collect();
        let client = SequentialMockClient::new(responses);

        // When
        let result = check_starknet(client, STARKNET_MAINNET_CHAIN_ID).await;

        // Then
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains("no transactions"), "{error}");
    }

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
        let aptos = golden::golden_set(Network::Mainnet).aptos.unwrap();
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

    // Arbitrary; the mock just echoes it back, so the exact value carries no meaning.
    const CHECKPOINT_HEIGHT: u64 = 123_456;

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
        let sui = golden::golden_set(Network::Mainnet).sui.unwrap();
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
            chain_id: golden::golden_set(Network::Testnet)
                .sui
                .unwrap()
                .chain_id
                .to_string(),
        };
        let expected = golden::golden_set(Network::Mainnet).sui.unwrap();

        // When
        let result = check_sui(client, expected.chain_id).await;

        // Then
        assert_matches!(
            result.unwrap_err().downcast_ref::<Mismatch>(),
            Some(Mismatch::ChainId { .. })
        );
    }

    #[tokio::test]
    async fn check_aptos__should_fail_when_event_type_tag_differs() {
        // Given
        let server = MockServer::start_async().await;
        let aptos = golden::golden_set(Network::Mainnet).aptos.unwrap();
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
        assert_matches!(
            result.unwrap_err().downcast_ref::<Mismatch>(),
            Some(Mismatch::EventTypeTag { .. })
        );
    }
}
