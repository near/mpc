use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use crate::common;

use anyhow::Context;
use e2e_tests::cluster::chain_entry_matching;
use e2e_tests::foreign_chain_mock::{
    MOCK_BLOCK_HASH, MockAuthExpectation, setup_bitcoin_mock, setup_bitcoin_mock_at,
};
use e2e_tests::metrics;
use httpmock::prelude::*;
use mpc_node_config::{
    AuthConfig, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::events::VerifyForeignTxV2YieldCreated;
use near_mpc_contract_interface::types::{
    BitcoinExtractedValue, BitcoinExtractor, BitcoinRpcRequest, BitcoinTxId, BlockConfirmations,
    BlockHeight, ChainEntry, DomainConfig, DomainId, DomainPurpose, ExtractedValue, ForeignChain,
    ForeignChainRpcRequest, ForeignTxVerificationNegativeVerdict, ForeignTxVerificationOutcome,
    Hash256, Protocol, PublicKey, ReconstructionThreshold, VerifyForeignTransactionRequestV2,
    VerifyForeignTransactionResponseV2, YieldId,
};
use near_mpc_sdk::foreign_chain::{
    ForeignChainSignatureVerifierV2, VerifiedForeignTxResponseV2, VerifyForeignChainError,
};

const FOREIGN_TX_DOMAIN_ID: DomainId = DomainId(0);
/// A block hash other than [`MOCK_BLOCK_HASH`].
const OTHER_BLOCK_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";

struct ReadRpcEnv {
    cluster: e2e_tests::MpcCluster,
    public_key: PublicKey,
    _bitcoin_mock: MockServer,
}

async fn must_setup_read_rpc_cluster() -> ReadRpcEnv {
    let bitcoin_mock = MockServer::start();
    setup_bitcoin_mock(&bitcoin_mock, MockAuthExpectation::None);
    let foreign_chains = bitcoin_config("mock", bitcoin_mock.url("/"));
    must_setup_read_rpc_cluster_with(
        common::READ_RPC_PORT_SEED,
        bitcoin_mock,
        [foreign_chains.clone(), foreign_chains],
    )
    .await
}

/// A cluster whose second node's provider finds the transaction in another block than the first
/// node's provider.
async fn must_setup_disagreeing_read_rpc_cluster() -> ReadRpcEnv {
    let bitcoin_mock = MockServer::start();
    setup_bitcoin_mock_at(&bitcoin_mock, "/first", MOCK_BLOCK_HASH);
    setup_bitcoin_mock_at(&bitcoin_mock, "/second", OTHER_BLOCK_HASH);
    let node_configs = [
        bitcoin_config("first", bitcoin_mock.url("/first")),
        bitcoin_config("second", bitcoin_mock.url("/second")),
    ];
    must_setup_read_rpc_cluster_with(
        common::READ_RPC_INCONCLUSIVE_PORT_SEED,
        bitcoin_mock,
        node_configs,
    )
    .await
}

fn bitcoin_config(provider: &str, rpc_url: String) -> ForeignChainsConfig {
    ForeignChainsConfig {
        bitcoin: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            expected_network_fingerprint: None,
            providers: NonEmptyBTreeMap::new(
                provider.to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url,
                    auth: AuthConfig::None,
                },
            ),
        }),
        ..Default::default()
    }
}

/// A cluster of two nodes, with the foreign chain configs `node_configs`. The whitelist holds
/// every provider they configure.
async fn must_setup_read_rpc_cluster_with(
    port_seed: u16,
    bitcoin_mock: MockServer,
    node_configs: [ForeignChainsConfig; 2],
) -> ReadRpcEnv {
    let mut whitelist: BTreeMap<ForeignChain, ChainEntry> = BTreeMap::new();
    for (chain, config) in node_configs
        .iter()
        .flat_map(ForeignChainsConfig::iter_chains)
    {
        let entry = chain_entry_matching(config, 1);
        let Some(whitelisted) = whitelist.get_mut(&chain) else {
            whitelist.insert(chain, entry);
            continue;
        };
        let providers: BTreeMap<_, _> = entry.providers.into();
        for (id, provider) in providers {
            whitelisted.providers.insert(id, provider);
        }
    }
    let available_chains: BTreeSet<_> = whitelist.keys().copied().collect();

    let (cluster, _running) = common::must_setup_cluster(port_seed, |c| {
        c.contract_wasm = common::must_load_contract_wasm_with_foreign_tx_v2();
        c.num_nodes = 2;
        c.threshold = 2;
        c.domains = vec![DomainConfig {
            id: FOREIGN_TX_DOMAIN_ID,
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(2),
            purpose: DomainPurpose::ForeignTx,
        }];
        c.foreign_chains.node_configs = node_configs.to_vec();
        c.foreign_chains.whitelist = whitelist;
    })
    .await;
    cluster
        .wait_for_available_foreign_chains(&available_chains)
        .await
        .expect("timed out waiting for Bitcoin to become available");
    let public_key = cluster
        .mpc_contract_handle
        .public_key(Some(FOREIGN_TX_DOMAIN_ID))
        .await
        .expect("failed to view the public key of the foreign tx domain")
        .value;

    ReadRpcEnv {
        cluster,
        public_key,
        _bitcoin_mock: bitcoin_mock,
    }
}

fn bitcoin_request(expected_block_hash: Hash256) -> VerifyForeignTransactionRequestV2 {
    VerifyForeignTransactionRequestV2 {
        request: ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
            tx_id: BitcoinTxId([0xbb; 32]),
            confirmations: BlockConfirmations(1),
            extractors: [BitcoinExtractor::BlockHash].into(),
        }),
        domain_id: FOREIGN_TX_DOMAIN_ID,
        expected_values: vec![ExtractedValue::BitcoinExtractedValue(
            BitcoinExtractedValue::BlockHash(expected_block_hash),
        )],
    }
}

fn mock_block_hash() -> Hash256 {
    let bytes: [u8; 32] = hex::decode(MOCK_BLOCK_HASH)
        .expect("MOCK_BLOCK_HASH is hex")
        .try_into()
        .expect("MOCK_BLOCK_HASH is 32 bytes");
    Hash256(bytes)
}

/// A response whose signature checked out, with the block that executed the `read_rpc` call
/// and the yield id its event announced.
struct AnsweredRequest {
    response: VerifiedForeignTxResponseV2,
    request_block_height: BlockHeight,
    announced_yield_id: YieldId,
}

/// The check a caller runs on a response: [`ForeignChainSignatureVerifierV2::verify_signature`]
/// accepts only a success.
type VerifyResponse = fn(
    &ForeignChainSignatureVerifierV2,
    &VerifyForeignTransactionResponseV2,
    &PublicKey,
) -> Result<VerifiedForeignTxResponseV2, VerifyForeignChainError>;

async fn read_rpc(
    env: &ReadRpcEnv,
    request: VerifyForeignTransactionRequestV2,
    verify: VerifyResponse,
) -> anyhow::Result<AnsweredRequest> {
    let user = env.cluster.default_user_account().clone();
    let outcome = env
        .cluster
        .contract_handle(&user)
        .read_rpc(request.clone())
        .await
        .context("read_rpc call failed")?;
    anyhow::ensure!(
        outcome.is_success(),
        "read_rpc failed: {:?}",
        outcome.failure_message()
    );
    let response: VerifyForeignTransactionResponseV2 = outcome
        .json()
        .context("failed to parse the read_rpc response")?;
    let response = verify(
        &ForeignChainSignatureVerifierV2::new(request),
        &response,
        &env.public_key,
    )
    .map_err(|err| anyhow::anyhow!("the response signature does not check out: {err:?}"))?;

    let (request_receipt, event) = outcome
        .receipts_outcome
        .iter()
        .find_map(|receipt| {
            receipt
                .outcome
                .logs
                .iter()
                .find_map(|line| VerifyForeignTxV2YieldCreated::from_log_line(line))
                .map(|event| (receipt, event))
        })
        .context("no receipt logged the yield created event")?;
    let request_block_height = env
        .cluster
        .blockchain
        .block_height(request_receipt.block_hash)
        .await?;
    Ok(AnsweredRequest {
        response,
        request_block_height: BlockHeight::new(request_block_height),
        announced_yield_id: event.yield_id,
    })
}

/// The contract checks every response against the block height it stored with the request,
/// while the nodes sign the height their indexer saw, so a signed answer also shows that the two
/// heights agree.
#[tokio::test]
#[expect(non_snake_case)]
async fn read_rpc__should_answer_with_a_signed_success_and_a_signed_negative_verdict() {
    // Given
    let env = must_setup_read_rpc_cluster().await;

    // When
    let success = read_rpc(
        &env,
        bitcoin_request(mock_block_hash()),
        ForeignChainSignatureVerifierV2::verify_signature,
    )
    .await
    .expect("the request with the values on chain was not answered");
    let negative = read_rpc(
        &env,
        bitcoin_request(Hash256([0x11; 32])),
        ForeignChainSignatureVerifierV2::verify_signed_outcome,
    )
    .await
    .expect("the request with other values was not answered");

    // Then
    assert_eq!(
        success.response.outcome(),
        &ForeignTxVerificationOutcome::Verified {}
    );
    assert_eq!(
        negative.response.outcome(),
        &ForeignTxVerificationOutcome::Negative {
            verdict: ForeignTxVerificationNegativeVerdict::ValuesMismatch,
        }
    );
    for answered in [&success, &negative] {
        assert_eq!(
            answered.response.request_block_height(),
            answered.request_block_height
        );
        assert_eq!(answered.response.yield_id(), answered.announced_yield_id);
    }
    assert_ne!(success.response.yield_id(), negative.response.yield_id());
}

#[tokio::test]
#[expect(non_snake_case)]
async fn read_rpc__should_answer_a_disagreement_with_a_signed_inconclusive() {
    // Given
    let env = must_setup_disagreeing_read_rpc_cluster().await;

    // When
    let answered = read_rpc(
        &env,
        bitcoin_request(mock_block_hash()),
        ForeignChainSignatureVerifierV2::verify_signed_outcome,
    )
    .await
    .expect("the request the nodes disagree on was not answered");

    // Then
    assert_eq!(
        answered.response.outcome(),
        &ForeignTxVerificationOutcome::Inconclusive {}
    );
    assert_eq!(
        answered.response.request_block_height(),
        answered.request_block_height
    );
    assert_eq!(answered.response.yield_id(), answered.announced_yield_id);
    let series = format!(
        r#"{}{{cause="verdicts_differ",chain="bitcoin"}}"#,
        metrics::VERIFY_FOREIGN_TX_INCONCLUSIVES
    );
    let inconclusives: i64 = env
        .cluster
        .get_metric_all_nodes(&series)
        .await
        .expect("failed to read the node metrics")
        .into_iter()
        .flatten()
        .sum();
    assert!(
        inconclusives >= 1,
        "no node counted the inconclusive as verdicts_differ on bitcoin"
    );
}
