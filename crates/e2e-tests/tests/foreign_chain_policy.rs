use crate::common;

use backon::{ConstantBuilder, Retryable};
use e2e_tests::CLUSTER_WAIT_TIMEOUT;
use mpc_node_config::{
    ForeignChainsConfig, SolanaApiVariant, SolanaChainConfig, SolanaProviderConfig,
};
use near_mpc_bounded_collections::NonEmptyBTreeMap;

fn solana_foreign_chains_config() -> ForeignChainsConfig {
    ForeignChainsConfig {
        solana: Some(SolanaChainConfig {
            timeout_sec: 30,
            max_retries: 3,
            providers: NonEmptyBTreeMap::new(
                "public".to_string(),
                SolanaProviderConfig {
                    rpc_url: "https://rpc.public.example.com".to_string(),
                    api_variant: SolanaApiVariant::Standard,
                    auth: Default::default(),
                },
            ),
        }),
        ..Default::default()
    }
}

/// Verify that foreign chain policy auto-voting requires unanimity.
///
/// 3-node cluster: nodes 0 and 1 are configured with Solana foreign chain,
/// node 2 has no foreign chain config.
///
/// 1. After nodes 0 and 1 auto-vote, proposals should show 2 votes but
///    the policy should NOT be applied to the contract.
/// 2. After node 2 manually votes (achieving unanimity), the policy is applied.
/// 3. Once applied, all proposal votes are cleared.
#[tokio::test]
async fn foreign_chain_policy_should_require_unanimity_for_auto_voting() {
    // given — 3-node cluster with foreign chains on nodes 0 and 1 only
    let (cluster, _running) = common::setup_cluster(common::FOREIGN_CHAIN_POLICY_PORT_SEED, |c| {
        c.node_foreign_chains_configs = vec![
            solana_foreign_chains_config(), // node 0
            solana_foreign_chains_config(), // node 1
            ForeignChainsConfig::default(), // node 2 — no foreign chains
        ];
    })
    .await;

    // when — wait for 2 partial votes to appear without policy application
    (|| async {
        let proposals = cluster
            .view_foreign_chain_policy_proposals()
            .await
            .expect("failed to view proposals");
        let policy = cluster
            .view_foreign_chain_policy()
            .await
            .expect("failed to view policy");

        anyhow::ensure!(
            proposals.proposal_by_account.len() == 2,
            "expected 2 votes, got {}",
            proposals.proposal_by_account.len()
        );
        anyhow::ensure!(
            policy.chains.is_empty(),
            "policy should not be applied before unanimous voting"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(
                (CLUSTER_WAIT_TIMEOUT.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
            ),
    )
    .await
    .expect("timed out waiting for 2 partial votes");

    // when — node 2 votes for the same policy, achieving unanimity
    let expected_policy = serde_json::json!({
        "chains": {
            "Solana": [
                { "rpc_url": "https://rpc.public.example.com" }
            ],
        }
    });
    let outcome = cluster
        .vote_foreign_chain_policy(2, expected_policy)
        .await
        .expect("failed to vote foreign chain policy from node 2");
    assert!(
        outcome.is_success(),
        "vote_foreign_chain_policy failed: {:?}",
        outcome.failure_message()
    );

    // then — wait for policy to be applied and votes to be cleared
    (|| async {
        let proposals = cluster
            .view_foreign_chain_policy_proposals()
            .await
            .expect("failed to view proposals");
        let policy = cluster
            .view_foreign_chain_policy()
            .await
            .expect("failed to view policy");

        anyhow::ensure!(
            !policy.chains.is_empty(),
            "policy should be applied after unanimous voting"
        );
        anyhow::ensure!(
            proposals.proposal_by_account.is_empty(),
            "votes should be cleared after policy is applied, got {} votes",
            proposals.proposal_by_account.len()
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(
                (CLUSTER_WAIT_TIMEOUT.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
            ),
    )
    .await
    .expect("timed out waiting for policy application after unanimous voting");
}
