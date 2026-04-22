use std::num::NonZeroU64;

use crate::common;

use backon::{ConstantBuilder, Retryable};
use e2e_tests::CLUSTER_WAIT_TIMEOUT;
use mpc_node_config::{ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig};
use near_mpc_bounded_collections::NonEmptyBTreeMap;

fn solana_foreign_chains_config() -> ForeignChainsConfig {
    ForeignChainsConfig {
        solana: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::new(
                "public".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: "https://rpc.public.example.com".to_string(),
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
#[expect(non_snake_case)]
async fn foreign_chain_policy__should_require_unanimity_for_auto_voting() {
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

    // when — node 2 votes with the same policy as the existing proposals.
    // Fetch an existing proposal verbatim so the vote matches regardless of
    // how the contract serializes the policy.
    let proposals = cluster
        .view_foreign_chain_policy_proposals()
        .await
        .expect("failed to view proposals");
    let existing_policy = proposals
        .proposal_by_account
        .values()
        .next()
        .expect("expected at least one proposal");
    let outcome = cluster
        .vote_foreign_chain_policy(2, existing_policy)
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
