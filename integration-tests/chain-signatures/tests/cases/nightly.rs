use integration_tests_chain_signatures::MultichainConfig;
use mpc_contract::config::{ProtocolConfig, TripleConfig};
use test_log::test;

use crate::actions::{self, wait_for};
use crate::with_multichain_nodes;

#[test(tokio::test)]
#[ignore = "This is triggered by the nightly Github Actions pipeline"]
async fn test_nightly_signature_production() -> anyhow::Result<()> {
    const SIGNATURE_AMOUNT: usize = 1000;
    const NODES: usize = 8;
    const THRESHOLD: usize = 4;
    const MIN_TRIPLES: u32 = 10;
    const MAX_TRIPLES: u32 = 2 * NODES as u32 * MIN_TRIPLES;

    let config = MultichainConfig {
        nodes: NODES,
        threshold: THRESHOLD,
        protocol: ProtocolConfig {
            triple: TripleConfig {
                min_triples: MIN_TRIPLES,
                max_triples: MAX_TRIPLES,
                ..Default::default()
            },
            ..Default::default()
        },
    };

    with_multichain_nodes(config, |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), NODES);

            for i in 0..SIGNATURE_AMOUNT {
                if let Err(err) = wait_for::has_at_least_mine_triples(&ctx, 4).await {
                    tracing::error!(?err, "Failed to wait for triples");
                    continue;
                }

                if let Err(err) = wait_for::has_at_least_mine_presignatures(&ctx, 2).await {
                    tracing::error!(?err, "Failed to wait for presignatures");
                    continue;
                }

                tracing::info!(at_signature = i, "Producing signature...");
                if let Err(err) = actions::single_signature_production(&ctx, &state_0).await {
                    tracing::error!(?err, "Failed to produce signature");
                }
            }

            Ok(())
        })
    })
    .await
}
