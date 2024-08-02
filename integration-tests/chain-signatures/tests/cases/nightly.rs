use integration_tests_chain_signatures::MultichainConfig;
use mpc_contract::config::ProtocolConfig;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use test_log::test;

use crate::actions::{self, wait_for};
use crate::with_multichain_nodes;

#[test(tokio::test)]
#[ignore = "This is triggered by the nightly Github Actions pipeline"]
async fn test_nightly_signature_production() -> anyhow::Result<()> {
    const SIGNATURE_AMOUNT: usize = 1000;
    const NODES: usize = 8;
    const THRESHOLD: usize = 4;

    let config = MultichainConfig {
        nodes: NODES,
        threshold: THRESHOLD,
        protocol: ProtocolConfig::default(),
    };

    with_multichain_nodes(config, |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), NODES);
            let mut rng = StdRng::from_seed([0; 32]);

            for i in 0..SIGNATURE_AMOUNT {
                let random_secs: u32 = rng.gen_range(1, 40);
                tokio::time::sleep(std::time::Duration::from_secs(random_secs as u64)).await;
                let (_account, signer) = actions::new_account(&ctx).await.unwrap();

                let sig_amount = rng.gen_range(1, 3);
                tracing::info!(i, sig_amount, "Producing signature");

                let (_payload_hashes, tx_hashes): (Vec<_>, Vec<_>) =
                    actions::request_sign_multiple(&ctx, &signer, sig_amount)
                        .await?
                        .into_iter()
                        .unzip();

                match wait_for::signatures_responded(&ctx, &tx_hashes).await {
                    Ok(_signatures) => tracing::info!(?tx_hashes, "got signatures"),
                    Err(err) => tracing::error!("unable to produce signatures in time: {err:?}"),
                }
            }

            Ok(())
        })
    })
    .await
}
