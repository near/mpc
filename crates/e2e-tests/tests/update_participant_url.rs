use crate::common;

use backon::{ConstantBuilder, Retryable};
use e2e_tests::MpcCluster;
use near_account_id::AccountId;
use near_mpc_contract_interface::types::ProtocolContractState;
use rand::{SeedableRng, rngs::StdRng};

/// End-to-end acceptance for #3677: a `update_participant_url` call on a real cluster is accepted,
/// the new URL is reflected in state, and the network keeps signing without a resharing.
#[tokio::test]
#[expect(non_snake_case)]
async fn update_participant_url__should_keep_signing_after_url_update() {
    // Given
    let (cluster, running) =
        common::must_setup_cluster(common::UPDATE_PARTICIPANT_URL_PORT_SEED, |_| {}).await;
    let mut rng = StdRng::seed_from_u64(0);
    let user = cluster.default_user_account().clone();
    common::send_sign_request(&cluster, &running, &mut rng, &user)
        .await
        .expect("signing should work before the url update");

    // When
    const TARGET_NODE: usize = 1;
    let account_id = cluster.nodes[TARGET_NODE].account_id().clone();
    // A different but still-reachable address (same listener), so the update is genuinely applied.
    let new_url = cluster.nodes[TARGET_NODE]
        .p2p_url()
        .replace("127.0.0.1", "localhost");
    assert_ne!(cluster.nodes[TARGET_NODE].p2p_url(), new_url);

    let outcome = cluster
        .update_participant_url(TARGET_NODE, new_url.clone())
        .await
        .expect("update_participant_url transaction failed");
    assert!(
        outcome.is_success(),
        "update_participant_url failed: {:?}",
        outcome.failure_message()
    );

    // Then
    (|| async {
        let url = participant_url(&cluster, &account_id).await?;
        anyhow::ensure!(
            url.as_deref() == Some(new_url.as_str()),
            "url not yet updated: {url:?}"
        );
        Ok::<_, anyhow::Error>(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(60),
    )
    .await
    .expect("contract did not reflect the updated url");

    common::send_sign_request(&cluster, &running, &mut rng, &user)
        .await
        .expect("signing should work after the url update");
}

/// Reads the registered URL of `account_id` from the contract's Running state.
async fn participant_url(
    cluster: &MpcCluster,
    account_id: &AccountId,
) -> anyhow::Result<Option<String>> {
    let state = cluster.get_contract_state().await?;
    let ProtocolContractState::Running(running) = state else {
        anyhow::bail!("contract is not in Running state");
    };
    Ok(running
        .parameters
        .participants
        .participants
        .into_iter()
        .find(|(a, _, _)| a == account_id)
        .map(|(_, _, info)| info.url))
}
