use crate::common;

use anyhow::Context;
use backon::{ConstantBuilder, Retryable};
use e2e_tests::MpcCluster;
use near_account_id::AccountId;
use near_mpc_contract_interface::types::{
    Curve, DomainPurpose, ProtocolContractState, RunningContractState, SignatureResponse,
};
use rand::SeedableRng;

/// A node operator can update their registered URL while the cluster is running, and signatures
/// keep flowing — the change is absorbed by the live network without tearing it down. (The
/// no-restart decision itself is covered by `coordinator::stop_running_tests`; the reconnect uses
/// the updated address per `p2p::tests::persistent_connection__should_dial_new_address_after_watch_update`.)
#[tokio::test]
#[expect(non_snake_case)]
async fn update_participant_info__should_keep_signing_after_url_update() {
    // Given a running cluster that can produce signatures.
    let (cluster, running) =
        common::must_setup_cluster(common::UPDATE_PARTICIPANT_INFO_PORT_SEED, |_| {}).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    sign_on_all_sign_domains(&cluster, &running, &mut rng).await;

    // When a participant updates its registered URL to a different but still-reachable address.
    const TARGET_NODE: usize = 1;
    let node = &cluster.nodes[TARGET_NODE];
    let account_id = node.account_id().clone();
    let new_url = node.p2p_url().replace("127.0.0.1", "localhost");
    assert_ne!(node.p2p_url(), new_url);

    let outcome = cluster
        .update_participant_info(TARGET_NODE, new_url.clone())
        .await
        .expect("update_participant_info transaction failed");
    assert!(
        outcome.is_success(),
        "update_participant_info failed: {:?}",
        outcome.failure_message()
    );

    // Then the contract reflects the new URL ...
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

    // ... and the cluster keeps producing signatures.
    sign_on_all_sign_domains(&cluster, &running, &mut rng).await;
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

/// Sends a sign request on every `Sign`-purpose domain and asserts each returns a signature.
async fn sign_on_all_sign_domains(
    cluster: &MpcCluster,
    running: &RunningContractState,
    rng: &mut impl rand::Rng,
) {
    for domain in &running.domains.domains {
        if domain.purpose != DomainPurpose::Sign {
            continue;
        }
        let payload = match Curve::from(domain.protocol) {
            Curve::Secp256k1 => common::generate_ecdsa_payload(rng),
            Curve::Edwards25519 => common::generate_eddsa_payload(rng),
            _ => continue,
        };
        let outcome = cluster
            .send_sign_request(domain.id, payload, cluster.default_user_account())
            .await
            .context("sign request transaction failed")
            .unwrap();
        assert!(
            outcome.is_success(),
            "sign request for domain {:?} failed: {:?}",
            domain.id,
            outcome.failure_message()
        );
        let _signature: SignatureResponse = outcome
            .json()
            .expect("failed to deserialize SignatureResponse");
    }
}
