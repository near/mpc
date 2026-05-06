//! Verifies that current `mpc-node` binaries remain functional when paired
//! with the contract WASM currently deployed on Mainnet/Testnet, then
//! continue working after the contract is upgraded to the current build.

#![expect(non_snake_case)]

use crate::common;

use e2e_tests::{CLUSTER_WAIT_TIMEOUT, ContractInitFormat};
use near_mpc_contract_interface::types::ProtocolContractState;
use rand::SeedableRng;
use rstest::rstest;

#[derive(Debug, Clone, Copy)]
enum Network {
    Mainnet,
    Testnet,
}

fn production_contract_wasm(network: Network) -> &'static [u8] {
    match network {
        Network::Mainnet => contract_history::current_mainnet(),
        Network::Testnet => contract_history::current_testnet(),
    }
}

/// Boots the cluster with the production contract WASM (Mainnet or Testnet),
/// exercises sign + CKD against it with the current node binaries, upgrades
/// the contract in place, and asserts that both keep working post-upgrade.
#[rstest]
#[case::mainnet(
    Network::Mainnet,
    common::CONTRACT_UPGRADE_COMPATIBILITY_MAINNET_PORT_SEED
)]
#[case::testnet(
    Network::Testnet,
    common::CONTRACT_UPGRADE_COMPATIBILITY_TESTNET_PORT_SEED
)]
#[tokio::test]
async fn contract_upgrade_compatibility__current_node_runs_against_production_contract(
    #[case] network: Network,
    #[case] port_seed: u16,
) {
    // Given: a cluster running current node binaries against the contract
    // WASM currently deployed on the chosen network, with the default domain
    // set (Secp256k1 + Ed25519 + CKD).
    let production_wasm = production_contract_wasm(network).to_vec();
    let current_contract_wasm = common::must_load_contract_wasm();
    let (cluster, running) = common::must_setup_cluster(port_seed, |c| {
        c.contract_wasm = production_wasm;
        c.init_format = ContractInitFormat::Legacy3_9_1;
    })
    .await;

    // When: sign and CKD requests are sent before the contract is upgraded.
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let user = cluster.default_user_account().clone();
    common::send_sign_request(&cluster, &running, &mut rng, &user)
        .await
        .expect("sign request failed against production contract");
    common::send_ckd_request(&cluster, &running, &mut rng, &user)
        .await
        .expect("ckd request failed against production contract");

    // When: we propose and vote in an update to the current contract WASM.
    cluster
        .propose_and_vote_contract_update(&current_contract_wasm)
        .await
        .expect("contract upgrade to current WASM failed");
    cluster
        .assert_deployed_code(&current_contract_wasm)
        .await
        .expect("deployed contract code does not match current WASM");

    // Then: the contract is back in Running state under the new code, and
    // both sign and CKD requests continue to succeed end-to-end.
    let post_upgrade_state = cluster
        .wait_for_state(
            |s| matches!(s, ProtocolContractState::Running(_)),
            CLUSTER_WAIT_TIMEOUT,
        )
        .await
        .expect("contract did not reach Running state after upgrade");
    let ProtocolContractState::Running(running_post_upgrade) = post_upgrade_state else {
        panic!("expected Running state after upgrade");
    };
    common::send_sign_request(&cluster, &running_post_upgrade, &mut rng, &user)
        .await
        .expect("sign request failed after contract upgrade");
    common::send_ckd_request(&cluster, &running_post_upgrade, &mut rng, &user)
        .await
        .expect("ckd request failed after contract upgrade");
}
