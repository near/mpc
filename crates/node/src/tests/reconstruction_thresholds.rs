//! Integration tests asserting signing availability is gated by each domain's own
//! reconstruction threshold `t`, not the governance threshold.
//!
//! Online signers needed to sign: `t` for CaitSith/Frost/CKD, `2t - 1` for DamgardEtAl.

use crate::indexer::fake::FakeIndexerManager;
use crate::indexer::participants::ContractState;
use crate::p2p::testing::PortSeed;
use crate::tests::common::sign_domain;
use crate::tests::{
    DEFAULT_MAX_PROTOCOL_WAIT_TIME, DEFAULT_MAX_SIGNATURE_WAIT_TIME, IntegrationTestSetup,
    request_signature_and_await_response,
};
use crate::tracking::AutoAbortTask;
use near_mpc_contract_interface::types::{DomainConfig, Protocol, ReconstructionThreshold};
use near_time::Clock;
use std::collections::BTreeMap;

// Slow enough that the DamgardEtAl domains don't flake (matches the existing
// distinct-reconstruction-thresholds test).
const BLOCK_TIME: std::time::Duration = std::time::Duration::from_millis(600);

async fn assert_can_sign(indexer: &mut FakeIndexerManager, user: &str, domain: &DomainConfig) {
    assert!(
        request_signature_and_await_response(
            indexer,
            user,
            domain,
            DEFAULT_MAX_SIGNATURE_WAIT_TIME
        )
        .await
        .is_some(),
        "domain {:?} (t={}) should be able to sign with the currently-online nodes",
        domain.id,
        domain.reconstruction_threshold.inner(),
    );
}

async fn assert_cannot_sign(indexer: &mut FakeIndexerManager, user: &str, domain: &DomainConfig) {
    assert!(
        request_signature_and_await_response(
            indexer,
            user,
            domain,
            DEFAULT_MAX_SIGNATURE_WAIT_TIME
        )
        .await
        .is_none(),
        "domain {:?} (t={}) must NOT be able to sign: too few nodes are online for its threshold",
        domain.id,
        domain.reconstruction_threshold.inner(),
    );
}

/// Nodes going offline leave low-`t` domains signing while higher-`t` domains in the
/// same cluster stop.
#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn per_domain_reconstruction_threshold__should_gate_signing_availability_when_nodes_go_offline()
 {
    // Given a 5-node cluster with three domains at distinct thresholds.
    const NUM_PARTICIPANTS: usize = 5;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::RECONSTRUCTION_THRESHOLD_AVAILABILITY_TEST,
        BLOCK_TIME,
    );

    // low needs 2 online, high needs 4 online, robust (DamgardEtAl) needs 2*3-1 = 5 online.
    let low = sign_domain(0, Protocol::CaitSith, 2);
    let high = sign_domain(1, Protocol::CaitSith, 4);
    let robust = sign_domain(2, Protocol::DamgardEtAl, 3);
    let domains = vec![low.clone(), high.clone(), robust.clone()];

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(domains.clone());
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME * domains.len() as u32,
        )
        .await
        .expect("must not exceed timeout");

    // When all 5 are online: every domain signs.
    assert_can_sign(&mut setup.indexer, "user_all_low", &low).await;
    assert_can_sign(&mut setup.indexer, "user_all_high", &high).await;
    assert_can_sign(&mut setup.indexer, "user_all_robust", &robust).await;

    // One node down (4 online): only robust (needs 5) stops.
    let disabled_a = setup.indexer.disable(4.into()).await;
    assert_can_sign(&mut setup.indexer, "user_4_low", &low).await;
    assert_can_sign(&mut setup.indexer, "user_4_high", &high).await;
    assert_cannot_sign(&mut setup.indexer, "user_4_robust", &robust).await;

    // Two nodes down (3 online): high (t=4) stops too.
    let disabled_b = setup.indexer.disable(3.into()).await;
    assert_can_sign(&mut setup.indexer, "user_3_low", &low).await;
    assert_cannot_sign(&mut setup.indexer, "user_3_high", &high).await;

    // Then restoring both nodes restores signing for every domain.
    disabled_b.reenable_and_wait_till_running().await;
    disabled_a.reenable_and_wait_till_running().await;
    assert_can_sign(&mut setup.indexer, "user_restored_high", &high).await;
    assert_can_sign(&mut setup.indexer, "user_restored_robust", &robust).await;
}

/// Resharing (a new node joining) preserves each domain's own reconstruction threshold:
/// afterwards the high-`t` domain still requires its higher online-signer count.
#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn per_domain_reconstruction_thresholds__should_be_preserved_for_each_domain_across_resharing()
 {
    // Given a cluster starting with 4 of an eventual 5 participants.
    const NUM_PARTICIPANTS: usize = 5;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::RECONSTRUCTION_THRESHOLD_RESHARING_TEST,
        BLOCK_TIME,
    );

    // low needs 2 online, mid (Frost) needs 3 online, high needs 4 online.
    let low = sign_domain(0, Protocol::CaitSith, 2);
    let mid = sign_domain(1, Protocol::Frost, 3);
    let high = sign_domain(2, Protocol::CaitSith, 4);
    let domains = vec![low.clone(), mid.clone(), high.clone()];

    // Initialize with one fewer participant; the fifth joins during resharing.
    let mut initial_participants = setup.participants.clone();
    initial_participants.participants.pop();

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(initial_participants);
        contract.add_domains(domains.clone());
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME * domains.len() as u32,
        )
        .await
        .expect("must not exceed timeout");

    // Sanity: all four initial nodes online, every domain signs (high's t=4 needs all 4).
    assert_can_sign(&mut setup.indexer, "user_pre_low", &low).await;
    assert_can_sign(&mut setup.indexer, "user_pre_mid", &mid).await;
    assert_can_sign(&mut setup.indexer, "user_pre_high", &high).await;

    // When the fifth node joins via resharing.
    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing(setup.participants.clone());

    setup
        .indexer
        .wait_for_contract_state(
            |state| match state {
                ContractState::Running(running) => {
                    running.keyset.epoch_id.get() == 1
                        && running.participants.participants.len() == NUM_PARTICIPANTS
                }
                _ => false,
            },
            DEFAULT_MAX_PROTOCOL_WAIT_TIME * domains.len() as u32,
        )
        .await
        .expect("Timeout waiting for resharing to complete");

    // Then all domains still sign with the full reshared set.
    assert_can_sign(&mut setup.indexer, "user_post_low", &low).await;
    assert_can_sign(&mut setup.indexer, "user_post_mid", &mid).await;
    assert_can_sign(&mut setup.indexer, "user_post_high", &high).await;

    // Then with two nodes down (3 online), high (t=4) can't sign — its threshold
    // survived the reshare while low/mid still work.
    let _disabled_a = setup.indexer.disable(4.into()).await;
    let _disabled_b = setup.indexer.disable(3.into()).await;
    assert_can_sign(&mut setup.indexer, "user_drop_low", &low).await;
    assert_can_sign(&mut setup.indexer, "user_drop_mid", &mid).await;
    assert_cannot_sign(&mut setup.indexer, "user_drop_high", &high).await;
}

/// Changing a domain's reconstruction threshold via a resharing proposal takes real
/// cryptographic effect: after lowering `t` from 4 to 2, only 2 nodes need be online to
/// sign — impossible unless the key was genuinely re-shared to the new degree.
#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn changing_reconstruction_threshold_via_resharing__should_reshare_the_key_to_the_new_degree()
{
    // Given a 5-node cluster with a single CaitSith domain at t=4.
    const NUM_PARTICIPANTS: usize = 5;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::RECONSTRUCTION_THRESHOLD_CHANGE_TEST,
        BLOCK_TIME,
    );

    let domain = sign_domain(0, Protocol::CaitSith, 4);
    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(vec![domain.clone()]);
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("must not exceed timeout");

    // Sanity: at t=4 the domain signs with all nodes online.
    assert_can_sign(&mut setup.indexer, "user_pre", &domain).await;

    // When resharing lowers the threshold to t=2 (participant set unchanged).
    let lowered = sign_domain(0, Protocol::CaitSith, 2);
    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing_with_threshold_updates(
            setup.participants.clone(),
            BTreeMap::from([(domain.id, ReconstructionThreshold::new(2))]),
        );

    setup
        .indexer
        .wait_for_contract_state(
            |state| match state {
                ContractState::Running(running) => running.keyset.epoch_id.get() == 1,
                _ => false,
            },
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("Timeout waiting for resharing to complete");

    // Then two online nodes suffice; the original t=4 sharing would have needed four.
    let _d1 = setup.indexer.disable(4.into()).await;
    let _d2 = setup.indexer.disable(3.into()).await;
    let _d3 = setup.indexer.disable(2.into()).await;
    assert_can_sign(&mut setup.indexer, "user_post", &lowered).await;
}
