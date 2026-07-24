//! Integration tests asserting signing availability is gated by each domain's own
//! reconstruction threshold `t`, not the governance threshold.
//!
//! Online signers needed to sign: `t` for CaitSith/Frost/CKD, `2t - 1` for DamgardEtAl.

use crate::indexer::fake::FakeIndexerManager;
use crate::indexer::participants::ContractState;
use crate::p2p::testing::port_seed;
use crate::tests::common::{ckd_domain, sign_domain};
use crate::tests::{
    DEFAULT_BLOCK_TIME, DEFAULT_MAX_PROTOCOL_WAIT_TIME, IntegrationTestSetup,
    request_ckd_and_await_response, request_signature_and_await_response,
};
use crate::tracking::AutoAbortTask;
use mpc_primitives::domain::Curve;
use near_mpc_contract_interface::types::{DomainConfig, Protocol, ReconstructionThreshold};
use near_time::Clock;
use std::collections::BTreeMap;

/// Shared budget for both assertions: the negative window must exceed the worst-case positive
/// latency, else [`assert_cannot_sign`] could pass merely because a capable domain was slow.
/// [`warm_up`] keeps that latency low, so 10s is safe.
const REQUEST_WAIT_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// Generous budget for [`warm_up`], absorbing the one-time cold-start after each online-set change.
const WARMUP_WAIT_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);

/// Sign or CKD request per `domain`'s protocol; both are gated by its reconstruction threshold.
async fn request_and_await_response(
    indexer: &mut FakeIndexerManager,
    user: &str,
    domain: &DomainConfig,
    budget: std::time::Duration,
) -> Option<std::time::Duration> {
    match Curve::from(domain.protocol) {
        Curve::Secp256k1 | Curve::Edwards25519 => {
            request_signature_and_await_response(indexer, user, domain, budget).await
        }
        Curve::Bls12381 => request_ckd_and_await_response(indexer, user, domain, budget).await,
    }
}

/// Primes each domain's presignatures for the current online set with an untimed sign, whose
/// cold-start can exceed [`REQUEST_WAIT_BUDGET`]. Only CaitSith and DamgardEtAl consume
/// pre-generated presignatures; Frost and CKD sign directly, so pass only the block's signable
/// CaitSith/DamgardEtAl domains after every online-set change.
async fn warm_up(indexer: &mut FakeIndexerManager, domains: &[&DomainConfig]) {
    for domain in domains {
        let _ = request_and_await_response(indexer, "warmup", domain, WARMUP_WAIT_BUDGET).await;
    }
}

async fn assert_can_sign(indexer: &mut FakeIndexerManager, user: &str, domain: &DomainConfig) {
    assert!(
        request_and_await_response(indexer, user, domain, REQUEST_WAIT_BUDGET)
            .await
            .is_some(),
        "domain {:?} (t={}) should be able to sign with the currently-online nodes",
        domain.id,
        domain.reconstruction_threshold.inner(),
    );
}

async fn assert_cannot_sign(indexer: &mut FakeIndexerManager, user: &str, domain: &DomainConfig) {
    assert!(
        request_and_await_response(indexer, user, domain, REQUEST_WAIT_BUDGET)
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
    const GOVERNANCE_THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        GOVERNANCE_THRESHOLD,
        TXN_DELAY_BLOCKS,
        port_seed::RECONSTRUCTION_THRESHOLD_AVAILABILITY_TEST,
        DEFAULT_BLOCK_TIME,
    );

    // Online signers needed: low 2, high 4, robust (DamgardEtAl, 2t-1) 5, ckd_low 2,
    // ckd_high 4, frost 4. Frost/CKD are gated by `t` like CaitSith.
    let low = sign_domain(0, Protocol::CaitSith, 2);
    let high = sign_domain(1, Protocol::CaitSith, 4);
    let robust = sign_domain(2, Protocol::DamgardEtAl, 3);
    let ckd_low = ckd_domain(3, 2);
    let ckd_high = ckd_domain(4, 4);
    let frost = sign_domain(5, Protocol::Frost, 4);
    let domains = vec![
        low.clone(),
        high.clone(),
        robust.clone(),
        ckd_low.clone(),
        ckd_high.clone(),
        frost.clone(),
    ];

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
    warm_up(&mut setup.indexer, &[&low, &high, &robust]).await;
    assert_can_sign(&mut setup.indexer, "user_all_low", &low).await;
    assert_can_sign(&mut setup.indexer, "user_all_high", &high).await;
    assert_can_sign(&mut setup.indexer, "user_all_robust", &robust).await;
    assert_can_sign(&mut setup.indexer, "user_all_ckd_low", &ckd_low).await;
    assert_can_sign(&mut setup.indexer, "user_all_ckd_high", &ckd_high).await;
    assert_can_sign(&mut setup.indexer, "user_all_frost", &frost).await;

    // One node down (4 online): only robust (needs 5) stops.
    let disabled_a = setup.indexer.disable(4.into()).await;
    warm_up(&mut setup.indexer, &[&low, &high]).await;
    assert_can_sign(&mut setup.indexer, "user_4_low", &low).await;
    assert_can_sign(&mut setup.indexer, "user_4_high", &high).await;
    assert_cannot_sign(&mut setup.indexer, "user_4_robust", &robust).await;
    assert_can_sign(&mut setup.indexer, "user_4_ckd_high", &ckd_high).await;
    assert_can_sign(&mut setup.indexer, "user_4_frost", &frost).await;

    // Two nodes down (3 online): high, ckd_high and frost (t=4) stop too.
    let disabled_b = setup.indexer.disable(3.into()).await;
    warm_up(&mut setup.indexer, &[&low]).await;
    assert_can_sign(&mut setup.indexer, "user_3_low", &low).await;
    assert_cannot_sign(&mut setup.indexer, "user_3_high", &high).await;
    assert_can_sign(&mut setup.indexer, "user_3_ckd_low", &ckd_low).await;
    assert_cannot_sign(&mut setup.indexer, "user_3_ckd_high", &ckd_high).await;
    assert_cannot_sign(&mut setup.indexer, "user_3_frost", &frost).await;

    // Then restoring both nodes restores signing for every domain.
    disabled_b.reenable_and_wait_till_running().await;
    disabled_a.reenable_and_wait_till_running().await;
    warm_up(&mut setup.indexer, &[&high, &robust]).await;
    assert_can_sign(&mut setup.indexer, "user_restored_high", &high).await;
    assert_can_sign(&mut setup.indexer, "user_restored_robust", &robust).await;
    assert_can_sign(&mut setup.indexer, "user_restored_ckd_high", &ckd_high).await;
    assert_can_sign(&mut setup.indexer, "user_restored_frost", &frost).await;
}

/// One resharing preserves unchanged domains' `t` while applying a per-domain update: the
/// lowered domain then signs with fewer online nodes than its old sharing allowed, while a
/// sibling left at the same `t` still needs its higher count.
#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn resharing__should_apply_updated_thresholds_while_preserving_unchanged_ones() {
    // Given a cluster starting with 4 of an eventual 5 participants.
    const NUM_PARTICIPANTS: usize = 5;
    const GOVERNANCE_THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        GOVERNANCE_THRESHOLD,
        TXN_DELAY_BLOCKS,
        port_seed::RECONSTRUCTION_THRESHOLD_RESHARING_TEST,
        DEFAULT_BLOCK_TIME,
    );

    // Online signers needed: low 2, mid (Frost) 3, high 4, ckd 4, robust (DamgardEtAl,
    // t capped at 2 by `2t - 1 <= 4` participants) 3. All survive the reshare.
    let low = sign_domain(0, Protocol::CaitSith, 2);
    let mid = sign_domain(1, Protocol::Frost, 3);
    let high = sign_domain(2, Protocol::CaitSith, 4);
    let ckd = ckd_domain(3, 4);
    let robust = sign_domain(4, Protocol::DamgardEtAl, 2);
    let domains = vec![
        low.clone(),
        mid.clone(),
        high.clone(),
        ckd.clone(),
        robust.clone(),
    ];

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

    // Sanity: all four initial nodes online, every domain signs (high/ckd t=4 need all 4).
    warm_up(&mut setup.indexer, &[&low, &high, &robust]).await;
    assert_can_sign(&mut setup.indexer, "user_pre_low", &low).await;
    assert_can_sign(&mut setup.indexer, "user_pre_mid", &mid).await;
    assert_can_sign(&mut setup.indexer, "user_pre_high", &high).await;
    assert_can_sign(&mut setup.indexer, "user_pre_ckd", &ckd).await;
    assert_can_sign(&mut setup.indexer, "user_pre_robust", &robust).await;

    // When the fifth node joins via resharing, which also lowers `high` from t=4 to t=2.
    let high_lowered = sign_domain(2, Protocol::CaitSith, 2);
    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing_with_threshold_updates(
            setup.participants.clone(),
            BTreeMap::from([(high.id, ReconstructionThreshold::new(2))]),
        );

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
    warm_up(&mut setup.indexer, &[&low, &high_lowered, &robust]).await;
    assert_can_sign(&mut setup.indexer, "user_post_low", &low).await;
    assert_can_sign(&mut setup.indexer, "user_post_mid", &mid).await;
    assert_can_sign(&mut setup.indexer, "user_post_high", &high_lowered).await;
    assert_can_sign(&mut setup.indexer, "user_post_ckd", &ckd).await;
    assert_can_sign(&mut setup.indexer, "user_post_robust", &robust).await;

    // With three nodes down (2 online): `high` now signs at its new t=2 — impossible under
    // the old t=4 sharing, so the update took real effect. `ckd`, left at t=4, stops —
    // proving the change was per-domain, not global. `low` (t=2) keeps working; `mid` (t=3)
    // and `robust` (DamgardEtAl, needs 2t-1=3) stop.
    let _disabled_a = setup.indexer.disable(4.into()).await;
    let _disabled_b = setup.indexer.disable(3.into()).await;
    let _disabled_c = setup.indexer.disable(2.into()).await;
    warm_up(&mut setup.indexer, &[&low, &high_lowered]).await;
    assert_can_sign(&mut setup.indexer, "user_drop_low", &low).await;
    assert_can_sign(&mut setup.indexer, "user_drop_high", &high_lowered).await;
    assert_cannot_sign(&mut setup.indexer, "user_drop_ckd", &ckd).await;
    assert_cannot_sign(&mut setup.indexer, "user_drop_mid", &mid).await;
    assert_cannot_sign(&mut setup.indexer, "user_drop_robust", &robust).await;
}
