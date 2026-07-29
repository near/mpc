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
    request_ckd_and_await_response, request_ckd_pv_and_await_response,
    request_signature_and_await_response,
};
use crate::tracking::AutoAbortTask;
use mpc_primitives::domain::{Curve, DomainId};
use near_mpc_contract_interface::types::{DomainConfig, Protocol, ReconstructionThreshold};
use near_time::Clock;

/// Shared budget for both assertions: the negative window must exceed the worst-case positive
/// latency, else [`assert_cannot_sign`] could pass merely because a capable domain was slow.
/// [`warm_up`] keeps that latency low.
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

/// Primes each domain's presignatures for the current online set with a generously-budgeted sign,
/// whose cold-start can exceed [`REQUEST_WAIT_BUDGET`]. Only CaitSith and DamgardEtAl consume
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

#[derive(Clone, Copy)]
enum Availability {
    Works,
    Stops,
}

async fn assert_availability(
    indexer: &mut FakeIndexerManager,
    stage: &str,
    expectations: &[(&DomainConfig, Availability)],
) {
    for (domain, expected) in expectations {
        let user = format!("user_{stage}_{}", domain.id.0);
        let response = match Curve::from(domain.protocol) {
            Curve::Bls12381 => {
                request_ckd_pv_and_await_response(indexer, &user, domain, REQUEST_WAIT_BUDGET).await
            }
            Curve::Secp256k1 | Curve::Edwards25519 => {
                request_signature_and_await_response(indexer, &user, domain, REQUEST_WAIT_BUDGET)
                    .await
            }
        };
        let t = domain.reconstruction_threshold.inner();
        match expected {
            Availability::Works => assert!(
                response.is_some(),
                "domain {:?} (t={t}) should be available at stage {stage}",
                domain.id,
            ),
            Availability::Stops => assert!(
                response.is_none(),
                "domain {:?} (t={t}) must NOT be available at stage {stage}: too few nodes are online",
                domain.id,
            ),
        }
    }
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

/// A domain's config on each side of a resharing, differing only in `t`.
struct ResharedDomain {
    before: DomainConfig,
    after: DomainConfig,
}

impl ResharedDomain {
    fn kept(domain: DomainConfig) -> Self {
        Self {
            before: domain.clone(),
            after: domain,
        }
    }

    fn updated(before: DomainConfig, new_threshold: u64) -> Self {
        let after = DomainConfig {
            reconstruction_threshold: ReconstructionThreshold::new(new_threshold),
            ..before.clone()
        };
        Self { before, after }
    }

    fn threshold_update(&self) -> Option<(DomainId, ReconstructionThreshold)> {
        (self.after.reconstruction_threshold != self.before.reconstruction_threshold)
            .then_some((self.before.id, self.after.reconstruction_threshold))
    }
}

/// One resharing lowers `t` from 3 to 2 on one domain per protocol while a CaitSith and a CKD
/// sibling keep theirs: the lowered domains then work with fewer online nodes than their old
/// sharings allowed, the DamgardEtAl one at its new `2t - 1 = 3` signers, and the kept siblings
/// still need their own `t`.
///
/// Lowering is what makes the updates provable: a resharing that ignored the update would leave a
/// sharing needing more shares than the new `t` selects, which every protocol here rejects when
/// verifying its own output.
#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn resharing__should_apply_updated_thresholds_while_preserving_unchanged_ones() {
    // Given a cluster starting with 5 of an eventual 6 participants.
    const NUM_PARTICIPANTS: usize = 6;
    // Must be valid for 5 and 6 participants alike, i.e. within `[ceil(3n/5), n]` for both.
    const GOVERNANCE_THRESHOLD: usize = 4;
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

    // Every domain starts at t=3, which the DamgardEtAl one can only sign with all `2t - 1 = 5`
    // initial participants.
    let caitsith_kept = ResharedDomain::kept(sign_domain(0, Protocol::CaitSith, 3));
    let caitsith_updated = ResharedDomain::updated(sign_domain(1, Protocol::CaitSith, 3), 2);
    let frost_updated = ResharedDomain::updated(sign_domain(2, Protocol::Frost, 3), 2);
    let ckd_kept = ResharedDomain::kept(ckd_domain(3, 3));
    let ckd_updated = ResharedDomain::updated(ckd_domain(4, 3), 2);
    let robust_updated = ResharedDomain::updated(sign_domain(5, Protocol::DamgardEtAl, 3), 2);
    let domains = [
        &caitsith_kept,
        &caitsith_updated,
        &frost_updated,
        &ckd_kept,
        &ckd_updated,
        &robust_updated,
    ];

    // Initialize with one fewer participant; the sixth joins during resharing.
    let mut initial_participants = setup.participants.clone();
    initial_participants.participants.pop();

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(initial_participants);
        contract.add_domains(domains.iter().map(|d| d.before.clone()).collect());
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

    // Sanity: all five initial nodes online, every domain works at its pre-reshare `t`.
    let presignature_domains_before = [
        &caitsith_kept.before,
        &caitsith_updated.before,
        &robust_updated.before,
    ];
    warm_up(&mut setup.indexer, &presignature_domains_before).await;
    assert_availability(
        &mut setup.indexer,
        "pre",
        &[
            (&caitsith_kept.before, Availability::Works),
            (&caitsith_updated.before, Availability::Works),
            (&frost_updated.before, Availability::Works),
            (&ckd_kept.before, Availability::Works),
            (&ckd_updated.before, Availability::Works),
            (&robust_updated.before, Availability::Works),
        ],
    )
    .await;

    // When the sixth node joins via resharing, which also carries the per-domain threshold updates.
    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing_with_threshold_updates(
            setup.participants.clone(),
            domains
                .iter()
                .filter_map(|d| d.threshold_update())
                .collect(),
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

    // Then all domains still work with the full reshared set.
    let presignature_domains_after = [
        &caitsith_kept.after,
        &caitsith_updated.after,
        &robust_updated.after,
    ];
    warm_up(&mut setup.indexer, &presignature_domains_after).await;
    assert_availability(
        &mut setup.indexer,
        "post",
        &[
            (&caitsith_kept.after, Availability::Works),
            (&caitsith_updated.after, Availability::Works),
            (&frost_updated.after, Availability::Works),
            (&ckd_kept.after, Availability::Works),
            (&ckd_updated.after, Availability::Works),
            (&robust_updated.after, Availability::Works),
        ],
    )
    .await;

    // With three nodes down (3 online): `robust` works at its new 2t-1=3 signers, which its old t=3
    // could never reach with fewer than 5. Every other domain is still at or above its `t`.
    let _disabled_a = setup.indexer.disable(5.into()).await;
    let _disabled_b = setup.indexer.disable(4.into()).await;
    let _disabled_c = setup.indexer.disable(3.into()).await;
    warm_up(&mut setup.indexer, &presignature_domains_after).await;
    assert_availability(
        &mut setup.indexer,
        "three_online",
        &[
            (&caitsith_kept.after, Availability::Works),
            (&caitsith_updated.after, Availability::Works),
            (&frost_updated.after, Availability::Works),
            (&ckd_kept.after, Availability::Works),
            (&ckd_updated.after, Availability::Works),
            (&robust_updated.after, Availability::Works),
        ],
    )
    .await;

    // With one more down (2 online): the updated domains work at their new t=2, impossible under
    // their old t=3 sharings, while the kept siblings stop: the updates were per-domain. `robust`
    // stops too, its 2t-1=3 signers now out of reach.
    let _disabled_d = setup.indexer.disable(2.into()).await;
    warm_up(&mut setup.indexer, &[&caitsith_updated.after]).await;
    assert_availability(
        &mut setup.indexer,
        "two_online",
        &[
            (&caitsith_kept.after, Availability::Stops),
            (&caitsith_updated.after, Availability::Works),
            (&frost_updated.after, Availability::Works),
            (&ckd_kept.after, Availability::Stops),
            (&ckd_updated.after, Availability::Works),
            (&robust_updated.after, Availability::Stops),
        ],
    )
    .await;
}
