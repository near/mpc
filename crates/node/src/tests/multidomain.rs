use crate::indexer::participants::ContractState;
use crate::p2p::testing::port_seed;
use crate::tests::common::{ckd_domain, sign_domain};
use crate::tests::{
    DEFAULT_MAX_PROTOCOL_WAIT_TIME, DEFAULT_MAX_SIGNATURE_WAIT_TIME, IntegrationTestSetup,
    request_ckd_and_await_response, request_signature_and_await_response,
};
use crate::tracking::AutoAbortTask;
use mpc_primitives::domain::Curve;
use near_mpc_contract_interface::types::Protocol;
use near_time::Clock;

// Make a cluster of four nodes, test that we can generate keyshares
// and then produce signatures.
#[tokio::test]
#[test_log::test]
async fn test_basic_multidomain() {
    const NUM_PARTICIPANTS: usize = 4;
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
        port_seed::BASIC_MULTIDOMAIN_TEST,
        std::time::Duration::from_millis(600), // helps to avoid flaky test
    );

    // TODO(#1689): in this test it would be desirable to add DamgardEtAl.
    // That requires having NUM_PARTICIPANTS = 5 and THRESHOLD = 5
    // which makes this test too slow to pass in CI, which should be fixed
    let mut domains = vec![
        sign_domain(0, Protocol::CaitSith, 3),
        sign_domain(1, Protocol::Frost, 3),
        ckd_domain(2, 3),
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

    tracing::info!("requesting signature");
    for domain in &domains {
        match Curve::from(domain.protocol) {
            Curve::Secp256k1 | Curve::Edwards25519 => {
                assert!(
                    request_signature_and_await_response(
                        &mut setup.indexer,
                        &format!("user{}", domain.id.0),
                        domain,
                        DEFAULT_MAX_SIGNATURE_WAIT_TIME
                    )
                    .await
                    .is_some()
                );
            }
            Curve::Bls12381 => {
                assert!(
                    request_ckd_and_await_response(
                        &mut setup.indexer,
                        &format!("user{}", domain.id.0),
                        domain,
                        DEFAULT_MAX_SIGNATURE_WAIT_TIME
                    )
                    .await
                    .is_some()
                );
            }
        }
    }
    let new_domains = vec![
        sign_domain(3, Protocol::Frost, 3),
        sign_domain(4, Protocol::CaitSith, 3),
        ckd_domain(5, 3),
    ];

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.add_domains(new_domains.clone());
        domains.extend(new_domains.clone());
    }
    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Initializing(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("must not exceed timeout");

    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME * new_domains.len() as u32,
        )
        .await
        .expect("must not exceed timeout");

    for domain in &domains {
        match Curve::from(domain.protocol) {
            Curve::Secp256k1 | Curve::Edwards25519 => {
                assert!(
                    request_signature_and_await_response(
                        &mut setup.indexer,
                        &format!("user{}", domain.id.0),
                        domain,
                        DEFAULT_MAX_SIGNATURE_WAIT_TIME
                    )
                    .await
                    .is_some()
                );
            }
            Curve::Bls12381 => {
                assert!(
                    request_ckd_and_await_response(
                        &mut setup.indexer,
                        &format!("user{}", domain.id.0),
                        domain,
                        DEFAULT_MAX_SIGNATURE_WAIT_TIME
                    )
                    .await
                    .is_some()
                );
            }
        }
    }

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.start_resharing(setup.participants);
    }

    setup
        .indexer
        .wait_for_contract_state(
            {
                |state| {
                    println!("state: {:?}", state);
                    match state {
                        ContractState::Running(running) => running.keyset.epoch_id.get() == 1,
                        _ => false,
                    }
                }
            },
            DEFAULT_MAX_PROTOCOL_WAIT_TIME * domains.len() as u32,
        )
        .await
        .expect("must not exceed timeout");

    for domain in &domains {
        match Curve::from(domain.protocol) {
            Curve::Secp256k1 | Curve::Edwards25519 => {
                assert!(
                    request_signature_and_await_response(
                        &mut setup.indexer,
                        &format!("user{}", domain.id.0),
                        domain,
                        DEFAULT_MAX_SIGNATURE_WAIT_TIME
                    )
                    .await
                    .is_some()
                );
            }
            Curve::Bls12381 => {
                assert!(
                    request_ckd_and_await_response(
                        &mut setup.indexer,
                        &format!("user{}", domain.id.0),
                        domain,
                        DEFAULT_MAX_SIGNATURE_WAIT_TIME
                    )
                    .await
                    .is_some()
                );
            }
        }
    }
}
