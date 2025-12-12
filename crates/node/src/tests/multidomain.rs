use crate::indexer::participants::ContractState;
use crate::p2p::testing::PortSeed;
use crate::tests::{
    request_ckd_and_await_response, request_signature_and_await_response, IntegrationTestSetup,
    DEFAULT_MAX_PROTOCOL_WAIT_TIME, DEFAULT_MAX_SIGNATURE_WAIT_TIME,
};
use crate::tracking::AutoAbortTask;
use mpc_contract::primitives::domain::{DomainConfig, DomainId, SignatureScheme};
use near_o11y::testonly::init_integration_logger;
use near_time::Clock;

// Make a cluster of four nodes, test that we can generate keyshares
// and then produce signatures.
#[tokio::test]
async fn test_basic_multidomain() {
    init_integration_logger();
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
        PortSeed::BASIC_MULTIDOMAIN_TEST,
        std::time::Duration::from_millis(600), // helps to avoid flaky test
    );

    let mut domains = vec![
        DomainConfig {
            id: DomainId(0),
            scheme: SignatureScheme::Secp256k1,
        },
        DomainConfig {
            id: DomainId(1),
            scheme: SignatureScheme::Ed25519,
        },
        DomainConfig {
            id: DomainId(2),
            scheme: SignatureScheme::Bls12381,
        },
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
            DEFAULT_MAX_PROTOCOL_WAIT_TIME * 3,
        )
        .await
        .expect("must not exceed timeout");

    tracing::info!("requesting signature");
    for domain in &domains {
        match domain.scheme {
            SignatureScheme::Secp256k1
            | SignatureScheme::Ed25519
            | SignatureScheme::V2Secp256k1 => {
                assert!(request_signature_and_await_response(
                    &mut setup.indexer,
                    &format!("user{}", domain.id.0),
                    domain,
                    DEFAULT_MAX_SIGNATURE_WAIT_TIME
                )
                .await
                .is_some());
            }
            SignatureScheme::Bls12381 => {
                assert!(request_ckd_and_await_response(
                    &mut setup.indexer,
                    &format!("user{}", domain.id.0),
                    domain,
                    DEFAULT_MAX_SIGNATURE_WAIT_TIME
                )
                .await
                .is_some());
            }
        }
    }

    {
        let new_domains = vec![
            DomainConfig {
                id: DomainId(3),
                scheme: SignatureScheme::Ed25519,
            },
            DomainConfig {
                id: DomainId(4),
                scheme: SignatureScheme::Secp256k1,
            },
            DomainConfig {
                id: DomainId(5),
                scheme: SignatureScheme::Bls12381,
            },
        ];
        let mut contract = setup.indexer.contract_mut().await;
        contract.add_domains(new_domains.clone());
        domains.extend(new_domains);
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
            DEFAULT_MAX_PROTOCOL_WAIT_TIME * 3,
        )
        .await
        .expect("must not exceed timeout");

    for domain in &domains {
        match domain.scheme {
            SignatureScheme::Secp256k1
            | SignatureScheme::Ed25519
            | SignatureScheme::V2Secp256k1 => {
                assert!(request_signature_and_await_response(
                    &mut setup.indexer,
                    &format!("user{}", domain.id.0),
                    domain,
                    DEFAULT_MAX_SIGNATURE_WAIT_TIME
                )
                .await
                .is_some());
            }
            SignatureScheme::Bls12381 => {
                assert!(request_ckd_and_await_response(
                    &mut setup.indexer,
                    &format!("user{}", domain.id.0),
                    domain,
                    DEFAULT_MAX_SIGNATURE_WAIT_TIME
                )
                .await
                .is_some());
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
            DEFAULT_MAX_PROTOCOL_WAIT_TIME * 4,
        )
        .await
        .expect("must not exceed timeout");

    for domain in &domains {
        match domain.scheme {
            SignatureScheme::Secp256k1
            | SignatureScheme::Ed25519
            | SignatureScheme::V2Secp256k1 => {
                assert!(request_signature_and_await_response(
                    &mut setup.indexer,
                    &format!("user{}", domain.id.0),
                    domain,
                    DEFAULT_MAX_SIGNATURE_WAIT_TIME
                )
                .await
                .is_some());
            }
            SignatureScheme::Bls12381 => {
                assert!(request_ckd_and_await_response(
                    &mut setup.indexer,
                    &format!("user{}", domain.id.0),
                    domain,
                    DEFAULT_MAX_SIGNATURE_WAIT_TIME
                )
                .await
                .is_some());
            }
        }
    }
}
