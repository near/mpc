use crate::indexer::participants::ContractState;
use crate::keyshare::import::ImportKeyshareFile;
use crate::p2p::testing::PortSeed;
use crate::tests::{
    request_signature_and_await_response, IntegrationTestSetup, DEFAULT_BLOCK_TIME,
    DEFAULT_MAX_PROTOCOL_WAIT_TIME, DEFAULT_MAX_SIGNATURE_WAIT_TIME,
};
use crate::tracking::AutoAbortTask;
use mpc_contract::primitives::domain::{DomainConfig, DomainId, SignatureScheme};
use near_o11y::testonly::init_integration_logger;
use near_time::Clock;
use rand::rngs::StdRng;
use rand::SeedableRng;
use threshold_signatures::participants::Participant;
use threshold_signatures::test_utils::TestGenerators;

/// Integration test: import keyshares from an external source, have nodes vote
/// to create a new domain, and then sign with the imported key.
///
/// Flow:
/// 1. Create a cluster with 4 nodes, threshold 3, and one existing Secp256k1 domain (via keygen).
/// 2. Generate ECDSA keyshares externally using TestGenerators with matching participant IDs.
/// 3. Write import_keyshare files to each node's home directory.
/// 4. Wait for the import to complete (new domain appears in keyset, nodes restart).
/// 5. Request a signature on the imported domain and verify it succeeds.
#[tokio::test]
async fn test_import_keyshare() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup: IntegrationTestSetup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::IMPORT_KEYSHARE_TEST,
        DEFAULT_BLOCK_TIME,
    );

    // We need an existing domain so the contract starts in Running state (via keygen).
    let existing_domain = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Secp256k1,
    };

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(vec![existing_domain.clone()]);
    }

    // Collect participant IDs from the setup (random u32 values assigned during config generation).
    let ecdsa_participants: Vec<Participant> = setup
        .participants
        .participants
        .iter()
        .map(|p| Participant::from(p.id.raw()))
        .collect();

    // Generate ECDSA keyshares for the import domain using matching participant IDs.
    let mut rng = StdRng::from_seed([42u8; 32]);
    let test_gen = TestGenerators {
        participants: ecdsa_participants.clone(),
        threshold: THRESHOLD,
    };
    let keyshares = test_gen.make_ecdsa_keygens(&mut rng);

    // Write import_keyshare files to each node's home directory.
    for i in 0..NUM_PARTICIPANTS {
        let participant_id = setup.participants.participants[i].id;
        let ecdsa_participant = Participant::from(participant_id.raw());
        let keygen_output = keyshares.get(&ecdsa_participant).unwrap().clone();

        let import_file = ImportKeyshareFile {
            keygen_output,
            participant_id: participant_id.raw(),
            threshold: THRESHOLD as u64,
        };

        let home_dir = temp_dir.path().join(format!("{}", i));
        std::fs::create_dir_all(&home_dir).unwrap();
        let import_path = home_dir.join("import_keyshare");
        let data = serde_json::to_vec(&import_file).unwrap();
        std::fs::write(&import_path, data).unwrap();
    }

    // Start all nodes.
    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // Wait for keygen of the existing domain to complete.
    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("timeout waiting for keygen to complete");

    // Wait for the imported domain to appear in the contract (domain count goes from 1 to 2).
    setup
        .indexer
        .wait_for_contract_state(
            |state| match state {
                ContractState::Running(running) => running.keyset.domains.len() >= 2,
                _ => false,
            },
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("timeout waiting for import domain to be created");

    // Identify the imported domain.
    let running_state = {
        let contract = setup.indexer.contract_mut().await;
        match &contract.state {
            mpc_contract::state::ProtocolContractState::Running(state) => state.clone(),
            _ => panic!("Expected Running state"),
        }
    };

    // The imported domain should be the one that was just added (not the original keygen domain).
    let imported_domain_id = running_state.keyset.domains.last().unwrap().domain_id;
    let imported_domain = DomainConfig {
        id: imported_domain_id,
        scheme: SignatureScheme::Secp256k1,
    };

    // Request a signature on the existing (keygen) domain first to verify it still works.
    assert!(
        request_signature_and_await_response(
            &mut setup.indexer,
            "user0",
            &existing_domain,
            DEFAULT_MAX_SIGNATURE_WAIT_TIME
        )
        .await
        .is_some(),
        "Signature on existing domain should succeed"
    );

    // Request a signature on the imported domain.
    assert!(
        request_signature_and_await_response(
            &mut setup.indexer,
            "user0",
            &imported_domain,
            DEFAULT_MAX_SIGNATURE_WAIT_TIME
        )
        .await
        .is_some(),
        "Signature on imported domain should succeed"
    );

    // Verify import files have been cleaned up.
    for i in 0..NUM_PARTICIPANTS {
        let import_path = temp_dir.path().join(format!("{}/import_keyshare", i));
        assert!(
            !import_path.exists(),
            "Import keyshare file for node {} should have been deleted",
            i
        );
    }
}
