#![expect(non_snake_case)]

use super::{MpcContract, gas};
use crate::types::{
    AccountId, AttemptId, Attestation, AuthScheme, BackupServiceInfo, BitcoinExtractor,
    BitcoinRpcRequest, BitcoinTxId, BlockConfirmations, CKDAppPublicKey, CKDAppPublicKeyPV,
    CKDRequest, CKDRequestArgs, CKDResponse, ChainEntry, ChainRouting, DestinationNodeInfo,
    DomainConfig, DomainId, DomainPurpose, Ed25519PublicKey, EpochId, ExpectedMeasurements,
    ForeignChain, ForeignChainRpcRequest, ForeignTxPayloadVersion, GovernanceThreshold,
    GovernanceThresholdParameters, Hash256, InitConfig, K256AffinePoint, K256Scalar, K256Signature,
    KeyEventId, KeyProviderEventDigest, Keyset, LauncherImageHash, MockAttestation, MrtdHash,
    ParticipantId, ParticipantInfo, Participants, Payload, ProposedGovernanceThresholdParameters,
    Protocol, ProviderConfig, ProviderId, PublicKey, ReconstructionThreshold, Rtmr0Hash, Rtmr1Hash,
    Rtmr2Hash, SignRequestArgs, SignatureRequest, SignatureResponse, TeeVerifierCodeHash, Update,
    UpdateHash, VerifyForeignTransactionRequest, VerifyForeignTransactionRequestArgs,
    VerifyForeignTransactionResponse,
};
use near_kit_primitives::protocol::Action;
use near_kit_primitives::rpc::{BlockReference, ViewFunctionResult};
use near_kit_primitives::{Contract, CryptoHash, NearToken, TxSender, Viewer};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_crypto_types::{Bls12381G1PublicKey, Bls12381G2PublicKey};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Records what it is asked to send or view, so a test can assert the exact
/// wire encoding of every method.
#[derive(Clone)]
struct Recorder {
    account_id: AccountId,
    sent: Arc<Mutex<Vec<Sent>>>,
    viewed: Arc<Mutex<Vec<Viewed>>>,
}

type Sent = (AccountId, Vec<Action>);
type Viewed = (AccountId, String, Vec<u8>);

impl Recorder {
    fn new() -> Self {
        Self {
            account_id: "alice.near".parse().unwrap(),
            sent: Arc::default(),
            viewed: Arc::default(),
        }
    }
}

impl TxSender for Recorder {
    type Output = ();
    type SendError = ();

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    async fn send(&self, receiver_id: AccountId, actions: Vec<Action>) -> Result<(), ()> {
        self.sent.lock().unwrap().push((receiver_id, actions));
        Ok(())
    }
}

impl Viewer for Recorder {
    type ViewError = ();

    async fn view_function(
        &self,
        contract_id: &AccountId,
        method: &str,
        args: &[u8],
        _block: BlockReference,
    ) -> Result<ViewFunctionResult, ()> {
        self.viewed
            .lock()
            .unwrap()
            .push((contract_id.clone(), method.to_string(), args.to_vec()));
        Ok(ViewFunctionResult::new(Vec::new(), 0, CryptoHash::ZERO))
    }
}

/// Renders arguments as JSON text, or as hex when they are Borsh (e.g. when
/// proposing updates). No arguments render as `{}`, however the client
/// encodes them.
fn render_args(args: &[u8]) -> String {
    if args.is_empty() {
        return "{}".to_string();
    }
    match std::str::from_utf8(args) {
        Ok(text) if serde_json::from_str::<serde_json::Value>(text).is_ok() => text.to_string(),
        _ => format!("0x{}", hex::encode(args)),
    }
}

/// Renders a sent function call as its reviewable wire format
/// (method, gas, deposit, args).
fn render(contract_id: &AccountId, actions: &[Action]) -> String {
    let [Action::FunctionCall(call)] = actions else {
        panic!("expected one function call, got {actions:?}");
    };
    format!(
        "contract: {contract_id}\nmethod:   {}\ngas:      {}\ndeposit:  {}\nargs:     {}",
        call.method_name,
        call.gas,
        call.deposit.exact_amount_display(),
        render_args(&call.args),
    )
}

/// One catalog snapshot for every call: each is sent once with the gas and
/// deposit callers attach, and its wire format becomes a section of the
/// snapshot. New calls add a section here.
#[tokio::test]
async fn mpc_contract__should_match_the_wire_format_catalog() {
    // Given
    let recorder = Recorder::new();
    let contract = MpcContract::client(recorder.clone(), "mpc.near".parse().unwrap());
    let governance_threshold_parameters = GovernanceThresholdParameters {
        threshold: GovernanceThreshold(1),
        participants: Participants {
            next_id: ParticipantId(1),
            participants: vec![(
                "alice.near".parse().unwrap(),
                ParticipantId(0),
                ParticipantInfo {
                    url: "http://localhost:7".try_into().unwrap(),
                    tls_public_key: Ed25519PublicKey::from([7u8; 32]),
                },
            )],
        },
    };
    let key_event_id = KeyEventId::new(EpochId::new(7), DomainId(0), AttemptId(0));
    let signature_response = SignatureResponse::Secp256k1(K256Signature {
        big_r: K256AffinePoint {
            affine_point: [7u8; 33],
        },
        s: K256Scalar { scalar: [7u8; 32] },
        recovery_id: 0,
    });
    let foreign_tx_request = VerifyForeignTransactionRequest {
        request: ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
            tx_id: BitcoinTxId([7u8; 32]),
            confirmations: BlockConfirmations(1),
            extractors: [BitcoinExtractor::BlockHash].into(),
        }),
        domain_id: DomainId(0),
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
    };
    let ckd_requests = [
        CKDAppPublicKey::AppPublicKey(Bls12381G1PublicKey([7u8; 48])),
        CKDAppPublicKey::AppPublicKeyPV(CKDAppPublicKeyPV {
            pk1: Bls12381G1PublicKey([7u8; 48]),
            pk2: Bls12381G2PublicKey([7u8; 96]),
        }),
    ]
    .map(|app_public_key| CKDRequestArgs {
        derivation_path: "test".to_string(),
        app_public_key,
        domain_id: DomainId(0),
    });

    // When: every call, once, in declaration order
    contract
        .init(
            governance_threshold_parameters.clone(),
            "tee-verifier.near".parse().unwrap(),
            Some(InitConfig::default()),
        )
        .await
        .unwrap();
    contract
        .init_running(
            Vec::new(),
            DomainId(0),
            Keyset::new(EpochId::new(7), Vec::new()),
            governance_threshold_parameters.clone(),
            "tee-verifier.near".parse().unwrap(),
            Some(InitConfig::default()),
        )
        .await
        .unwrap();
    contract.migrate().await.unwrap();
    contract
        .sign(SignRequestArgs::new(
            "test".to_string(),
            Payload::Ecdsa([7u8; 32].into()),
            DomainId(0),
        ))
        .await
        .unwrap();
    contract
        .respond(
            SignatureRequest::new(
                DomainId(0),
                Payload::Ecdsa([7u8; 32].into()),
                &"alice.near".parse().unwrap(),
                "test",
            ),
            signature_response.clone(),
        )
        .await
        .unwrap();
    for request in ckd_requests {
        contract
            .request_app_private_key(request.clone())
            .gas(gas::request_app_private_key(&request))
            .await
            .unwrap();
    }
    contract
        .respond_ckd(
            CKDRequest::new(
                CKDAppPublicKey::AppPublicKey(Bls12381G1PublicKey([7u8; 48])),
                DomainId(0),
                &"alice.near".parse().unwrap(),
                "test",
            ),
            CKDResponse {
                big_y: Bls12381G1PublicKey([7u8; 48]),
                big_c: Bls12381G1PublicKey([7u8; 48]),
            },
        )
        .await
        .unwrap();
    // The second request has `expected_payload_hash: None`: pins that an unset
    // field is omitted from the wire entirely.
    for expected_payload_hash in [Some(Hash256([7u8; 32])), None] {
        contract
            .verify_foreign_transaction(VerifyForeignTransactionRequestArgs {
                request: ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                    tx_id: BitcoinTxId([7u8; 32]),
                    confirmations: BlockConfirmations(1),
                    extractors: [BitcoinExtractor::BlockHash].into(),
                }),
                domain_id: DomainId(0),
                payload_version: ForeignTxPayloadVersion::V1,
                expected_payload_hash,
            })
            .await
            .unwrap();
    }
    contract
        .respond_verify_foreign_tx(
            foreign_tx_request,
            VerifyForeignTransactionResponse {
                payload_hash: Hash256([7u8; 32]),
                signature: signature_response,
            },
        )
        .await
        .unwrap();
    contract
        .submit_contract_update(Update::Code(vec![7u8; 4]))
        .await
        .unwrap();
    contract
        .vote_contract_update(UpdateHash::Code(Hash256([7u8; 32])))
        .await
        .unwrap();
    contract.remove_contract_update_vote().await.unwrap();
    contract
        .remove_non_participant_contract_update_votes()
        .await
        .unwrap();
    contract
        .vote_add_domains(vec![DomainConfig {
            id: DomainId(0),
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(2),
            purpose: DomainPurpose::Sign,
        }])
        .await
        .unwrap();
    contract.start_keygen_instance(key_event_id).await.unwrap();
    contract
        .vote_pk(
            key_event_id,
            PublicKey::Ed25519(Ed25519PublicKey::from([7u8; 32])),
        )
        .await
        .unwrap();
    contract
        .vote_new_parameters(
            EpochId::new(7),
            ProposedGovernanceThresholdParameters {
                parameters: governance_threshold_parameters,
                per_domain_thresholds: BTreeMap::new(),
            },
        )
        .await
        .unwrap();
    contract.start_reshare_instance(key_event_id).await.unwrap();
    contract.vote_reshared(key_event_id).await.unwrap();
    contract
        .vote_abort_key_event_instance(key_event_id)
        .await
        .unwrap();
    contract.vote_cancel_keygen(DomainId(7)).await.unwrap();
    contract.vote_cancel_resharing().await.unwrap();
    contract
        .vote_add_launcher_hash(LauncherImageHash::from([7u8; 32]))
        .await
        .unwrap();
    contract
        .vote_add_os_measurement(ExpectedMeasurements {
            mrtd: MrtdHash::from([7u8; 48]),
            rtmr0: Rtmr0Hash::from([7u8; 48]),
            rtmr1: Rtmr1Hash::from([7u8; 48]),
            rtmr2: Rtmr2Hash::from([7u8; 48]),
            key_provider_event_digest: KeyProviderEventDigest::from([7u8; 48]),
        })
        .await
        .unwrap();
    contract
        .vote_tee_verifier_change(
            "verifier.near".parse().unwrap(),
            TeeVerifierCodeHash::new([7u8; 32]),
        )
        .await
        .unwrap();
    contract
        .update_participant_url("http://localhost:7".try_into().unwrap())
        .await
        .unwrap();
    contract
        .register_backup_service(BackupServiceInfo {
            public_key: Ed25519PublicKey::from([7u8; 32]),
        })
        .await
        .unwrap();
    contract
        .start_node_migration(DestinationNodeInfo {
            signer_account_pk: Ed25519PublicKey::from([7u8; 32]),
            destination_node_info: ParticipantInfo {
                url: "http://localhost:7".try_into().unwrap(),
                tls_public_key: Ed25519PublicKey::from([7u8; 32]),
            },
        })
        .await
        .unwrap();
    contract.cancel_node_migration().await.unwrap();
    contract
        .conclude_node_migration(Keyset::new(EpochId::new(7), Vec::new()))
        .await
        .unwrap();
    contract
        .vote_update_foreign_chain_providers(NonEmptyBTreeMap::new(
            ForeignChain::Bitcoin,
            ChainEntry {
                providers: NonEmptyBTreeMap::new(
                    ProviderId("alchemy".to_string()),
                    ProviderConfig {
                        base_url: "http://localhost:7".to_string(),
                        auth_scheme: AuthScheme::None,
                        chain_routing: ChainRouting::Embedded,
                    },
                ),
                quorum: 1,
            },
        ))
        .await
        .unwrap();
    contract
        .prepay_attestation_storage("node.near".parse().unwrap(), 2)
        .deposit(NearToken::from_millinear(14))
        .await
        .unwrap();
    contract
        .submit_participant_info(
            Attestation::Mock(MockAttestation::Valid),
            Ed25519PublicKey::from([7u8; 32]),
        )
        .await
        .unwrap();
    contract.verify_tee().await.unwrap();
    contract.clean_tee_status().await.unwrap();
    contract.clean_invalid_attestations(7).await.unwrap();

    // Then
    let catalog = recorder
        .sent
        .lock()
        .unwrap()
        .iter()
        .map(|(contract_id, actions)| render(contract_id, actions))
        .collect::<Vec<_>>()
        .join("\n\n");
    insta::assert_snapshot!(catalog);
}

/// One catalog snapshot for every view: each is called once and its wire
/// format becomes a section of the snapshot. New views add a call here.
#[tokio::test]
async fn mpc_contract__should_match_the_view_catalog() {
    // Given
    let recorder = Recorder::new();
    let contract = MpcContract::client(recorder.clone(), "mpc.near".parse().unwrap());

    // When: every view, once, in declaration order; only the recorded calls
    // matter, so the empty response is left undecoded
    let _ = contract.allowed_docker_image_hashes().await;
    let _ = contract.allowed_launcher_image_hashes().await;
    let _ = contract.allowed_launcher_compose_hashes().await;
    let _ = contract.allowed_os_measurements().await;
    let _ = contract.mpc_node_manifest_digest_votes().await;
    let _ = contract.launcher_hash_votes().await;
    let _ = contract.os_measurement_votes().await;
    let _ = contract.contract_update_votes().await;
    let _ = contract.state().await;
    let _ = contract.config().await;
    let _ = contract.get_tee_accounts().await;
    let _ = contract.migration_info().await;
    let _ = contract.get_available_foreign_chains().await;
    let _ = contract.get_foreign_chains_configs().await;
    let _ = contract.allowed_foreign_chain_providers().await;
    let _ = contract.version().await;
    let _ = contract.tee_verifier_account_id().await;
    let _ = contract.tee_verifier_votes().await;
    let _ = contract.public_key(Some(DomainId(0))).await;
    let _ = contract
        .derived_public_key(
            "test".to_string(),
            Some("alice.near".parse().unwrap()),
            Some(DomainId(0)),
        )
        .await;
    let _ = contract
        .available_attestation_grants("alice.near".parse().unwrap())
        .await;
    let _ = contract
        .get_attestation(&Ed25519PublicKey::from([7u8; 32]))
        .await;
    let _ = contract
        .get_pending_request(&SignatureRequest::new(
            DomainId(0),
            Payload::Ecdsa([7u8; 32].into()),
            &"alice.near".parse().unwrap(),
            "test",
        ))
        .await;
    let _ = contract
        .get_pending_ckd_request(&CKDRequest::new(
            CKDAppPublicKey::AppPublicKey(Bls12381G1PublicKey([7u8; 48])),
            DomainId(0),
            &"alice.near".parse().unwrap(),
            "test",
        ))
        .await;
    let _ = contract
        .get_pending_verify_foreign_tx_request(&VerifyForeignTransactionRequest {
            request: ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: BitcoinTxId([7u8; 32]),
                confirmations: BlockConfirmations(1),
                extractors: [BitcoinExtractor::BlockHash].into(),
            }),
            domain_id: DomainId(0),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
        })
        .await;

    // Then
    let catalog = recorder
        .viewed
        .lock()
        .unwrap()
        .iter()
        .map(|(contract_id, method, args)| {
            format!(
                "contract: {contract_id}\nmethod:   {method}\nargs:     {}",
                render_args(args)
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n");
    insta::assert_snapshot!(catalog);
}
