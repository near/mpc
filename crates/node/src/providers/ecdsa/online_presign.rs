use crate::metrics::{self, ONLINE_PRESIGN_MODE_LABEL, STORED_PRESIGNATURE_MODE_LABEL};
use crate::network::NetworkTaskChannel;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::primitives::{ParticipantId, UniqueId};
use crate::protocol::NamedProtocol;
use crate::providers::ecdsa::sign::parse_tweak_and_msg_hash;
use crate::providers::ecdsa::triple::PairedTriple;
use crate::providers::ecdsa::triple::participants_from_triples;
use crate::providers::ecdsa::{
    EcdsaSignatureProvider, EcdsaTaskId, KeygenOutput, ONLINE_PRESIGN_MIN_PROTOCOL_VERSION,
    TripleStorage,
};
use crate::types::{SignatureId, SignatureRequest};
use anyhow::Context;
use mpc_primitives::ReconstructionThreshold;
use mpc_primitives::domain::DomainId;
use near_mpc_contract_interface::types::Tweak;
use std::sync::Arc;
use std::time::Duration;
use threshold_signatures::ReconstructionThreshold as TSReconstructionThreshold;
use threshold_signatures::ecdsa::ot_based_ecdsa::triples::TripleGenerationOutput;
use threshold_signatures::ecdsa::ot_based_ecdsa::{PresignArguments, presign_and_sign};
use threshold_signatures::ecdsa::{Signature, SignatureOption};
use threshold_signatures::frost_secp256k1::VerifyingKey;
use threshold_signatures::participants::Participant;
use tokio::time::timeout;

impl EcdsaSignatureProvider {
    /// Presigns online when `signature.online_presign` is set and a triple pair is available
    /// whose participants all understand [`EcdsaTaskId::OnlinePresignSignature`], else signs
    /// from a stored presignature. With the flag set and every peer on a version that
    /// understands it, all signatures take the online path.
    pub(super) async fn make_signature_leader_choosing_flow(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(Signature, VerifyingKey)> {
        let sign_request = self.sign_request_store.get(id).await?;
        let keyshare = self.keyshare(sign_request.domain)?;
        let triple_store = self.triple_store_for_t(keyshare.reconstruction_threshold)?;
        let reconstruction_threshold: usize =
            keyshare.reconstruction_threshold.inner().try_into()?;
        let supporting = self
            .client
            .participants_supporting(ONLINE_PRESIGN_MIN_PROTOCOL_VERSION);
        match choose_signing_path(
            self.config.signature.online_presign,
            &triple_store,
            supporting,
            reconstruction_threshold,
        ) {
            SigningPath::OnlinePresign {
                paired_triple_id,
                triples,
            } => {
                metrics::MPC_NUM_ECDSA_SIGNATURES_LED_BY_MODE
                    .with_label_values(&[ONLINE_PRESIGN_MODE_LABEL])
                    .inc();
                let (triple0, triple1) = *triples;
                let participants = participants_from_triples(&triple0, &triple1);
                let channel = self.new_channel_for_task(
                    EcdsaTaskId::OnlinePresignSignature {
                        id,
                        paired_triple_id,
                    },
                    participants,
                )?;
                self.make_online_presign_signature_leader_given_parameters(
                    sign_request,
                    triple0,
                    triple1,
                    channel,
                )
                .await
            }
            SigningPath::StoredPresignature => {
                metrics::MPC_NUM_ECDSA_SIGNATURES_LED_BY_MODE
                    .with_label_values(&[STORED_PRESIGNATURE_MODE_LABEL])
                    .inc();
                self.make_signature_leader(id).await
            }
        }
    }

    pub(crate) async fn make_online_presign_signature_leader_given_parameters(
        &self,
        sign_request: SignatureRequest,
        triple0: TripleGenerationOutput,
        triple1: TripleGenerationOutput,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<(Signature, VerifyingKey)> {
        let keyshare = self.keyshare(sign_request.domain)?;
        let participants = channel.participants().to_vec();
        let (signature, public_key) = OnlinePresignSignComputation {
            keygen_out: keyshare.keygen_output,
            reconstruction_threshold: reconstruction_threshold(&keyshare.reconstruction_threshold)?,
            triple0,
            triple1,
            msg_hash: ecdsa_msg_hash(&sign_request)?,
            tweak: sign_request.tweak,
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.signature.timeout_sec),
        )
        .await
        .inspect_err(|_| {
            participants.iter().for_each(|id| {
                metrics::PARTICIPANT_TOTAL_TIMES_SEEN_IN_FAILED_SIGNATURE_COMPUTATION_LEADER
                    .with_label_values(&[&id.raw().to_string()])
                    .inc();
            });
        })?;

        Ok((
            signature.context("Leader should obtain a signature")?,
            public_key,
        ))
    }

    pub(crate) async fn make_online_presign_signature_follower(
        &self,
        channel: NetworkTaskChannel,
        id: SignatureId,
        paired_triple_id: UniqueId,
    ) -> anyhow::Result<()> {
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_RECEIVED.inc();
        let sign_request = timeout(
            Duration::from_secs(self.config.signature.timeout_sec),
            self.sign_request_store.get(id),
        )
        .await??;
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED.inc();

        let keyshare = self.keyshare(sign_request.domain)?;
        let reconstruction_threshold_usize: usize =
            keyshare.reconstruction_threshold.inner().try_into()?;
        validate_follower_request(
            channel.sender().get_leader(),
            paired_triple_id,
            channel.participants().len(),
            reconstruction_threshold_usize,
            sign_request.domain,
        )?;
        let triple_store = self.triple_store_for_t(keyshare.reconstruction_threshold)?;

        let participants = channel.participants().to_vec();
        FollowerOnlinePresignSignComputation {
            keygen_out: keyshare.keygen_output,
            reconstruction_threshold: TSReconstructionThreshold::from(
                reconstruction_threshold_usize,
            ),
            triple_store,
            paired_triple_id,
            msg_hash: ecdsa_msg_hash(&sign_request)?,
            tweak: sign_request.tweak,
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.signature.timeout_sec),
        )
        .await
        .inspect_err(|_| {
            participants.iter().for_each(|id| {
                metrics::PARTICIPANT_TOTAL_TIMES_SEEN_IN_FAILED_SIGNATURE_COMPUTATION_FOLLOWER
                    .with_label_values(&[&id.raw().to_string()])
                    .inc();
            });
        })?;

        Ok(())
    }
}

/// Presigning and signing in one computation over a triple pair, for the leader and the
/// followers alike. The presignature never leaves the computation, so it is neither stored
/// nor rerandomized; the tweak still derives the signing key.
pub struct OnlinePresignSignComputation {
    pub keygen_out: KeygenOutput,
    pub reconstruction_threshold: TSReconstructionThreshold,
    pub triple0: TripleGenerationOutput,
    pub triple1: TripleGenerationOutput,
    pub msg_hash: [u8; 32],
    pub tweak: Tweak,
}

impl NamedProtocol for OnlinePresignSignComputation {
    const NAME: &'static str = "presign and sign cait-sith";
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<(SignatureOption, VerifyingKey)> for OnlinePresignSignComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<(SignatureOption, VerifyingKey)> {
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();
        let (tweak, msg_hash) = parse_tweak_and_msg_hash(&self.tweak, &self.msg_hash)?;
        let derived_public_key = tweak.derive_verifying_key(&self.keygen_out.public_key);

        let protocol = presign_and_sign(
            &cs_participants,
            channel.sender().get_leader().into(),
            channel.my_participant_id().into(),
            PresignArguments {
                triple0: self.triple0,
                triple1: self.triple1,
                keygen_out: self.keygen_out,
                threshold: self.reconstruction_threshold,
            },
            tweak,
            msg_hash,
        )?;
        let _timer = metrics::MPC_ONLINE_PRESIGN_SIGNATURE_TIME_ELAPSED.start_timer();
        let signature = Self::run(channel, protocol).await?;
        Ok((signature, derived_public_key))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// The follower side of [`OnlinePresignSignComputation`], which first has to look up its share
/// of the leader's triple pair.
pub struct FollowerOnlinePresignSignComputation {
    pub keygen_out: KeygenOutput,
    pub reconstruction_threshold: TSReconstructionThreshold,
    pub triple_store: Arc<TripleStorage>,
    pub paired_triple_id: UniqueId,
    pub msg_hash: [u8; 32],
    pub tweak: Tweak,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<()> for FollowerOnlinePresignSignComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
        let (triple0, triple1) = self.triple_store.take_unowned(self.paired_triple_id)?;
        OnlinePresignSignComputation {
            keygen_out: self.keygen_out,
            reconstruction_threshold: self.reconstruction_threshold,
            triple0,
            triple1,
            msg_hash: self.msg_hash,
            tweak: self.tweak,
        }
        .compute(channel)
        .await?;
        Ok(())
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// Which flow [`EcdsaSignatureProvider::make_signature_leader_choosing_flow`] takes for one signature.
#[derive(Debug)]
enum SigningPath {
    OnlinePresign {
        paired_triple_id: UniqueId,
        triples: Box<PairedTriple>,
    },
    StoredPresignature,
}

/// Takes a triple pair whose participants all support online presigning, if the store holds
/// one; a pair is only consumed when it will be used. Neither a node with online presigning
/// switched off nor fewer supporting participants than `t` can form such a pair, so in both
/// cases the store is not even consulted.
fn choose_signing_path(
    online_presign_enabled: bool,
    triple_store: &TripleStorage,
    supporting: Vec<ParticipantId>,
    reconstruction_threshold: usize,
) -> SigningPath {
    if !online_presign_enabled || supporting.len() < reconstruction_threshold {
        return SigningPath::StoredPresignature;
    }
    match triple_store.try_take_owned_matching(supporting) {
        Some((paired_triple_id, triples)) => SigningPath::OnlinePresign {
            paired_triple_id,
            triples: Box::new(triples),
        },
        None => SigningPath::StoredPresignature,
    }
}

/// A follower only consumes a triple pair owned by the leader, and only in a computation with
/// exactly `t` parties, which is how cait-sith triples are generated.
fn validate_follower_request(
    leader: ParticipantId,
    paired_triple_id: UniqueId,
    num_participants: usize,
    reconstruction_threshold: usize,
    domain_id: DomainId,
) -> anyhow::Result<()> {
    paired_triple_id.validate_owned_by(leader)?;
    if num_participants != reconstruction_threshold {
        metrics::MPC_NUM_BAD_PEER_ONLINE_PRESIGN_REQUESTS
            .with_label_values(&[&domain_id.to_string()])
            .inc();
        anyhow::bail!(
            "CaitSith online-presign participant count ({num_participants}) does not match \
             domain threshold t={reconstruction_threshold}",
        );
    }
    Ok(())
}

fn reconstruction_threshold(
    threshold: &ReconstructionThreshold,
) -> anyhow::Result<TSReconstructionThreshold> {
    let threshold: usize = threshold.inner().try_into()?;
    Ok(TSReconstructionThreshold::from(threshold))
}

fn ecdsa_msg_hash(sign_request: &SignatureRequest) -> anyhow::Result<[u8; 32]> {
    sign_request
        .payload
        .as_ecdsa()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("Payload is not an ECDSA payload"))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{
        OnlinePresignSignComputation, SigningPath, choose_signing_path, validate_follower_request,
    };
    use crate::assets::test_utils::make_triple;
    use crate::db::SecretDB;
    use crate::network::computation::MpcLeaderCentricComputation;
    use crate::network::testing::{new_test_client, run_test_clients};
    use crate::primitives::{ParticipantId, UniqueId};
    use crate::providers::ecdsa::triple::PairedTriple;
    use crate::providers::ecdsa::{EcdsaTaskId, TripleStorage};
    use crate::tests::into_participant_ids;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use anyhow::Context;
    use assert_matches::assert_matches;
    use k256::Scalar;
    use k256::elliptic_curve::PrimeField;
    use mpc_primitives::ReconstructionThreshold;
    use mpc_primitives::domain::DomainId;
    use near_indexer_primitives::CryptoHash;
    use near_mpc_contract_interface::types::Tweak;
    use near_time::FakeClock;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use rstest::rstest;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use threshold_signatures::ReconstructionThreshold as TSReconstructionThreshold;
    use threshold_signatures::ecdsa::KeygenOutput;
    use threshold_signatures::ecdsa::ot_based_ecdsa::triples::generate_triple_many;
    use threshold_signatures::frost_secp256k1::Secp256K1Sha256;
    use threshold_signatures::participants::Participant;
    use threshold_signatures::protocol::Protocol;
    use threshold_signatures::test_utils::{generate_participants, run_keygen, run_protocol};

    const TWEAK: [u8; 32] = [1u8; 32];
    const MSG_HASH: [u8; 32] = [2u8; 32];

    #[rstest]
    #[case::owned_by_leader_with_t_participants(1, 1, 3, 3, true)]
    #[case::owned_by_someone_else(2, 1, 3, 3, false)]
    #[case::fewer_participants_than_threshold(1, 1, 2, 3, false)]
    #[case::more_participants_than_threshold(1, 1, 4, 3, false)]
    fn validate_follower_request__should_accept_only_leader_owned_pair_with_t_participants(
        #[case] owner: u32,
        #[case] leader: u32,
        #[case] num_participants: usize,
        #[case] reconstruction_threshold: usize,
        #[case] accepted: bool,
    ) {
        // Given
        let paired_triple_id = UniqueId::new(ParticipantId::from_raw(owner), 1, 0);

        // When
        let result = validate_follower_request(
            ParticipantId::from_raw(leader),
            paired_triple_id,
            num_participants,
            reconstruction_threshold,
            DomainId(0),
        );

        // Then
        assert_eq!(result.is_ok(), accepted, "{result:?}");
    }

    /// Runs one keygen and one triple generation in-process, then hands every participant its
    /// shares so the fake-network clients only exercise the merged signing computation.
    fn deal_shares(
        participants: &[Participant],
        threshold: usize,
        rng: &mut StdRng,
    ) -> (
        KeygenOutput,
        HashMap<ParticipantId, (KeygenOutput, PairedTriple)>,
    ) {
        let keys: HashMap<Participant, KeygenOutput> =
            run_keygen::<Secp256K1Sha256, _>(participants, threshold, rng)
                .into_iter()
                .collect();
        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = _>>)> = Vec::new();
        for p in participants {
            let rng_p = StdRng::seed_from_u64(rng.next_u64());
            let protocol = generate_triple_many::<2, _, _>(
                participants,
                *p,
                TSReconstructionThreshold::from(threshold),
                rng_p,
            )
            .unwrap();
            protocols.push((*p, Box::new(protocol)));
        }
        let triples = run_protocol(protocols).unwrap();
        let public_keygen_output = keys[&participants[0]].clone();
        let shares = triples
            .into_iter()
            .map(|(p, two_triples)| {
                let pair = (two_triples[0].clone(), two_triples[1].clone());
                (p.into(), (keys[&p].clone(), pair))
            })
            .collect();
        (public_keygen_output, shares)
    }

    #[test_log::test(tokio::test(flavor = "multi_thread"))]
    async fn online_presign_computation__should_produce_signature_verifiable_under_derived_key() {
        start_root_task_with_periodic_dump(async {
            // Given
            const THRESHOLD: usize = 3;
            let mut rng = StdRng::seed_from_u64(42);
            let ts_participants = generate_participants(THRESHOLD);
            let participants = into_participant_ids(&ts_participants);
            let leader = *participants.iter().min().unwrap();
            let (keygen_output, shares) = deal_shares(&ts_participants, THRESHOLD, &mut rng);
            let shares = Arc::new(shares);

            // When
            let results = run_test_clients(participants.clone(), move |client, mut receiver| {
                let shares = shares.clone();
                let participants = participants.clone();
                async move {
                    let me = client.my_participant_id();
                    let (keygen_out, (triple0, triple1)) = shares[&me].clone();
                    let computation = OnlinePresignSignComputation {
                        keygen_out,
                        reconstruction_threshold: TSReconstructionThreshold::from(THRESHOLD),
                        triple0,
                        triple1,
                        msg_hash: MSG_HASH,
                        tweak: Tweak::new(TWEAK),
                    };
                    let channel = if me == leader {
                        client.new_channel_for_task(
                            EcdsaTaskId::OnlinePresignSignature {
                                id: CryptoHash::default(),
                                paired_triple_id: UniqueId::new(leader, 1, 0),
                            },
                            participants,
                        )?
                    } else {
                        receiver.recv().await.context("no channel received")?
                    };
                    let (signature, verifying_key) = computation
                        .perform_leader_centric_computation(channel, Duration::from_secs(60))
                        .await?;
                    Ok(signature.map(|signature| (signature, verifying_key)))
                }
            })
            .await
            .unwrap();

            // Then
            let signatures: Vec<_> = results.into_iter().flatten().collect();
            assert_eq!(signatures.len(), 1);
            let (signature, verifying_key) = &signatures[0];
            let tweak =
                threshold_signatures::ecdsa::Tweak::new(Scalar::from_repr(TWEAK.into()).unwrap());
            let expected_key = tweak.derive_verifying_key(&keygen_output.public_key);
            assert_eq!(verifying_key.to_element(), expected_key.to_element());
            let msg_hash = Scalar::from_repr(MSG_HASH.into()).unwrap();
            assert!(signature.verify(&expected_key.to_element().to_affine(), &msg_hash));
        })
        .await;
    }

    fn triple_store_with_one_pair(
        participants: &[ParticipantId],
    ) -> (Arc<TripleStorage>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let client = new_test_client(participants.to_vec(), participants[0]);
        let store = Arc::new(
            TripleStorage::new(
                FakeClock::default().clock(),
                db,
                client,
                ReconstructionThreshold::new(3),
            )
            .unwrap(),
        );
        store.add_owned(
            UniqueId::new(participants[0], 1, 0),
            make_triple(participants),
        );
        (store, dir)
    }

    #[tokio::test]
    async fn choose_signing_path__should_online_presign_when_all_pair_participants_support_it() {
        // Given
        let participants: Vec<ParticipantId> = (1..=3).map(ParticipantId::from_raw).collect();
        let (store, _dir) = triple_store_with_one_pair(&participants);

        // When
        let path = choose_signing_path(true, &store, participants, 3);

        // Then
        assert_matches!(path, SigningPath::OnlinePresign { .. });
        assert_eq!(store.num_owned(), 0);
    }

    #[tokio::test]
    async fn choose_signing_path__should_fall_back_when_a_pair_participant_runs_old_version() {
        // Given
        let participants: Vec<ParticipantId> = (1..=3).map(ParticipantId::from_raw).collect();
        let (store, _dir) = triple_store_with_one_pair(&participants);
        let supporting = vec![participants[0], participants[1], ParticipantId::from_raw(9)];

        // When
        let path = choose_signing_path(true, &store, supporting, 3);

        // Then
        assert_matches!(path, SigningPath::StoredPresignature);
        assert_eq!(store.num_owned(), 1);
    }

    #[tokio::test]
    async fn choose_signing_path__should_fall_back_without_consulting_store_below_threshold() {
        // Given
        let participants: Vec<ParticipantId> = (1..=3).map(ParticipantId::from_raw).collect();
        let (store, _dir) = triple_store_with_one_pair(&participants);

        // When
        let path = choose_signing_path(true, &store, participants[..2].to_vec(), 3);

        // Then
        assert_matches!(path, SigningPath::StoredPresignature);
        assert_eq!(store.num_owned(), 1);
    }

    #[tokio::test]
    async fn choose_signing_path__should_fall_back_without_consulting_store_when_config_disables_it()
     {
        // Given
        let participants: Vec<ParticipantId> = (1..=3).map(ParticipantId::from_raw).collect();
        let (store, _dir) = triple_store_with_one_pair(&participants);

        // When
        let path = choose_signing_path(false, &store, participants, 3);

        // Then
        assert_matches!(path, SigningPath::StoredPresignature);
        assert_eq!(store.num_owned(), 1);
    }
}
