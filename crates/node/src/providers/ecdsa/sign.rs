use crate::metrics;
use crate::network::NetworkTaskChannel;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::primitives::{ParticipantId, UniqueId};
use crate::protocol::run_protocol;
use crate::providers::ecdsa::presign::PresignOutputWithParticipants;
use crate::providers::ecdsa::triple::{PairedTriple, participants_from_triples};
use crate::providers::ecdsa::{
    EcdsaSignatureProvider, EcdsaTaskId, KeygenOutput, ONLINE_PRESIGN_MIN_PROTOCOL_VERSION,
    PresignatureStorage, TripleStorage,
};
use crate::types::{SignatureId, SignatureRequest};
use anyhow::Context;
use k256::Scalar;
use k256::elliptic_curve::PrimeField;
use mpc_primitives::domain::DomainId;
use near_mpc_contract_interface::types::Tweak;
use std::sync::Arc;
use std::time::Duration;
use threshold_signatures::ParticipantList;
use threshold_signatures::ReconstructionThreshold;
use threshold_signatures::ecdsa::ot_based_ecdsa::{
    PresignArguments, PresignOutput, RerandomizedPresignOutput, presign_and_sign,
};
use threshold_signatures::ecdsa::{RerandomizationArguments, Signature, SignatureOption};
use threshold_signatures::frost_secp256k1::VerifyingKey;
use threshold_signatures::participants::Participant;
use tokio::time::timeout;

/// What a signature is computed from. The two variants differ only in how the presignature is
/// obtained; everything around them (key derivation, the signing round, failure propagation) is
/// shared.
pub enum SigningMaterial {
    /// A presignature generated ahead of time and taken from storage. `entropy` rerandomizes
    /// it (inspired by \[[GS21](https://eprint.iacr.org/2021/1330.pdf)\]).
    Presignature {
        presign_out: PresignOutput,
        entropy: [u8; 32],
    },
    /// A triple pair presigned within this computation. The presignature never leaves the
    /// computation, so it is neither stored nor rerandomized.
    Triples(Box<PairedTriple>),
}

impl SigningMaterial {
    /// Value of the `mode` label on [`metrics::MPC_NUM_ECDSA_SIGNATURES_LED_BY_MODE`].
    fn mode(&self) -> &'static str {
        match self {
            SigningMaterial::Presignature { .. } => "stored_presignature",
            SigningMaterial::Triples(_) => "online_presign",
        }
    }

    /// Name the protocol run is tagged with in tracking progress.
    fn protocol_name(&self) -> &'static str {
        match self {
            SigningMaterial::Presignature { .. } => "sign cait-sith",
            SigningMaterial::Triples(_) => "presign and sign cait-sith",
        }
    }
}

/// Where a follower takes its share of the leader's material from. Resolved inside the
/// computation because the lookup may fail.
pub enum FollowerSigningMaterial {
    Presignature {
        store: Arc<PresignatureStorage>,
        presignature_id: UniqueId,
        entropy: [u8; 32],
    },
    Triples {
        store: Arc<TripleStorage>,
        paired_triple_id: UniqueId,
    },
}

impl EcdsaSignatureProvider {
    /// Presigns online when a triple pair is available whose participants all understand
    /// [`EcdsaTaskId::OnlinePresignSignature`], else signs from a stored presignature. Once
    /// every node runs a version that understands it, all signatures take the online path.
    pub(super) async fn make_signature_leader(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(Signature, VerifyingKey)> {
        let sign_request = self.sign_request_store.get(id).await?;
        let keyshare = self.keyshare(sign_request.domain)?;

        let online_presign = all_live_participants_support(
            &self.client.all_alive_participant_ids(),
            &self
                .client
                .participants_supporting(ONLINE_PRESIGN_MIN_PROTOCOL_VERSION),
        );

        let (task_id, participants, material) = if online_presign {
            let triple_store = self.triple_store_for_t(keyshare.reconstruction_threshold)?;
            let (paired_triple_id, triples) = triple_store.take_owned().await;
            (
                EcdsaTaskId::OnlinePresignSignature {
                    id,
                    paired_triple_id,
                },
                participants_from_triples(&triples.0, &triples.1),
                SigningMaterial::Triples(Box::new(triples)),
            )
        } else {
            let (presignature_id, presignature) = keyshare.presignature_store.take_owned().await;
            (
                EcdsaTaskId::Signature {
                    id,
                    presignature_id,
                },
                presignature.participants,
                SigningMaterial::Presignature {
                    presign_out: presignature.presignature,
                    entropy: sign_request.entropy,
                },
            )
        };

        metrics::MPC_NUM_ECDSA_SIGNATURES_LED_BY_MODE
            .with_label_values(&[material.mode()])
            .inc();
        let channel = self.new_channel_for_task(task_id, participants)?;
        self.make_signature_leader_given_material(sign_request, material, channel)
            .await
    }

    pub(crate) async fn make_signature_leader_given_parameters(
        &self,
        sign_request: SignatureRequest,
        presignature: PresignOutputWithParticipants,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<(Signature, VerifyingKey)> {
        let material = SigningMaterial::Presignature {
            presign_out: presignature.presignature,
            entropy: sign_request.entropy,
        };
        self.make_signature_leader_given_material(sign_request, material, channel)
            .await
    }

    async fn make_signature_leader_given_material(
        &self,
        sign_request: SignatureRequest,
        material: SigningMaterial,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<(Signature, VerifyingKey)> {
        let keyshare = self.keyshare(sign_request.domain)?;
        let participants = channel.participants().to_vec();

        let (signature, public_key) = SignComputation {
            keygen_out: keyshare.keygen_output,
            reconstruction_threshold: reconstruction_threshold(keyshare.reconstruction_threshold)?,
            material,
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

    pub(crate) async fn make_signature_follower_given_request(
        &self,
        channel: NetworkTaskChannel,
        presignature_id: UniqueId,
        sign_request: SignatureRequest,
    ) -> anyhow::Result<()> {
        // The presignature must be owned by the leader, never one of ours.
        presignature_id.validate_owned_by(channel.sender().get_leader())?;
        let keyshare = self.keyshare(sign_request.domain)?;
        let material = FollowerSigningMaterial::Presignature {
            store: keyshare.presignature_store.clone(),
            presignature_id,
            entropy: sign_request.entropy,
        };
        self.make_signature_follower_given_material(sign_request, material, channel)
            .await
    }

    pub(crate) async fn make_signature_follower(
        &self,
        channel: NetworkTaskChannel,
        id: SignatureId,
        presignature_id: UniqueId,
    ) -> anyhow::Result<()> {
        let sign_request = self.await_sign_request(id).await?;
        self.make_signature_follower_given_request(channel, presignature_id, sign_request)
            .await
    }

    pub(crate) async fn make_online_presign_signature_follower(
        &self,
        channel: NetworkTaskChannel,
        id: SignatureId,
        paired_triple_id: UniqueId,
    ) -> anyhow::Result<()> {
        let sign_request = self.await_sign_request(id).await?;
        let keyshare = self.keyshare(sign_request.domain)?;
        let reconstruction_threshold: usize =
            keyshare.reconstruction_threshold.inner().try_into()?;
        validate_follower_request(
            channel.sender().get_leader(),
            paired_triple_id,
            channel.participants().len(),
            reconstruction_threshold,
            sign_request.domain,
        )?;
        let material = FollowerSigningMaterial::Triples {
            store: self.triple_store_for_t(keyshare.reconstruction_threshold)?,
            paired_triple_id,
        };
        self.make_signature_follower_given_material(sign_request, material, channel)
            .await
    }

    async fn await_sign_request(&self, id: SignatureId) -> anyhow::Result<SignatureRequest> {
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_RECEIVED.inc();
        let sign_request = timeout(
            Duration::from_secs(self.config.signature.timeout_sec),
            self.sign_request_store.get(id),
        )
        .await??;
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED.inc();
        Ok(sign_request)
    }

    async fn make_signature_follower_given_material(
        &self,
        sign_request: SignatureRequest,
        material: FollowerSigningMaterial,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<()> {
        let keyshare = self.keyshare(sign_request.domain)?;
        let participants = channel.participants().to_vec();

        FollowerSignComputation {
            keygen_out: keyshare.keygen_output,
            reconstruction_threshold: reconstruction_threshold(keyshare.reconstruction_threshold)?,
            material,
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

/// Performs an MPC signature operation. This is the same for the initiator and for passive
/// participants. The tweak allows key derivation; how the presignature is obtained is
/// [`SigningMaterial`].
pub struct SignComputation {
    pub keygen_out: KeygenOutput,
    pub reconstruction_threshold: ReconstructionThreshold,
    pub material: SigningMaterial,
    pub msg_hash: [u8; 32],
    pub tweak: Tweak,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<(SignatureOption, VerifyingKey)> for SignComputation {
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
        let leader = channel.sender().get_leader().into();
        let me = channel.my_participant_id().into();

        let (tweak, msg_hash) = parse_tweak_and_msg_hash(&self.tweak, &self.msg_hash)?;
        let derived_public_key = tweak.derive_verifying_key(&self.keygen_out.public_key);
        let name = self.material.protocol_name();

        let signature = match self.material {
            SigningMaterial::Presignature {
                presign_out,
                entropy,
            } => {
                let rerand_args = RerandomizationArguments::new(
                    self.keygen_out.public_key.to_element().to_affine(),
                    tweak,
                    self.msg_hash,
                    presign_out.big_r,
                    ParticipantList::new(&cs_participants).unwrap(),
                    entropy,
                );
                let rerandomized_presignature =
                    RerandomizedPresignOutput::rerandomize_presign(&presign_out, &rerand_args)?;
                let protocol = threshold_signatures::ecdsa::ot_based_ecdsa::sign::sign(
                    &cs_participants,
                    leader,
                    self.reconstruction_threshold,
                    me,
                    derived_public_key.to_element().to_affine(),
                    rerandomized_presignature,
                    msg_hash,
                )?;
                let _timer = metrics::MPC_SIGNATURE_TIME_ELAPSED.start_timer();
                run_protocol(name, channel, protocol).await?
            }
            SigningMaterial::Triples(triples) => {
                let (triple0, triple1) = *triples;
                let protocol = presign_and_sign(
                    &cs_participants,
                    leader,
                    me,
                    PresignArguments {
                        triple0,
                        triple1,
                        keygen_out: self.keygen_out,
                        threshold: self.reconstruction_threshold,
                    },
                    tweak,
                    msg_hash,
                )?;
                let _timer = metrics::MPC_ONLINE_PRESIGN_SIGNATURE_TIME_ELAPSED.start_timer();
                run_protocol(name, channel, protocol).await?
            }
        };

        Ok((signature, derived_public_key))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// Performs an MPC signature operation as a follower. The difference is that the follower needs
/// to look up its share of the leader's material, which may fail.
pub struct FollowerSignComputation {
    pub keygen_out: KeygenOutput,
    pub reconstruction_threshold: ReconstructionThreshold,
    pub material: FollowerSigningMaterial,
    pub msg_hash: [u8; 32],
    pub tweak: Tweak,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<()> for FollowerSignComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
        let material = match self.material {
            FollowerSigningMaterial::Presignature {
                store,
                presignature_id,
                entropy,
            } => SigningMaterial::Presignature {
                presign_out: store.take_unowned(presignature_id)?.presignature,
                entropy,
            },
            FollowerSigningMaterial::Triples {
                store,
                paired_triple_id,
            } => SigningMaterial::Triples(Box::new(store.take_unowned(paired_triple_id)?)),
        };
        SignComputation {
            keygen_out: self.keygen_out,
            reconstruction_threshold: self.reconstruction_threshold,
            material,
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

/// Converts the on-chain tweak and payload hash into the scalars the signing protocols take.
pub(super) fn parse_tweak_and_msg_hash(
    tweak: &Tweak,
    msg_hash: &[u8; 32],
) -> anyhow::Result<(threshold_signatures::ecdsa::Tweak, Scalar)> {
    let tweak = Scalar::from_repr(tweak.as_bytes().into())
        .into_option()
        .context("Couldn't construct k256 scalar from tweak")?;
    let msg_hash = Scalar::from_repr((*msg_hash).into())
        .into_option()
        .context("Couldn't construct k256 scalar from message hash")?;
    Ok((threshold_signatures::ecdsa::Tweak::new(tweak), msg_hash))
}

/// Whether every participant we can currently compute with is new enough. The asset stores only
/// hand out assets all of whose participants are live, so this decides up front that whatever
/// they hand back is usable with the newer protocol, without having to filter the take itself.
fn all_live_participants_support(alive: &[ParticipantId], supporting: &[ParticipantId]) -> bool {
    alive
        .iter()
        .all(|participant| supporting.contains(participant))
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
    threshold: mpc_primitives::ReconstructionThreshold,
) -> anyhow::Result<ReconstructionThreshold> {
    let threshold: usize = threshold.inner().try_into()?;
    Ok(ReconstructionThreshold::from(threshold))
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
        SignComputation, SigningMaterial, all_live_participants_support, validate_follower_request,
    };
    use crate::network::computation::MpcLeaderCentricComputation;
    use crate::network::testing::run_test_clients;
    use crate::primitives::{ParticipantId, UniqueId};
    use crate::providers::ecdsa::EcdsaTaskId;
    use crate::providers::ecdsa::triple::PairedTriple;
    use crate::tests::into_participant_ids;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use anyhow::Context;
    use k256::Scalar;
    use k256::elliptic_curve::PrimeField;
    use mpc_primitives::domain::DomainId;
    use near_indexer_primitives::CryptoHash;
    use near_mpc_contract_interface::types::Tweak;
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
    /// shares so the fake-network clients only exercise the signing computation.
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
    async fn sign_computation__should_online_presign_a_signature_verifiable_under_the_derived_key()
    {
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
                    let (keygen_out, triples) = shares[&me].clone();
                    let computation = SignComputation {
                        keygen_out,
                        reconstruction_threshold: TSReconstructionThreshold::from(THRESHOLD),
                        material: SigningMaterial::Triples(Box::new(triples)),
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

    #[rstest]
    #[case::every_live_participant_is_new_enough(&[1, 2, 3], &[1, 2, 3], true)]
    #[case::a_live_participant_is_too_old(&[1, 2, 3], &[1, 2], false)]
    #[case::a_supporting_participant_is_not_live(&[1, 2], &[1, 2, 3], true)]
    #[case::nobody_supports_it(&[1, 2, 3], &[], false)]
    fn all_live_participants_support__should_hold_only_when_no_live_participant_is_too_old(
        #[case] alive: &[u32],
        #[case] supporting: &[u32],
        #[case] expected: bool,
    ) {
        // Given
        let alive: Vec<ParticipantId> =
            alive.iter().copied().map(ParticipantId::from_raw).collect();
        let supporting: Vec<ParticipantId> = supporting
            .iter()
            .copied()
            .map(ParticipantId::from_raw)
            .collect();

        // When
        let result = all_live_participants_support(&alive, &supporting);

        // Then
        assert_eq!(result, expected);
    }
}
