use crate::metrics;
use crate::metrics::{ONLINE_PRESIGN_MODE_LABEL, STORED_PRESIGNATURE_MODE_LABEL};
use crate::network::NetworkTaskChannel;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::wire_format::EcdsaTaskId;
use crate::primitives::UniqueId;
use crate::protocol::NamedProtocol;
use crate::providers::ecdsa::presign::PresignOutputWithParticipants;
use crate::providers::ecdsa::triple::{
    PairedTriple, participants_from_triples, validate_paired_triple_request,
};
use crate::providers::ecdsa::{
    EcdsaKeyshare, EcdsaSignatureProvider, KeygenOutput, ONLINE_PRESIGN_MIN_PROTOCOL_VERSION,
    PresignatureStorage, TripleStorage,
};
use crate::types::{SignatureId, SignatureRequest};
use anyhow::Context;
use futures::FutureExt;
use k256::Scalar;
use k256::elliptic_curve::PrimeField;
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

impl EcdsaSignatureProvider {
    pub(crate) async fn make_signature_leader_given_parameters(
        &self,
        sign_request: SignatureRequest,
        presignature: PresignOutputWithParticipants,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<(Signature, VerifyingKey)> {
        let keyshare = self.keyshare(sign_request.domain)?;
        let participants = presignature.participants.clone();
        let reconstruction_threshold: usize =
            keyshare.reconstruction_threshold.inner().try_into()?;
        let reconstruction_threshold = ReconstructionThreshold::from(reconstruction_threshold);

        let (signature, public_key) = SignComputation {
            keygen_out: keyshare.keygen_output,
            reconstruction_threshold,
            presign_out: presignature.presignature,
            msg_hash: *sign_request
                .payload
                .as_ecdsa()
                .ok_or_else(|| anyhow::anyhow!("Payload is not an ECDSA payload"))?,
            tweak: sign_request.tweak,
            entropy: sign_request.entropy,
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

    pub(super) async fn make_signature_leader(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(Signature, VerifyingKey)> {
        let sign_request = self.sign_request_store.get(id).await?;
        let keyshare = self.keyshare(sign_request.domain)?;
        if self.config.signature.online_presign
            && let Some((paired_triple_id, triples)) =
                self.try_take_triples_among_supporters(&keyshare)?
        {
            metrics::MPC_NUM_ECDSA_SIGNATURES_LED_BY_MODE
                .with_label_values(&[ONLINE_PRESIGN_MODE_LABEL])
                .inc();
            return self
                .make_online_presign_signature_leader(
                    id,
                    sign_request,
                    keyshare,
                    paired_triple_id,
                    triples,
                )
                .await;
        }
        metrics::MPC_NUM_ECDSA_SIGNATURES_LED_BY_MODE
            .with_label_values(&[STORED_PRESIGNATURE_MODE_LABEL])
            .inc();
        let (presignature_id, presignature) = keyshare.presignature_store.take_owned().await;
        let participants = presignature.participants.clone();
        let channel = self.new_channel_for_task(
            EcdsaTaskId::Signature {
                id,
                presignature_id,
            },
            participants,
        )?;
        self.make_signature_leader_given_parameters(sign_request, presignature, channel)
            .await
    }

    // TODO(#4529): remove once a single cait-sith signing variant remains.
    fn try_take_triples_among_supporters(
        &self,
        keyshare: &EcdsaKeyshare,
    ) -> anyhow::Result<Option<(UniqueId, PairedTriple)>> {
        let supporting = self
            .client
            .participants_supporting(ONLINE_PRESIGN_MIN_PROTOCOL_VERSION);
        Ok(self
            .triple_store_for_t(keyshare.reconstruction_threshold)?
            .take_owned_matching(supporting)
            .now_or_never())
    }

    async fn make_online_presign_signature_leader(
        &self,
        id: SignatureId,
        sign_request: SignatureRequest,
        keyshare: EcdsaKeyshare,
        paired_triple_id: UniqueId,
        triples: PairedTriple,
    ) -> anyhow::Result<(Signature, VerifyingKey)> {
        let reconstruction_threshold: usize =
            keyshare.reconstruction_threshold.inner().try_into()?;
        let participants = participants_from_triples(&triples.0, &triples.1);
        let channel = self.new_channel_for_task(
            EcdsaTaskId::OnlinePresignSignature {
                id,
                paired_triple_id,
            },
            participants.clone(),
        )?;

        let (signature, public_key) = OnlinePresignSignComputation {
            keygen_out: keyshare.keygen_output,
            reconstruction_threshold: ReconstructionThreshold::from(reconstruction_threshold),
            triples,
            msg_hash: *sign_request
                .payload
                .as_ecdsa()
                .ok_or_else(|| anyhow::anyhow!("Payload is not an ECDSA payload"))?,
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
        let reconstruction_threshold: usize =
            keyshare.reconstruction_threshold.inner().try_into()?;
        validate_paired_triple_request(
            channel.sender().get_leader(),
            paired_triple_id,
            channel.participants().len(),
            reconstruction_threshold,
            &metrics::MPC_NUM_BAD_PEER_ONLINE_PRESIGN_REQUESTS,
            sign_request.domain,
        )?;
        let triple_store = self.triple_store_for_t(keyshare.reconstruction_threshold)?;

        let participants = channel.participants().to_vec();
        OnlinePresignFollowerSignComputation {
            keygen_out: keyshare.keygen_output,
            reconstruction_threshold: ReconstructionThreshold::from(reconstruction_threshold),
            paired_triple_id,
            triple_store,
            msg_hash: *sign_request
                .payload
                .as_ecdsa()
                .ok_or_else(|| anyhow::anyhow!("Payload is not an ECDSA payload"))?,
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

    pub(crate) async fn make_signature_follower_given_request(
        &self,
        channel: NetworkTaskChannel,
        presignature_id: UniqueId,
        sign_request: SignatureRequest,
    ) -> anyhow::Result<()> {
        // The presignature must be owned by the leader, never one of ours.
        presignature_id.validate_owned_by(channel.sender().get_leader())?;
        let keyshare = self.keyshare(sign_request.domain)?;
        let reconstruction_threshold: usize =
            keyshare.reconstruction_threshold.inner().try_into()?;
        let reconstruction_threshold = ReconstructionThreshold::from(reconstruction_threshold);

        let participants = channel.participants().to_vec();
        FollowerSignComputation {
            keygen_out: keyshare.keygen_output,
            reconstruction_threshold,
            presignature_store: keyshare.presignature_store.clone(),
            presignature_id,
            msg_hash: *sign_request
                .payload
                .as_ecdsa()
                .ok_or_else(|| anyhow::anyhow!("Payload is not an ECDSA payload"))?,
            tweak: sign_request.tweak,
            entropy: sign_request.entropy,
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

    pub(crate) async fn make_signature_follower(
        &self,
        channel: NetworkTaskChannel,
        id: SignatureId,
        presignature_id: UniqueId,
    ) -> anyhow::Result<()> {
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_RECEIVED.inc();
        let sign_request = timeout(
            Duration::from_secs(self.config.signature.timeout_sec),
            self.sign_request_store.get(id),
        )
        .await??;
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED.inc();

        self.make_signature_follower_given_request(channel, presignature_id, sign_request)
            .await
    }
}

/// Performs an MPC signature operation. This is the same for the initiator
/// and for passive participants.
/// The entropy is used to rerandomize the presignature (inspired by
/// \[[GS21](https://eprint.iacr.org/2021/1330.pdf)\])
/// The tweak allows key derivation
pub struct SignComputation {
    pub keygen_out: KeygenOutput,
    pub reconstruction_threshold: ReconstructionThreshold,
    pub presign_out: PresignOutput,
    pub msg_hash: [u8; 32],
    pub tweak: Tweak,
    pub entropy: [u8; 32],
}

impl NamedProtocol for SignComputation {
    const NAME: &'static str = "sign cait-sith";
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

        let tweak = Scalar::from_repr(self.tweak.as_bytes().into())
            .into_option()
            .context("Couldn't construct k256 point")?;
        let tweak = threshold_signatures::Tweak::new(tweak);

        let msg_hash = Scalar::from_repr(self.msg_hash.into())
            .into_option()
            .context("Couldn't construct k256 point")?;

        let derived_public_key = tweak
            .derive_verifying_key(&self.keygen_out.public_key)
            .to_element()
            .to_affine();
        let participants = ParticipantList::new(&cs_participants).unwrap();

        let rerand_args = RerandomizationArguments::new(
            self.keygen_out.public_key.to_element().to_affine(),
            tweak,
            self.msg_hash,
            self.presign_out.big_r,
            participants,
            self.entropy,
        );
        let rerandomized_presignature =
            RerandomizedPresignOutput::rerandomize_presign(&self.presign_out, &rerand_args)?;

        let protocol = threshold_signatures::ecdsa::ot_based_ecdsa::sign::sign(
            &cs_participants,
            channel.sender().get_leader().into(),
            self.reconstruction_threshold,
            channel.my_participant_id().into(),
            derived_public_key,
            rerandomized_presignature,
            msg_hash,
        )?;
        let _timer = metrics::MPC_SIGNATURE_TIME_ELAPSED.start_timer();
        let signature = Self::run(channel, protocol).await?;
        Ok((signature, VerifyingKey::new(derived_public_key.into())))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// Performs an MPC signature operation as a follower.
/// The difference is that the follower needs to look up the presignature, which may fail.
pub struct FollowerSignComputation {
    pub keygen_out: KeygenOutput,
    pub reconstruction_threshold: ReconstructionThreshold,
    pub presignature_id: UniqueId,
    pub presignature_store: Arc<PresignatureStorage>,
    pub msg_hash: [u8; 32],
    pub tweak: Tweak,
    pub entropy: [u8; 32],
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<()> for FollowerSignComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
        let presign_out = self
            .presignature_store
            .take_unowned(self.presignature_id)?
            .presignature;
        SignComputation {
            keygen_out: self.keygen_out,
            reconstruction_threshold: self.reconstruction_threshold,
            presign_out,
            msg_hash: self.msg_hash,
            tweak: self.tweak,
            entropy: self.entropy,
        }
        .compute(channel)
        .await?;
        Ok(())
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

pub struct OnlinePresignSignComputation {
    pub keygen_out: KeygenOutput,
    pub reconstruction_threshold: ReconstructionThreshold,
    pub triples: PairedTriple,
    pub msg_hash: [u8; 32],
    pub tweak: Tweak,
}

impl NamedProtocol for OnlinePresignSignComputation {
    const NAME: &'static str = "online presign cait-sith";
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

        let tweak = Scalar::from_repr(self.tweak.as_bytes().into())
            .into_option()
            .context("Couldn't construct k256 scalar from tweak")?;
        let tweak = threshold_signatures::Tweak::new(tweak);

        let msg_hash = Scalar::from_repr(self.msg_hash.into())
            .into_option()
            .context("Couldn't construct k256 scalar from message hash")?;

        let derived_public_key = tweak.derive_verifying_key(&self.keygen_out.public_key);
        let (triple0, triple1) = self.triples;

        let protocol = presign_and_sign(
            &cs_participants,
            channel.sender().get_leader().into(),
            channel.my_participant_id().into(),
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
        let signature = Self::run(channel, protocol).await?;
        Ok((signature, derived_public_key))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// [`OnlinePresignSignComputation`] as a follower, which first has to look up its shares of the
/// leader's triple pair; that may fail.
pub struct OnlinePresignFollowerSignComputation {
    pub keygen_out: KeygenOutput,
    pub reconstruction_threshold: ReconstructionThreshold,
    pub paired_triple_id: UniqueId,
    pub triple_store: Arc<TripleStorage>,
    pub msg_hash: [u8; 32],
    pub tweak: Tweak,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<()> for OnlinePresignFollowerSignComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
        let triples = self.triple_store.take_unowned(self.paired_triple_id)?;
        OnlinePresignSignComputation {
            keygen_out: self.keygen_out,
            reconstruction_threshold: self.reconstruction_threshold,
            triples,
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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::OnlinePresignSignComputation;
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
    use near_indexer_primitives::CryptoHash;
    use near_mpc_contract_interface::types::Tweak;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use threshold_signatures::ReconstructionThreshold as TSReconstructionThreshold;
    use threshold_signatures::ecdsa::KeygenOutput;
    use threshold_signatures::frost_secp256k1::Secp256K1Sha256;
    use threshold_signatures::participants::Participant;
    use threshold_signatures::test_utils::{deal_triple, generate_participants, run_keygen};

    const TWEAK: [u8; 32] = [1u8; 32];
    const MSG_HASH: [u8; 32] = [2u8; 32];

    /// Deals a key and a triple pair to every participant, so the fake-network clients only
    /// exercise the signing computation.
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
        let (pub0, shares0) = deal_triple(rng, participants, threshold.into()).unwrap();
        let (pub1, shares1) = deal_triple(rng, participants, threshold.into()).unwrap();
        let public_keygen_output = keys[&participants[0]].clone();
        let shares = participants
            .iter()
            .zip(shares0)
            .zip(shares1)
            .map(|((p, share0), share1)| {
                let pair = ((share0, pub0.clone()), (share1, pub1.clone()));
                ((*p).into(), (keys[p].clone(), pair))
            })
            .collect();
        (public_keygen_output, shares)
    }

    #[test_log::test(tokio::test(flavor = "multi_thread"))]
    async fn online_presign_sign_computation__should_produce_a_signature_verifiable_under_the_derived_key()
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
                    let computation = OnlinePresignSignComputation {
                        keygen_out,
                        reconstruction_threshold: TSReconstructionThreshold::from(THRESHOLD),
                        triples,
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
}
