// This module provides generic functions to be used in the mpc repository
use k256::elliptic_curve::PrimeField;
use k256::AffinePoint;
use rand::SeedableRng;
use rand_core::CryptoRngCore;
use std::collections::HashMap;

use crate::ecdsa::ot_based_ecdsa::triples::TripleGenerationOutput;
use crate::frost_ed25519::Ed25519Sha512;
use crate::frost_secp256k1::Secp256K1Sha256;
use crate::participants::Participant;
use crate::protocol::Protocol;
use crate::{confidential_key_derivation as ckd, ReconstructionLowerBound};
use crate::{ecdsa, frost, ParticipantList};
use crate::{keygen, VerifyingKey};

use crate::test_utils::run_protocol;

pub struct TestGenerators {
    pub participants: Vec<Participant>,
    pub threshold: ReconstructionLowerBound,
}

type ParticipantAndProtocol<T> = (Participant, Box<dyn Protocol<Output = T>>);

impl TestGenerators {
    pub fn new(num_participants: usize, threshold: ReconstructionLowerBound) -> Self {
        Self {
            participants: (0..num_participants)
                .map(|_| Participant::from(rand::random::<u32>()))
                .collect::<Vec<_>>(),
            threshold,
        }
    }

    pub fn new_contiguous_participant_ids(
        num_participants: usize,
        threshold: ReconstructionLowerBound,
    ) -> Self {
        Self {
            participants: (0..num_participants)
                .map(|i| Participant::from(i as u32))
                .collect::<Vec<_>>(),
            threshold,
        }
    }

    pub fn make_ecdsa_keygens<R: CryptoRngCore + SeedableRng + Send + 'static>(
        &self,
        rng: &mut R,
    ) -> HashMap<Participant, ecdsa::KeygenOutput> {
        let mut protocols: Vec<ParticipantAndProtocol<ecdsa::KeygenOutput>> = Vec::new();
        for participant in &self.participants {
            let rng_p = R::seed_from_u64(rng.next_u64());
            protocols.push((
                *participant,
                Box::new(
                    keygen::<Secp256K1Sha256>(
                        &self.participants,
                        *participant,
                        self.threshold,
                        rng_p,
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_eddsa_keygens<R: CryptoRngCore + SeedableRng + Send + 'static>(
        &self,
        rng: &mut R,
    ) -> HashMap<Participant, frost::eddsa::KeygenOutput> {
        let mut protocols: Vec<ParticipantAndProtocol<frost::eddsa::KeygenOutput>> = Vec::new();
        for participant in &self.participants {
            let rng_p = R::seed_from_u64(rng.next_u64());
            protocols.push((
                *participant,
                Box::new(
                    keygen::<Ed25519Sha512>(
                        &self.participants,
                        *participant,
                        self.threshold,
                        rng_p,
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_ckd_keygens<R: CryptoRngCore + SeedableRng + Send + 'static>(
        &self,
        rng: &mut R,
    ) -> HashMap<Participant, ckd::KeygenOutput> {
        let mut protocols: Vec<ParticipantAndProtocol<ckd::KeygenOutput>> = Vec::new();
        for participant in &self.participants {
            let rng_p = R::seed_from_u64(rng.next_u64());
            protocols.push((
                *participant,
                Box::new(
                    keygen::<ckd::BLS12381SHA256>(
                        &self.participants,
                        *participant,
                        self.threshold,
                        rng_p,
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_triples<R: CryptoRngCore + SeedableRng + Send + Clone + 'static>(
        &self,
        rng: &mut R,
    ) -> HashMap<Participant, TripleGenerationOutput> {
        let mut protocols: Vec<ParticipantAndProtocol<TripleGenerationOutput>> = Vec::new();
        for participant in &self.participants {
            let rng_p = R::seed_from_u64(rng.next_u64());
            protocols.push((
                *participant,
                Box::new(
                    ecdsa::ot_based_ecdsa::triples::generate_triple(
                        &self.participants,
                        *participant,
                        self.threshold,
                        rng_p,
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_presignatures(
        &self,
        triple0s: &HashMap<Participant, TripleGenerationOutput>,
        triple1s: &HashMap<Participant, TripleGenerationOutput>,
        keygens: &HashMap<Participant, ecdsa::KeygenOutput>,
    ) -> HashMap<Participant, ecdsa::ot_based_ecdsa::PresignOutput> {
        let mut protocols: Vec<ParticipantAndProtocol<ecdsa::ot_based_ecdsa::PresignOutput>> =
            Vec::new();
        for participant in &self.participants {
            protocols.push((
                *participant,
                Box::new(
                    ecdsa::ot_based_ecdsa::presign::presign(
                        &self.participants,
                        *participant,
                        ecdsa::ot_based_ecdsa::PresignArguments {
                            triple0: triple0s[participant].clone(),
                            triple1: triple1s[participant].clone(),
                            keygen_out: keygens[participant].clone(),
                            threshold: self.threshold,
                        },
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_signature(
        &self,
        threshold: ReconstructionLowerBound,
        presignatures: &HashMap<Participant, ecdsa::ot_based_ecdsa::PresignOutput>,
        public_key: AffinePoint,
        msg_hash: ecdsa::Scalar,
    ) -> ecdsa::Signature {
        let mut protocols: Vec<ParticipantAndProtocol<Option<ecdsa::Signature>>> = Vec::new();
        let leader = self.participants[0];
        for participant in &self.participants {
            let msg_hash_bytes: [u8; 32] = msg_hash.to_bytes().into();
            let presign_out = presignatures[participant].clone();
            let entropy = [0u8; 32];

            let tweak = [1u8; 32];
            let tweak = ecdsa::Scalar::from_repr(tweak.into()).unwrap();
            let tweak = crate::Tweak::new(tweak);

            let rerand_args = ecdsa::RerandomizationArguments::new(
                public_key,
                tweak,
                msg_hash_bytes,
                presign_out.big_r,
                ParticipantList::new(&self.participants).unwrap(),
                entropy,
            );

            let derived_public_key = tweak
                .derive_verifying_key(&VerifyingKey::new(public_key.into()))
                .to_element()
                .to_affine();

            let rerandomized_presignature =
                ecdsa::ot_based_ecdsa::RerandomizedPresignOutput::rerandomize_presign(
                    &presign_out,
                    &rerand_args,
                )
                .unwrap();

            protocols.push((
                *participant,
                Box::new(
                    ecdsa::ot_based_ecdsa::sign::sign(
                        &self.participants,
                        leader,
                        threshold,
                        *participant,
                        derived_public_key,
                        rerandomized_presignature,
                        msg_hash,
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols)
            .unwrap()
            .iter()
            .find_map(|(p, sig)| if *p == leader { Some(sig) } else { None })
            .unwrap()
            .as_ref()
            .unwrap()
            .clone()
    }
}
