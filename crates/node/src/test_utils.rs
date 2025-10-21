// TODO(#1318) this utilities should be moved to the threshold_signatures repo
/// Convenient test utilities to generate keys, triples, presignatures, and signatures.
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, Scalar};
use rand::rngs::OsRng;
use std::collections::HashMap;
use threshold_signatures::confidential_key_derivation as ckd;
use threshold_signatures::ecdsa::ot_based_ecdsa::triples::TripleGenerationOutput;
use threshold_signatures::ecdsa::ot_based_ecdsa::PresignOutput;
use threshold_signatures::ecdsa::ot_based_ecdsa::{PresignArguments, RerandomizedPresignOutput};
use threshold_signatures::ecdsa::{RerandomizationArguments, Signature};
use threshold_signatures::frost_ed25519::Ed25519Sha512;
use threshold_signatures::frost_secp256k1::{Secp256K1Sha256, VerifyingKey};
use threshold_signatures::protocol::{run_protocol, Participant, Protocol};
use threshold_signatures::{ecdsa, eddsa, keygen, ParticipantList};

use crate::primitives::ParticipantId;

pub struct TestGenerators {
    pub participants: Vec<Participant>,
    pub threshold: usize,
}

type ParticipantAndProtocol<T> = (Participant, Box<dyn Protocol<Output = T>>);

impl TestGenerators {
    pub fn new(num_participants: usize, threshold: usize) -> Self {
        Self {
            participants: (0..num_participants)
                .map(|_| Participant::from(rand::random::<u32>()))
                .collect::<Vec<_>>(),
            threshold,
        }
    }

    pub fn new_contiguous_participant_ids(num_participants: usize, threshold: usize) -> Self {
        Self {
            participants: (0..num_participants)
                .map(|i| Participant::from(i as u32))
                .collect::<Vec<_>>(),
            threshold,
        }
    }

    pub fn participant_ids(&self) -> Vec<ParticipantId> {
        self.participants.iter().map(|p| (*p).into()).collect()
    }

    pub fn make_ecdsa_keygens(&self) -> HashMap<Participant, ecdsa::KeygenOutput> {
        let mut protocols: Vec<ParticipantAndProtocol<ecdsa::KeygenOutput>> = Vec::new();
        for participant in &self.participants {
            protocols.push((
                *participant,
                Box::new(
                    keygen::<Secp256K1Sha256>(
                        &self.participants,
                        *participant,
                        self.threshold,
                        OsRng,
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_eddsa_keygens(&self) -> HashMap<Participant, eddsa::KeygenOutput> {
        let mut protocols: Vec<ParticipantAndProtocol<eddsa::KeygenOutput>> = Vec::new();
        for participant in &self.participants {
            protocols.push((
                *participant,
                Box::new(
                    keygen::<Ed25519Sha512>(
                        &self.participants,
                        *participant,
                        self.threshold,
                        OsRng,
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_ckd_keygens(&self) -> HashMap<Participant, ckd::KeygenOutput> {
        let mut protocols: Vec<ParticipantAndProtocol<ckd::KeygenOutput>> = Vec::new();
        for participant in &self.participants {
            protocols.push((
                *participant,
                Box::new(
                    keygen::<ckd::BLS12381SHA256>(
                        &self.participants,
                        *participant,
                        self.threshold,
                        OsRng,
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_triples(&self) -> HashMap<Participant, TripleGenerationOutput> {
        let mut protocols: Vec<ParticipantAndProtocol<TripleGenerationOutput>> = Vec::new();
        for participant in &self.participants {
            protocols.push((
                *participant,
                Box::new(
                    ecdsa::ot_based_ecdsa::triples::generate_triple(
                        &self.participants,
                        *participant,
                        self.threshold,
                        OsRng,
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
    ) -> HashMap<Participant, PresignOutput> {
        let mut protocols: Vec<ParticipantAndProtocol<PresignOutput>> = Vec::new();
        for participant in &self.participants {
            protocols.push((
                *participant,
                Box::new(
                    ecdsa::ot_based_ecdsa::presign::presign(
                        &self.participants,
                        *participant,
                        PresignArguments {
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
        presignatures: &HashMap<Participant, PresignOutput>,
        public_key: AffinePoint,
        msg_hash: Scalar,
    ) -> Signature {
        let mut protocols: Vec<ParticipantAndProtocol<Option<Signature>>> = Vec::new();
        let leader = self.participants[0];
        for participant in &self.participants {
            let msg_hash_bytes: [u8; 32] = msg_hash.to_bytes().into();
            let presign_out = presignatures[participant].clone();
            let entropy = [0u8; 32];

            let tweak = [1u8; 32];
            let tweak = Scalar::from_repr(tweak.into()).unwrap();
            let tweak = threshold_signatures::Tweak::new(tweak);

            let public_key = tweak
                .derive_verifying_key(&VerifyingKey::new(public_key.into()))
                .to_element()
                .to_affine();

            let rerand_args = RerandomizationArguments::new(
                public_key,
                msg_hash_bytes,
                presign_out.big_r,
                ParticipantList::new(&self.participants).unwrap(),
                entropy,
            );

            let rerandomized_presignature =
                RerandomizedPresignOutput::new(&presign_out, &tweak, &rerand_args).unwrap();

            protocols.push((
                *participant,
                Box::new(
                    ecdsa::ot_based_ecdsa::sign::sign(
                        &self.participants,
                        leader,
                        *participant,
                        public_key,
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
