// This module provides generic functions to be used
// in the implemented schemes testing cases
#![allow(
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

use k256::elliptic_curve::PrimeField;
use k256::AffinePoint;
use rand_core::{CryptoRngCore, OsRng};
use std::collections::HashMap;
use std::error::Error;

use crate::confidential_key_derivation as ckd;
use crate::ecdsa::ot_based_ecdsa::triples::TripleGenerationOutput;
use crate::errors::{InitializationError, ProtocolError};
use crate::frost_ed25519::Ed25519Sha512;
use crate::frost_secp256k1::Secp256K1Sha256;
use crate::participants::Participant;
use crate::protocol::{Action, Protocol};
use crate::{ecdsa, eddsa, ParticipantList};
use crate::{keygen, refresh, reshare, Ciphersuite, Element, KeygenOutput, Scalar, VerifyingKey};

pub type GenProtocol<C> = Vec<(Participant, Box<dyn Protocol<Output = C>>)>;
use rand::{CryptoRng, RngCore};
use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng};

// +++++++++++++++++ General Utilities +++++++++++++++++ //
pub struct MockCryptoRng(ChaCha12Rng);

impl MockCryptoRng {
    pub fn seed_from_u64(seed: u64) -> Self {
        Self(ChaCha12Rng::seed_from_u64(seed))
    }
}

impl RngCore for MockCryptoRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for MockCryptoRng {}

pub fn random_32_bytes(rng: &mut impl CryptoRngCore) -> [u8; 32] {
    let mut bytes: [u8; 32] = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

// +++++++++++++++++ Participants Utilities +++++++++++++++++ //
/// Generates a vector of `number` participants, sorted by the participant id.
/// The participants ids range from 0 to `number`-1
pub fn generate_participants(number: usize) -> Vec<Participant> {
    (0..u32::try_from(number).unwrap())
        .map(Participant::from)
        .collect::<Vec<_>>()
}

/// Generates a vector of `number` participants, sorted by the participant id.
/// The participants ids are drawn from rng.
pub fn generate_participants_with_random_ids(
    number: usize,
    rng: &mut impl CryptoRngCore,
) -> Vec<Participant> {
    let mut participants = (0..number)
        .map(|_| Participant::from(rng.next_u32()))
        .collect::<Vec<_>>();
    participants.sort();
    participants
}

// +++++++++++++++++ Any Protocol +++++++++++++++++ //
/// Run a protocol to completion, synchronously.
///
/// This works by executing each participant in order.
///
/// The reason this function exists is as a convenient testing utility.
/// In practice each protocol participant is likely running on a different machine,
/// and so orchestrating the protocol would happen differently.
pub fn run_protocol<T>(
    mut ps: Vec<(Participant, Box<dyn Protocol<Output = T>>)>,
) -> Result<Vec<(Participant, T)>, ProtocolError> {
    let indices: HashMap<Participant, usize> =
        ps.iter().enumerate().map(|(i, (p, _))| (*p, i)).collect();

    let size = ps.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            while {
                let action = ps[i].1.poke()?;
                match action {
                    Action::Wait => false,
                    Action::SendMany(m) => {
                        for j in 0..size {
                            if i == j {
                                continue;
                            }
                            let from = ps[i].0;
                            ps[j].1.message(from, m.clone());
                        }
                        true
                    }
                    Action::SendPrivate(to, m) => {
                        let from = ps[i].0;
                        ps[indices[&to]].1.message(from, m);
                        true
                    }
                    Action::Return(r) => {
                        out.push((ps[i].0, r));
                        false
                    }
                }
            } {}
        }
    }
    Ok(out)
}

/// Like [`run_protocol()`], except for just two parties.
///
/// This is more useful for testing two party protocols with assymetric results,
/// since the return types for the two protocols can be different.
pub fn run_two_party_protocol<T0: std::fmt::Debug, T1: std::fmt::Debug>(
    p0: Participant,
    p1: Participant,
    prot0: &mut dyn Protocol<Output = T0>,
    prot1: &mut dyn Protocol<Output = T1>,
) -> Result<(T0, T1), ProtocolError> {
    let mut active0 = true;

    let mut out0 = None;
    let mut out1 = None;

    while out0.is_none() || out1.is_none() {
        if active0 {
            let action = prot0.poke()?;
            match action {
                Action::Wait => active0 = false,
                Action::SendMany(m) => prot1.message(p0, m),
                Action::SendPrivate(to, m) if to == p1 => {
                    prot1.message(p0, m);
                }
                Action::Return(out) => out0 = Some(out),
                // Ignore other actions, which means sending private messages to other people.
                Action::SendPrivate(..) => {}
            }
        } else {
            let action = prot1.poke()?;
            match action {
                Action::Wait => active0 = true,
                Action::SendMany(m) => prot0.message(p1, m),
                Action::SendPrivate(to, m) if to == p0 => {
                    prot0.message(p1, m);
                }
                Action::Return(out) => out1 = Some(out),
                // Ignore other actions, which means sending private messages to other people.
                Action::SendPrivate(..) => {}
            }
        }
    }

    Ok((
        out0.ok_or_else(|| ProtocolError::Other("out0 is None".to_string()))?,
        out1.ok_or_else(|| ProtocolError::Other("out1 is None".to_string()))?,
    ))
}

// +++++++++++++++++ DKG Functions +++++++++++++++++ //
pub type GenOutput<C> = Vec<(Participant, KeygenOutput<C>)>;
type DKGGenProtocol<C> = GenProtocol<KeygenOutput<C>>;

/// Runs distributed keygen
/// If the protocol succeeds, returns a sorted vector based on participants id
pub fn run_keygen<C: Ciphersuite>(participants: &[Participant], threshold: usize) -> GenOutput<C>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let mut protocols: DKGGenProtocol<C> = Vec::with_capacity(participants.len());

    for p in participants {
        let protocol = keygen::<C>(participants, *p, threshold, OsRng).unwrap();
        protocols.push((*p, Box::new(protocol)));
    }

    let mut result = run_protocol(protocols).unwrap();
    result.sort_by_key(|(p, _)| *p);
    result
}

/// Runs distributed refresh
/// If the protocol succeeds, returns a sorted vector based on participants id
pub fn run_refresh<C: Ciphersuite>(
    participants: &[Participant],
    keys: &[(Participant, KeygenOutput<C>)],
    threshold: usize,
) -> GenOutput<C>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let mut protocols: DKGGenProtocol<C> = Vec::with_capacity(participants.len());

    for (p, out) in keys {
        let protocol = refresh::<C>(
            Some(out.private_share),
            out.public_key,
            participants,
            threshold,
            *p,
            OsRng,
        )
        .unwrap();
        protocols.push((*p, Box::new(protocol)));
    }

    let mut result = run_protocol(protocols).unwrap();
    result.sort_by_key(|(p, _)| *p);
    result
}

/// Runs distributed reshare
/// If the protocol succeeds, returns a sorted vector based on participants id
pub fn run_reshare<C: Ciphersuite>(
    participants: &[Participant],
    pub_key: &VerifyingKey<C>,
    keys: &[(Participant, KeygenOutput<C>)],
    old_threshold: usize,
    new_threshold: usize,
    new_participants: &[Participant],
) -> GenOutput<C>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    assert!(!new_participants.is_empty());
    let mut setup = vec![];

    for new_participant in new_participants {
        let mut is_break = false;
        for (p, k) in keys {
            if p == new_participant {
                setup.push((*p, (Some(k.private_share), k.public_key)));
                is_break = true;
                break;
            }
        }
        if !is_break {
            setup.push((*new_participant, (None, *pub_key)));
        }
    }

    let mut protocols: DKGGenProtocol<C> = Vec::with_capacity(participants.len());

    for (p, out) in &setup {
        let protocol = reshare(
            participants,
            old_threshold,
            out.0,
            out.1,
            new_participants,
            new_threshold,
            *p,
            OsRng,
        )
        .unwrap();
        protocols.push((*p, Box::new(protocol)));
    }

    let mut result = run_protocol(protocols).unwrap();
    result.sort_by_key(|(p, _)| *p);
    result
}

/// Assert that each participant has the same view of the public key
pub fn assert_public_key_invariant<C: Ciphersuite>(
    participants: &[(Participant, KeygenOutput<C>)],
) {
    let vk = participants.first().unwrap().1.public_key;

    if participants
        .iter()
        .any(|(_, key_pair)| key_pair.public_key != vk)
    {
        panic!("public key package is not the same for all participants");
    }
}

// +++++++++++++++++ Signing Functions +++++++++++++++++ //
/// Runs the signing algorithm for ECDSA.
/// The scheme must be asymmetric as in: there exists a coordinator that is different than participants.
/// Only used for unit tests.
pub fn run_sign<C: Ciphersuite, PresignOutput, Signature: Clone, F>(
    participants_presign: Vec<(Participant, PresignOutput)>,
    coordinator: Participant,
    public_key: Element<C>,
    msg_hash: Scalar<C>,
    sign: F,
) -> Result<Vec<(Participant, Signature)>, Box<dyn Error>>
where
    F: Fn(
        &[Participant],
        Participant,
        Participant,
        Element<C>,
        PresignOutput,
        Scalar<C>,
    ) -> Result<Box<dyn Protocol<Output = Signature>>, InitializationError>,
{
    let mut protocols: GenProtocol<Signature> = Vec::with_capacity(participants_presign.len());

    let participants: Vec<Participant> = participants_presign.iter().map(|(p, _)| *p).collect();
    let participants = participants.as_slice();
    for (p, presignature) in participants_presign {
        let protocol = sign(
            participants,
            coordinator,
            p,
            public_key,
            presignature,
            msg_hash,
        )?;

        protocols.push((p, protocol));
    }

    Ok(run_protocol(protocols)?)
}

/// Checks that the list contains all None but one element
/// and verifies such element belongs to the coordinator
pub fn one_coordinator_output<ProtocolOutput: Clone>(
    all_sigs: Vec<(Participant, Option<ProtocolOutput>)>,
    coordinator: Participant,
) -> Result<ProtocolOutput, ProtocolError> {
    let mut some_iter = all_sigs.into_iter().filter(|(_, sig)| sig.is_some());

    // test there is at least one not None element
    let (p, c_opt) = some_iter
        .next()
        .ok_or(ProtocolError::MismatchCoordinatorOutput)?;

    // test the coordinator is the one owning the output
    if coordinator != p {
        return Err(ProtocolError::MismatchCoordinatorOutput);
    }

    // test the participant is unique
    let out = c_opt.ok_or(ProtocolError::MismatchCoordinatorOutput)?;

    if some_iter.next().is_some() {
        return Err(ProtocolError::MismatchCoordinatorOutput);
    }
    Ok(out)
}

// Taken from https://github.com/ZcashFoundation/frost/blob/3ffc19d8f473d5bc4e07ed41bc884bdb42d6c29f/frost-secp256k1/tests/common_traits_tests.rs#L9
#[allow(clippy::unnecessary_literal_unwrap)]
pub fn check_common_traits_for_type<T: Clone + Eq + PartialEq + std::fmt::Debug>(v: &T) {
    // Make sure can be debug-printed. This also catches if the Debug does not
    // have an endless recursion (a popular mistake).
    println!("{v:?}");
    // Test Clone and Eq
    assert_eq!(*v, v.clone());
    // Make sure it can be unwrapped in a Result (which requires Debug).
    let e: Result<T, ()> = Ok(v.clone());
    assert_eq!(*v, e.unwrap());
}

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
