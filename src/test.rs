// This module provides generic functions to be used
// in the implemented schemes testing cases

use rand_core::{CryptoRng, CryptoRngCore, OsRng, RngCore};
use std::error::Error;

use crate::protocol::{errors::InitializationError, run_protocol, Participant, Protocol};
use crate::{keygen, refresh, reshare, Ciphersuite, KeygenOutput, VerifyingKey};

// +++++++++++++++++ Participants Utilities +++++++++++++++++ //
/// Generates a vector of `number` participants, sorted by the participant id.
/// The participants ids range from 0 to `number`-1
pub fn generate_participants(number: usize) -> Vec<Participant> {
    (0..number)
        .map(|i| Participant::from(i as u32))
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

// +++++++++++++++++ DKG Functions +++++++++++++++++ //
type GenOutput<C> = Result<Vec<(Participant, KeygenOutput<C>)>, Box<dyn Error>>;
type GenProtocol<C> = Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput<C>>>)>;

/// Runs distributed keygen
/// If the protocol succeeds, returns a sorted vector based on participants id
pub(crate) fn run_keygen<C: Ciphersuite>(
    participants: &[Participant],
    threshold: usize,
) -> GenOutput<C>
where
    frost_core::Element<C>: Send,
    frost_core::Scalar<C>: Send,
{
    let mut protocols: GenProtocol<C> = Vec::with_capacity(participants.len());

    for p in participants {
        let protocol = keygen::<C>(participants, *p, threshold, OsRng)?;
        protocols.push((*p, Box::new(protocol)));
    }

    let mut result = run_protocol(protocols)?;
    result.sort_by_key(|(p, _)| *p);
    Ok(result)
}

/// Runs distributed refresh
/// If the protocol succeeds, returns a sorted vector based on participants id
pub(crate) fn run_refresh<C: Ciphersuite>(
    participants: &[Participant],
    keys: Vec<(Participant, KeygenOutput<C>)>,
    threshold: usize,
) -> GenOutput<C>
where
    frost_core::Element<C>: Send,
    frost_core::Scalar<C>: Send,
{
    let mut protocols: GenProtocol<C> = Vec::with_capacity(participants.len());

    for (p, out) in keys.iter() {
        let protocol = refresh::<C>(
            Some(out.private_share),
            out.public_key,
            participants,
            threshold,
            *p,
            OsRng,
        )?;
        protocols.push((*p, Box::new(protocol)));
    }

    let mut result = run_protocol(protocols)?;
    result.sort_by_key(|(p, _)| *p);
    Ok(result)
}

/// Runs distributed reshare
/// If the protocol succeeds, returns a sorted vector based on participants id
pub(crate) fn run_reshare<C: Ciphersuite>(
    participants: &[Participant],
    pub_key: &VerifyingKey<C>,
    keys: Vec<(Participant, KeygenOutput<C>)>,
    old_threshold: usize,
    new_threshold: usize,
    new_participants: Vec<Participant>,
) -> GenOutput<C>
where
    frost_core::Element<C>: Send,
    frost_core::Scalar<C>: Send,
{
    assert!(!new_participants.is_empty());
    let mut setup = vec![];

    for new_participant in &new_participants {
        let mut is_break = false;
        for (p, k) in &keys {
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

    let mut protocols: GenProtocol<C> = Vec::with_capacity(participants.len());

    for (p, out) in setup.iter() {
        let protocol = reshare(
            participants,
            old_threshold,
            out.0,
            out.1,
            &new_participants,
            new_threshold,
            *p,
            OsRng,
        )?;
        protocols.push((*p, Box::new(protocol)));
    }

    let mut result = run_protocol(protocols)?;
    result.sort_by_key(|(p, _)| *p);
    Ok(result)
}

/// Assert that each participant has the same view of the public key
pub(crate) fn assert_public_key_invariant<C: Ciphersuite>(
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
/// Only used for unit tests.
pub(crate) fn run_sign<C: Ciphersuite, PresignOutput, Signature: Clone, F>(
    participants_presign: Vec<(Participant, PresignOutput)>,
    public_key: frost_core::Element<C>,
    msg_hash: frost_core::Scalar<C>,
    sign: F,
) -> Result<Vec<(Participant, Signature)>, Box<dyn Error>>
where
    F: Fn(
        &[Participant],
        Participant,
        frost_core::Element<C>,
        PresignOutput,
        frost_core::Scalar<C>,
    ) -> Result<Box<dyn Protocol<Output = Signature>>, InitializationError>,
{
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = Signature>>)> =
        Vec::with_capacity(participants_presign.len());

    let participants: Vec<Participant> = participants_presign.iter().map(|(p, _)| *p).collect();
    let participants = participants.as_slice();
    for (p, presignature) in participants_presign.into_iter() {
        let protocol = sign(participants, p, public_key, presignature, msg_hash)?;

        protocols.push((p, protocol));
    }

    Ok(run_protocol(protocols)?)
}

// Taken from https://rust-random.github.io/book/guide-test-fn-rng.html
#[derive(Clone, Copy, Debug)]
pub struct MockCryptoRng {
    data: [u8; 8],
    index: usize,
}

impl MockCryptoRng {
    pub fn new(data: [u8; 8]) -> MockCryptoRng {
        MockCryptoRng { data, index: 0 }
    }
}

impl CryptoRng for MockCryptoRng {}

impl RngCore for MockCryptoRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = self.data[self.index];
            self.index = (self.index + 1) % self.data.len();
        }
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        unimplemented!()
    }
}
