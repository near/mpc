// This module provides generic functions to be used
// in the implemented schemes testing cases

use rand_core::{OsRng, RngCore};
use std::error::Error;

use crate::protocol::{run_protocol, Participant, Protocol};
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
/// The participants ids are drawn from OsRng.
pub fn generate_participants_with_random_ids(number: usize) -> Vec<Participant> {
    let mut participants = (0..number)
        .map(|_| Participant::from(OsRng.next_u32()))
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
        let protocol = keygen::<C>(participants, *p, threshold)?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
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
        )?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
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
        )?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
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
