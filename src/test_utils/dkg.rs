use rand_core::OsRng;

use crate::participants::Participant;
use crate::test_utils::{run_protocol, GenOutput, GenProtocol};
use crate::{keygen, refresh, reshare, Ciphersuite, Element, KeygenOutput, Scalar, VerifyingKey};

// +++++++++++++++++ DKG Functions +++++++++++++++++ //
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
