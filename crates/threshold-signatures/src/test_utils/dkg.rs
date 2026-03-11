use rand::SeedableRng;
use rand_core::CryptoRngCore;

use crate::participants::Participant;
use crate::test_utils::{run_protocol, GenOutput, GenProtocol};
use crate::thresholds::ReconstructionLowerBound;
use crate::{keygen, refresh, reshare, Ciphersuite, Element, KeygenOutput, Scalar, VerifyingKey};

// +++++++++++++++++ DKG Functions +++++++++++++++++ //
type DKGGenProtocol<C> = GenProtocol<KeygenOutput<C>>;

/// Runs distributed keygen
/// If the protocol succeeds, returns a sorted vector based on participants id
/// Runs distributed keygen
/// If the protocol succeeds, returns a sorted vector based on participants id
pub fn run_keygen<C: Ciphersuite, R: CryptoRngCore + SeedableRng + Send + 'static>(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound> + Copy + Send + 'static,
    rng: &mut R,
) -> GenOutput<C>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let mut protocols: DKGGenProtocol<C> = Vec::with_capacity(participants.len());

    for p in participants {
        let rng_p = R::seed_from_u64(rng.next_u64());
        let protocol = keygen::<C>(participants, *p, threshold, rng_p).unwrap();
        protocols.push((*p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

/// Runs distributed refresh
/// If the protocol succeeds, returns a sorted vector based on participants id
pub fn run_refresh<C: Ciphersuite, R: CryptoRngCore + SeedableRng + Send + 'static>(
    participants: &[Participant],
    keys: &[(Participant, KeygenOutput<C>)],
    threshold: impl Into<ReconstructionLowerBound> + Copy + Send + 'static,
    rng: &mut R,
) -> GenOutput<C>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let mut protocols: DKGGenProtocol<C> = Vec::with_capacity(participants.len());

    for (p, out) in keys {
        let rng_p = R::seed_from_u64(rng.next_u64());
        let protocol = refresh::<C>(
            Some(out.private_share),
            out.public_key,
            participants,
            threshold,
            *p,
            rng_p,
        )
        .unwrap();
        protocols.push((*p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

/// Runs distributed reshare
/// If the protocol succeeds, returns a sorted vector based on participants id
pub fn run_reshare<C: Ciphersuite, R: CryptoRngCore + SeedableRng + Send + 'static>(
    participants: &[Participant],
    pub_key: &VerifyingKey<C>,
    keys: &[(Participant, KeygenOutput<C>)],
    old_threshold: impl Into<ReconstructionLowerBound> + Copy + Send + 'static,
    new_threshold: impl Into<ReconstructionLowerBound> + Copy + Send + 'static,
    new_participants: &[Participant],
    rng: &mut R,
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
        let rng_p = R::seed_from_u64(rng.next_u64());
        let protocol = reshare(
            participants,
            old_threshold,
            out.0,
            out.1,
            new_participants,
            new_threshold,
            *p,
            rng_p,
        )
        .unwrap();
        protocols.push((*p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
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
