use rand::SeedableRng;
use rand_core::CryptoRngCore;

use frost_core::{Field, Group, keys::SigningShare};

use crate::crypto::polynomials::Polynomial;
use crate::participants::Participant;
#[cfg(test)]
use crate::test_utils::participants::generate_participants_with_random_ids;
use crate::test_utils::{GenOutput, GenProtocol, run_protocol};
use crate::thresholds::ReconstructionThreshold;
use crate::{Ciphersuite, KeygenOutput, Scalar, VerifyingKey, keygen, refresh, reshare};

// +++++++++++++++++ DKG Functions +++++++++++++++++ //
type DKGGenProtocol<C> = GenProtocol<KeygenOutput<C>>;

/// Runs distributed keygen
/// If the protocol succeeds, returns a sorted vector based on participants id
/// Runs distributed keygen
/// If the protocol succeeds, returns a sorted vector based on participants id
pub fn run_keygen<C: Ciphersuite, R: CryptoRngCore + SeedableRng + Send + 'static>(
    participants: &[Participant],
    threshold: impl Into<ReconstructionThreshold> + Copy + Send + 'static,
    rng: &mut R,
) -> GenOutput<C> {
    let mut protocols: DKGGenProtocol<C> = Vec::with_capacity(participants.len());

    for p in participants {
        let rng_p = R::seed_from_u64(rng.next_u64());
        let protocol = keygen::<C, _, _>(participants, *p, threshold, rng_p).unwrap();
        protocols.push((*p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

/// Deals key shares for a *supplied* master secret, acting as a trusted dealer.
pub fn deal_keygen_outputs<C: Ciphersuite>(
    secret: Scalar<C>,
    participants: &[Participant],
    threshold: impl Into<ReconstructionThreshold>,
    rng: &mut impl CryptoRngCore,
) -> GenOutput<C> {
    let degree = threshold.into().value() - 1;
    let (f, pk) = generate_test_keys_with_secret(secret, degree, rng);
    participants
        .iter()
        .map(|p| (*p, make_keygen_output(&f, &pk, *p)))
        .collect()
}

/// Runs distributed refresh
/// If the protocol succeeds, returns a sorted vector based on participants id
pub fn run_refresh<C: Ciphersuite, R: CryptoRngCore + SeedableRng + Send + 'static>(
    participants: &[Participant],
    keys: &[(Participant, KeygenOutput<C>)],
    threshold: impl Into<ReconstructionThreshold> + Copy + Send + 'static,
    rng: &mut R,
) -> GenOutput<C> {
    let mut protocols: DKGGenProtocol<C> = Vec::with_capacity(participants.len());

    for (p, out) in keys {
        let rng_p = R::seed_from_u64(rng.next_u64());
        let protocol = refresh::<C, _, _>(
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
    old_threshold: impl Into<ReconstructionThreshold> + Copy + Send + 'static,
    new_threshold: impl Into<ReconstructionThreshold> + Copy + Send + 'static,
    new_participants: &[Participant],
    rng: &mut R,
) -> GenOutput<C> {
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

/// Generates a random polynomial of given degree and derives the corresponding
/// public verifying key. Returns both the polynomial (for per-participant share
/// derivation) and the verifying key.
pub fn generate_test_keys<C: Ciphersuite>(
    degree: usize,
    rng: &mut impl CryptoRngCore,
) -> (Polynomial<C>, VerifyingKey<C>) {
    let secret = <C::Group as Group>::Field::random(rng);
    generate_test_keys_with_secret(secret, degree, rng)
}

/// Like [`generate_test_keys`] but pins the polynomial's constant term to
/// `secret`, so the reconstructed master secret is known in advance.
pub fn generate_test_keys_with_secret<C: Ciphersuite>(
    secret: Scalar<C>,
    degree: usize,
    rng: &mut impl CryptoRngCore,
) -> (Polynomial<C>, VerifyingKey<C>) {
    let f = Polynomial::<C>::generate_polynomial(Some(secret), degree, rng).unwrap();
    (
        f,
        VerifyingKey::new(<C::Group as Group>::generator() * secret),
    )
}

/// Constructs a [`KeygenOutput`] for a single participant from a shared
/// polynomial and public verifying key.
pub fn make_keygen_output<C: Ciphersuite>(
    f: &Polynomial<C>,
    pk: &VerifyingKey<C>,
    p: Participant,
) -> KeygenOutput<C> {
    KeygenOutput {
        private_share: SigningShare::new(f.eval_at_participant(p).unwrap().0),
        public_key: *pk,
    }
}

/// Centralized key generation for testing: generates random participant IDs
/// and creates `KeygenOutput` for each using polynomial evaluation.
#[cfg(test)]
pub fn build_frost_key_packages_with_dealer<C: Ciphersuite>(
    max_signers: u16,
    min_signers: u16,
    rng: &mut impl CryptoRngCore,
) -> GenOutput<C> {
    let participants = generate_participants_with_random_ids(max_signers as usize, rng);
    let (f, pk) = generate_test_keys::<C>((min_signers - 1) as usize, rng);
    participants
        .iter()
        .map(|p| (*p, make_keygen_output(&f, &pk, *p)))
        .collect()
}
