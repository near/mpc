use rand_core::{CryptoRngCore, SeedableRng};

use threshold_signatures::{
    keygen,
    participants::Participant,
    protocol::Protocol,
    test_utils::{generate_participants_with_random_ids, MockCryptoRng},
    Ciphersuite, KeygenOutput, ReconstructionLowerBound,
};

/// Used to prepare DKG keygen protocols for benchmarking
pub fn prepare_dkg<C: Ciphersuite, R: CryptoRngCore + SeedableRng + Send + 'static>(
    num_participants: usize,
    threshold: ReconstructionLowerBound,
    rng: &mut R,
) -> PreparedDkgPackage<C>
where
    threshold_signatures::Element<C>: Send,
    threshold_signatures::Scalar<C>: Send,
{
    let participants = generate_participants_with_random_ids(num_participants, rng);
    let mut protocols = Vec::with_capacity(num_participants);

    for p in &participants {
        let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
        let protocol = keygen::<C>(&participants, *p, threshold, rng_p)
            .map(|p| Box::new(p) as Box<dyn Protocol<Output = KeygenOutput<C>>>)
            .expect("Keygen should succeed");
        protocols.push((*p, protocol));
    }

    protocols
}

pub type PreparedDkgPackage<C> = Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput<C>>>)>;
