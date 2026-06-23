use std::collections::HashMap;

use rand_core::{CryptoRngCore, SeedableRng};

use threshold_signatures::{
    Ciphersuite, KeygenOutput, ReconstructionThreshold, keygen,
    participants::Participant,
    protocol::Protocol,
    test_utils::{MockCryptoRng, generate_participants_with_random_ids},
};

/// Used to prepare DKG keygen protocols for benchmarking
pub fn prepare_dkg<C: Ciphersuite, R: CryptoRngCore + SeedableRng + Send + 'static>(
    num_participants: usize,
    threshold: ReconstructionThreshold,
    rng: &mut R,
) -> PreparedDkgPackage<C>
where
    threshold_signatures::Element<C>: Send,
    threshold_signatures::Scalar<C>: Send,
{
    let participants = generate_participants_with_random_ids(num_participants, rng);
    let mut protocols = Vec::with_capacity(num_participants);
    let mut seeds = HashMap::with_capacity(num_participants);

    for p in &participants {
        let seed = rng.next_u64();
        let rng_p = MockCryptoRng::seed_from_u64(seed);
        let protocol = keygen::<C, _, _>(&participants, *p, threshold, rng_p)
            .map(|p| Box::new(p) as Box<dyn Protocol<Output = KeygenOutput<C>>>)
            .expect("Keygen should succeed");
        protocols.push((*p, protocol));
        seeds.insert(*p, seed);
    }

    PreparedDkgPackage { protocols, seeds }
}

pub type DkgProtocols<C> = Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput<C>>>)>;

pub struct PreparedDkgPackage<C: Ciphersuite> {
    pub protocols: DkgProtocols<C>,
    pub seeds: HashMap<Participant, u64>,
}
