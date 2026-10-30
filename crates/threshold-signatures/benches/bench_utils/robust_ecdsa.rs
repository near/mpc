//! Benchmarks the Robust ECDSA stub, not a real scheme: its presigning is a single
//! broadcast round, so these numbers are a lower bound on what a replacement scheme
//! could cost rather than a comparison against OT-based ECDSA.

use std::collections::HashMap;

use rand::Rng;
use rand_core::{CryptoRngCore, SeedableRng};

use threshold_signatures::{
    ecdsa::{
        self,
        robust_ecdsa::{PresignArguments, presign_and_sign},
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{MockCryptoRng, generate_participants_with_random_ids, run_keygen},
};

use super::MAX_MALICIOUS;

/// Used to prepare robust ecdsa signatures for benchmarking
pub fn robust_ecdsa_prepare_sign<R: CryptoRngCore + SeedableRng + Send + 'static>(
    num_participants: usize,
    rng: &mut R,
) -> RobustECDSAPreparedSig {
    let participants = generate_participants_with_random_ids(num_participants, rng);
    let key_packages = run_keygen(&participants, *MAX_MALICIOUS + 1, rng);
    let coordinator = participants[rng.gen_range(0..participants.len())];
    let tweak = ecdsa::Tweak::new(frost_core::random_nonzero::<ecdsa::Secp256K1Sha256, _>(rng));
    let msg_hash = frost_core::random_nonzero::<ecdsa::Secp256K1Sha256, _>(rng);

    let mut protocols: Vec<_> = Vec::with_capacity(participants.len());
    let mut seeds = HashMap::with_capacity(participants.len());
    for (p, keygen_out) in &key_packages {
        let seed = rng.next_u64();
        let protocol = presign_and_sign(
            &participants,
            coordinator,
            *p,
            PresignArguments {
                keygen_out: keygen_out.clone(),
                max_malicious: (*MAX_MALICIOUS).into(),
            },
            tweak,
            msg_hash,
            MockCryptoRng::seed_from_u64(seed),
        )
        .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = ecdsa::SignatureOption>>)
        .expect("Signing should succeed");
        protocols.push((*p, protocol));
        seeds.insert(*p, seed);
    }
    RobustECDSAPreparedSig {
        protocols,
        key_packages,
        participants,
        coordinator,
        tweak,
        msg_hash,
        seeds,
    }
}

pub struct RobustECDSAPreparedSig {
    pub protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = ecdsa::SignatureOption>>,
    )>,
    pub key_packages: Vec<(Participant, ecdsa::KeygenOutput)>,
    pub participants: Vec<Participant>,
    pub coordinator: Participant,
    pub tweak: ecdsa::Tweak,
    pub msg_hash: ecdsa::Scalar,
    /// Per-participant RNG seed used to build each sign protocol.
    pub seeds: HashMap<Participant, u64>,
}
