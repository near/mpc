use std::collections::HashMap;

use rand::Rng;
use rand_core::{CryptoRngCore, SeedableRng};

use threshold_signatures::{
    ReconstructionThreshold,
    confidential_key_derivation::{
        self as ckd,
        ciphersuite::{Field as _, Group as _},
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{MockCryptoRng, generate_participants_with_random_ids, run_keygen},
};

use super::MAX_MALICIOUS;

pub fn prepare_ckd<R: CryptoRngCore + SeedableRng + Send + 'static>(
    threshold: ReconstructionThreshold,
    rng: &mut R,
) -> PreparedCkdPackage {
    let num_participants = threshold.value();
    // collect all participants
    let participants = generate_participants_with_random_ids(num_participants, rng);
    let key_packages = run_keygen(&participants, *MAX_MALICIOUS + 1, rng);

    // choose a coordinator at random
    let coordinator_index = rng.gen_range(0..num_participants);
    let coordinator = participants[coordinator_index];

    let mut protocols = Vec::with_capacity(participants.len());
    let mut seeds = HashMap::with_capacity(participants.len());

    let mut app_id: [u8; 32] = [0u8; 32];
    rng.fill_bytes(&mut app_id);
    let app_id = ckd::AppId::try_new(app_id).expect("cannot fail");

    let scalar_rng = MockCryptoRng::seed_from_u64(rng.next_u64());
    let app_sk = ckd::Scalar::random(scalar_rng);
    let app_pk = ckd::ElementG1::generator() * app_sk;

    for (p, keygen_out) in &key_packages {
        let seed = rng.next_u64();
        let rng_p = MockCryptoRng::seed_from_u64(seed);
        let protocol = ckd::protocol::ckd(
            &participants,
            coordinator,
            *p,
            keygen_out.clone(),
            app_id.clone(),
            app_pk,
            rng_p,
        )
        .map(|ckd| Box::new(ckd) as Box<dyn Protocol<Output = ckd::CKDOutputOption>>)
        .expect("Ckd should succeed");
        protocols.push((*p, protocol));
        seeds.insert(*p, seed);
    }

    PreparedCkdPackage {
        protocols,
        index: coordinator_index,
        key_packages,
        app_id,
        app_pk,
        seeds,
    }
}

pub struct PreparedCkdPackage {
    pub protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = ckd::CKDOutputOption>>,
    )>,
    pub index: usize,
    pub key_packages: Vec<(Participant, ckd::KeygenOutput)>,
    pub app_id: ckd::AppId,
    pub app_pk: ckd::ElementG1,
    pub seeds: HashMap<Participant, u64>,
}
