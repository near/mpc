use std::collections::HashMap;

use rand::Rng;
use rand_core::{CryptoRngCore, SeedableRng};

use threshold_signatures::{
    ReconstructionThreshold,
    ecdsa::{
        self,
        ot_based_ecdsa::{
            SignArguments, sign,
            triples::{TriplePub, TripleShare, generate_triple_many},
        },
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{MockCryptoRng, generate_participants_with_random_ids, run_keygen},
};

/// Used to prepare ot based ecdsa triples for benchmarking
pub fn ot_ecdsa_prepare_triples<R: CryptoRngCore + SeedableRng + Send + 'static>(
    participant_num: usize,
    threshold: ReconstructionThreshold,
    rng: &mut R,
) -> OTECDSAPreparedTriples {
    let mut protocols: Vec<(_, Box<dyn Protocol<Output = _>>)> =
        Vec::with_capacity(participant_num);
    let participants = generate_participants_with_random_ids(participant_num, rng);
    let mut seeds = HashMap::with_capacity(participant_num);

    for p in &participants {
        let seed = rng.next_u64();
        let rng_p = MockCryptoRng::seed_from_u64(seed);
        let protocol = generate_triple_many(&participants, *p, threshold, 2, rng_p)
            .expect("Triple generation should succeed");
        protocols.push((*p, Box::new(protocol)));
        seeds.insert(*p, seed);
    }
    OTECDSAPreparedTriples {
        protocols,
        participants,
        seeds,
    }
}

/// Used to prepare ot based ecdsa signatures for benchmarking, each consuming a pair of triples
pub fn ot_ecdsa_prepare_sign<R: CryptoRngCore + SeedableRng + Send + 'static>(
    two_triples: &[(Participant, Vec<(TripleShare, TriplePub)>)],
    threshold: ReconstructionThreshold,
    rng: &mut R,
) -> OTECDSAPreparedSig {
    let mut two_triples = two_triples.to_owned();
    two_triples.sort_by_key(|(p, _)| *p);

    // collect all participants
    let participants: Vec<Participant> = two_triples
        .iter()
        .map(|(participant, _)| *participant)
        .collect();

    let (shares, pubs): (Vec<_>, Vec<_>) = two_triples.into_iter().flat_map(|(_, vec)| vec).unzip();
    // split shares into shares0 and shares 1 and pubs into pubs0 and pubs1
    let (shares0, shares1) = split_even_odd(shares);
    // split shares into shares0 and shares 1 and pubs into pubs0 and pubs1
    let (pub0, pub1) = split_even_odd(pubs);

    let key_packages = run_keygen(&participants, threshold, rng);
    let coordinator = participants[rng.gen_range(0..participants.len())];
    let tweak = ecdsa::Tweak::new(frost_core::random_nonzero::<ecdsa::Secp256K1Sha256, _>(rng));
    let msg_hash = frost_core::random_nonzero::<ecdsa::Secp256K1Sha256, _>(rng);

    let mut protocols: Vec<_> = Vec::with_capacity(participants.len());

    for (((p, keygen_out), share0), share1) in
        key_packages.clone().into_iter().zip(shares0).zip(shares1)
    {
        let protocol = sign(
            &participants,
            coordinator,
            p,
            SignArguments {
                triple0: (share0, pub0[0].clone()),
                triple1: (share1, pub1[0].clone()),
                keygen_out,
                threshold,
            },
            tweak,
            msg_hash,
        )
        .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = ecdsa::SignatureOption>>)
        .expect("Signing should succeed");
        protocols.push((p, protocol));
    }
    OTECDSAPreparedSig {
        protocols,
        key_packages,
        participants,
        coordinator,
        tweak,
        msg_hash,
    }
}

pub fn split_even_odd<T: Clone>(v: Vec<T>) -> (Vec<T>, Vec<T>) {
    let mut even = Vec::with_capacity(v.len() / 2 + 1);
    let mut odd = Vec::with_capacity(v.len() / 2);
    for (i, x) in v.into_iter().enumerate() {
        if i.is_multiple_of(2) {
            even.push(x);
        } else {
            odd.push(x);
        }
    }
    (even, odd)
}

type TriplesProtocols = Vec<(
    Participant,
    Box<dyn Protocol<Output = Vec<(TripleShare, TriplePub)>>>,
)>;
pub struct OTECDSAPreparedTriples {
    pub protocols: TriplesProtocols,
    pub participants: Vec<Participant>,
    pub seeds: HashMap<Participant, u64>,
}

pub struct OTECDSAPreparedSig {
    pub protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = ecdsa::SignatureOption>>,
    )>,
    pub key_packages: Vec<(Participant, ecdsa::KeygenOutput)>,
    pub participants: Vec<Participant>,
    pub coordinator: Participant,
    pub tweak: ecdsa::Tweak,
    pub msg_hash: ecdsa::Scalar,
}
