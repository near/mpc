use rand::Rng;
use rand_core::{CryptoRngCore, SeedableRng};

use threshold_signatures::{
    ecdsa::{
        self,
        ot_based_ecdsa::{
            self,
            triples::{generate_triple_many, TriplePub, TripleShare},
        },
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        ecdsa_generate_rerandpresig_args, generate_participants_with_random_ids, run_keygen,
        MockCryptoRng,
    },
    ReconstructionLowerBound,
};

use super::{PreparedPresig, PreparedSig};

/// Used to prepare ot based ecdsa triples for benchmarking
pub fn ot_ecdsa_prepare_triples<R: CryptoRngCore + SeedableRng + Send + 'static>(
    participant_num: usize,
    threshold: ReconstructionLowerBound,
    rng: &mut R,
) -> OTECDSAPreparedTriples {
    let mut protocols: Vec<(_, Box<dyn Protocol<Output = _>>)> =
        Vec::with_capacity(participant_num);
    let participants = generate_participants_with_random_ids(participant_num, rng);

    for p in &participants {
        let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
        let protocol = generate_triple_many::<2>(&participants, *p, threshold, rng_p)
            .expect("Triple generation should succeed");
        protocols.push((*p, Box::new(protocol)));
    }
    OTECDSAPreparedTriples {
        protocols,
        participants,
    }
}

/// Used to prepare ot based ecdsa presignatures for benchmarking
pub fn ot_ecdsa_prepare_presign<R: CryptoRngCore + SeedableRng + Send + 'static>(
    two_triples: &[(Participant, Vec<(TripleShare, TriplePub)>)],
    threshold: ReconstructionLowerBound,
    rng: &mut R,
) -> OTECDSAPreparedPresig {
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

    let mut protocols: Vec<_> = Vec::with_capacity(participants.len());

    for (((p, keygen_out), share0), share1) in
        key_packages.clone().into_iter().zip(shares0).zip(shares1)
    {
        let protocol = ot_based_ecdsa::presign::presign(
            &participants,
            p,
            ot_based_ecdsa::PresignArguments {
                triple0: (share0, pub0[0].clone()),
                triple1: (share1, pub1[0].clone()),
                keygen_out,
                threshold,
            },
        )
        .expect("Presigning should succeed");
        protocols.push((p, Box::new(protocol) as Box<dyn Protocol<Output = _>>));
    }
    OTECDSAPreparedPresig {
        protocols,
        key_packages,
        participants,
    }
}

/// Used to prepare ot based ecdsa signatures for benchmarking
pub fn ot_ecdsa_prepare_sign<R: CryptoRngCore + SeedableRng>(
    result: &[(Participant, ot_based_ecdsa::PresignOutput)],
    threshold: ReconstructionLowerBound,
    pk: frost_secp256k1::VerifyingKey,
    rng: &mut R,
) -> OTECDSAPreparedSig {
    // collect all participants
    let participants: Vec<Participant> =
        result.iter().map(|(participant, _)| *participant).collect();

    // choose a coordinator at random
    let index = rng.gen_range(0..result.len());
    let coordinator = result[index].0;

    let (args, msg_hash) =
        ecdsa_generate_rerandpresig_args(rng, &participants, pk, result[0].1.big_r);
    let derived_pk = args
        .tweak
        .derive_verifying_key(&pk)
        .to_element()
        .to_affine();

    let result = result
        .iter()
        .map(|(p, presig)| {
            (
                *p,
                ot_based_ecdsa::RerandomizedPresignOutput::rerandomize_presign(presig, &args)
                    .expect("Rerandomizing presignature should succeed"),
            )
        })
        .collect::<Vec<_>>();

    let mut protocols = Vec::with_capacity(result.len());

    for (p, presignature) in result.clone() {
        let protocol = ot_based_ecdsa::sign::sign(
            args.participants.participants(),
            coordinator,
            threshold,
            p,
            derived_pk,
            presignature,
            msg_hash,
        )
        .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = ecdsa::SignatureOption>>)
        .expect("Signing should succeed");
        protocols.push((p, protocol));
    }
    OTECDSAPreparedSig {
        protocols,
        index,
        presig: result[index].1.clone(),
        derived_pk,
        msg_hash,
    }
}

pub fn split_even_odd<T: Clone>(v: Vec<T>) -> (Vec<T>, Vec<T>) {
    let mut even = Vec::with_capacity(v.len() / 2 + 1);
    let mut odd = Vec::with_capacity(v.len() / 2);
    for (i, x) in v.into_iter().enumerate() {
        if i % 2 == 0 {
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
}

pub type OTECDSAPreparedPresig = PreparedPresig<ot_based_ecdsa::PresignOutput, ecdsa::KeygenOutput>;
pub type OTECDSAPreparedSig = PreparedSig<ot_based_ecdsa::RerandomizedPresignOutput>;
