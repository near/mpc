#![allow(dead_code, clippy::missing_panics_doc, clippy::indexing_slicing)]

use average::{Estimate, Quantile, Variance};
use frost_secp256k1::VerifyingKey;
use k256::AffinePoint;
use rand::Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use std::{env, sync::LazyLock};

use threshold_signatures::{
    ecdsa::ot_based_ecdsa,
    ecdsa::robust_ecdsa,
    ecdsa::{
        ot_based_ecdsa::triples::{generate_triple_many, TriplePub, TripleShare},
        KeygenOutput, Scalar, SignatureOption,
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        create_rngs, ecdsa_generate_rerandpresig_args, generate_participants_with_random_ids,
        run_keygen, Simulator,
    },
};

// fix malicious number of participants
pub static MAX_MALICIOUS: LazyLock<usize> = std::sync::LazyLock::new(|| {
    env::var("MAX_MALICIOUS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6)
});

// fix number of samples
pub static SAMPLE_SIZE: LazyLock<usize> = std::sync::LazyLock::new(|| {
    env::var("SAMPLE_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(15)
});

/// This helps defining a generic type for the benchmarks prepared outputs
pub struct PreparedOutputs<T> {
    pub participant: Participant,
    pub protocol: Box<dyn Protocol<Output = T>>,
    pub simulator: Simulator,
}
pub struct PreparedPresig<PresignOutput> {
    pub protocols: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)>,
    pub key_packages: Vec<(Participant, KeygenOutput)>,
    pub participants: Vec<Participant>,
}

pub struct PreparedSig<RerandomizedPresignOutput> {
    pub protocols: Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)>,
    pub index: usize,
    pub presig: RerandomizedPresignOutput,
    pub derived_pk: AffinePoint,
    pub msg_hash: Scalar,
}

#[allow(clippy::cast_precision_loss)]
/// Analyzes the size of the received data by a participant accross the entire protocol
pub fn analyze_received_sizes(
    sizes: &[usize],
    is_print: bool,
) -> (usize, usize, f64, f64, f64, f64) {
    if sizes.len() <= 1 {
        return (0, 0, 0.0, 0.0, 0.0, 0.0);
    }
    let min = *sizes.iter().min().expect("Minimum should exist");
    let max = *sizes.iter().max().expect("Maximum should exist");
    let avg = sizes.iter().sum::<usize>() as f64 / sizes.len() as f64;

    let data = sizes.iter().map(|&x| x as f64).collect::<Vec<f64>>();

    // Median (0.5 quantile)
    let mut quantile = Quantile::new(0.5);
    // Variance + Std Dev
    let mut variance_est = Variance::new();

    for &x in &data {
        variance_est.add(x);
        quantile.add(x);
    }

    let median = quantile.quantile();
    let variance = variance_est.sample_variance();
    let std_dev = variance.sqrt();

    if is_print {
        println!("Analysis for received messages:");
        println!(
            "\
            min:{min}B\t\
            max:{max}B\t\
            average:{avg}B\t\
            median:{median}B\t\
            variance:{variance}B\t\
            standard deviation:{std_dev}B
        "
        );
    }

    (min, max, avg, median, variance, std_dev)
}

/********************* OT Based ECDSA *********************/
/// Used to prepare ot based ecdsa triples for benchmarking
pub fn ot_ecdsa_prepare_triples<R: CryptoRngCore + SeedableRng + Send + 'static>(
    participant_num: usize,
    threshold: usize,
    rng: &mut R,
) -> OTECDSAPreparedTriples {
    let mut protocols: Vec<(_, Box<dyn Protocol<Output = _>>)> =
        Vec::with_capacity(participant_num);
    let rngs = create_rngs(participant_num, rng);
    let participants = generate_participants_with_random_ids(participant_num, rng);

    for (i, p) in participants.iter().enumerate() {
        let protocol = generate_triple_many::<2>(&participants, *p, threshold, rngs[i].clone())
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
    threshold: usize,
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

    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = ot_based_ecdsa::PresignOutput>>,
    )> = Vec::with_capacity(participants.len());

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
        protocols.push((p, Box::new(protocol)));
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
    pk: VerifyingKey,
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

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)> =
        Vec::with_capacity(result.len());

    for (p, presignature) in result.clone() {
        let protocol = ot_based_ecdsa::sign::sign(
            args.participants.participants(),
            coordinator,
            p,
            derived_pk,
            presignature,
            msg_hash,
        )
        .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
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

pub type OTECDSAPreparedPresig = PreparedPresig<ot_based_ecdsa::PresignOutput>;
pub type OTECDSAPreparedSig = PreparedSig<ot_based_ecdsa::RerandomizedPresignOutput>;

/********************* Robust ECDSA *********************/
/// Used to prepare robust ecdsa presignatures for benchmarking
pub fn robust_ecdsa_prepare_presign<R: CryptoRngCore + SeedableRng + Send + 'static>(
    num_participants: usize,
    rng: &mut R,
) -> RobustECDSAPreparedPresig {
    let rngs = create_rngs(num_participants, rng);
    let participants = generate_participants_with_random_ids(num_participants, rng);
    let key_packages = run_keygen(&participants, *MAX_MALICIOUS + 1, rng);
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = robust_ecdsa::PresignOutput>>,
    )> = Vec::with_capacity(participants.len());

    for (i, (p, keygen_out)) in key_packages.iter().enumerate() {
        let protocol = robust_ecdsa::presign::presign(
            &participants,
            *p,
            robust_ecdsa::PresignArguments {
                keygen_out: keygen_out.clone(),
                threshold: *MAX_MALICIOUS,
            },
            rngs[i].clone(),
        )
        .map(|presig| Box::new(presig) as Box<dyn Protocol<Output = robust_ecdsa::PresignOutput>>)
        .expect("Presignature should succeed");
        protocols.push((*p, protocol));
    }
    RobustECDSAPreparedPresig {
        protocols,
        key_packages,
        participants,
    }
}

/// Used to prepare robust ecdsa signatures for benchmarking
pub fn robust_ecdsa_prepare_sign<R: CryptoRngCore + SeedableRng>(
    result: &[(Participant, robust_ecdsa::PresignOutput)],
    pk: VerifyingKey,
    rng: &mut R,
) -> RobustECDSASig {
    // collect all participants
    let participants: Vec<Participant> =
        result.iter().map(|(participant, _)| *participant).collect();

    // choose a coordinator at random
    let coordinator_index = rng.gen_range(0..result.len());
    let coordinator = result[coordinator_index].0;

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
                robust_ecdsa::RerandomizedPresignOutput::rerandomize_presign(presig, &args)
                    .expect("Rerandomizing presignature should succeed"),
            )
        })
        .collect::<Vec<_>>();

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)> =
        Vec::with_capacity(result.len());

    for (p, presignature) in result.clone() {
        let protocol = robust_ecdsa::sign::sign(
            &participants,
            coordinator,
            p,
            derived_pk,
            presignature,
            msg_hash,
        )
        .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
        .expect("Signing should succeed");
        protocols.push((p, protocol));
    }
    RobustECDSASig {
        protocols,
        index: coordinator_index,
        presig: result[coordinator_index].1.clone(),
        derived_pk,
        msg_hash,
    }
}

pub type RobustECDSAPreparedPresig = PreparedPresig<robust_ecdsa::PresignOutput>;
pub type RobustECDSASig = PreparedSig<robust_ecdsa::RerandomizedPresignOutput>;
