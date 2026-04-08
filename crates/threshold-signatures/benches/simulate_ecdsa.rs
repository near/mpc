#![allow(clippy::indexing_slicing, clippy::missing_panics_doc)]

use rand::RngCore;
use rand_core::SeedableRng;

mod bench_utils;
use bench_utils::split_even_odd;

use threshold_signatures::{
    ecdsa::{
        self,
        ot_based_ecdsa::{self, triples::generate_triple_many},
        robust_ecdsa,
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        bench_simulation, ecdsa_generate_rerandpresig_args, generate_participants_with_random_ids,
        run_keygen, run_simulation, BenchConfig, LatencyModel, MockCryptoRng, SimulationMetrics,
    },
    MaxMalicious, ReconstructionLowerBound,
};

type TriplePair = (
    ot_based_ecdsa::triples::TripleShare,
    ot_based_ecdsa::triples::TriplePub,
);
type TriplesResult = Vec<(Participant, Vec<TriplePair>)>;

fn ot_run_triples(
    participants: &[Participant],
    threshold: ReconstructionLowerBound,
    latency: &LatencyModel,
    rng: &mut MockCryptoRng,
) -> (TriplesResult, SimulationMetrics) {
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = _>>)> =
        Vec::with_capacity(participants.len());
    for &p in participants {
        let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
        let protocol = generate_triple_many::<2>(participants, p, threshold, rng_p)
            .expect("Triple generation should succeed");
        protocols.push((p, Box::new(protocol)));
    }
    run_simulation(protocols, latency)
}

fn ot_run_presign(
    participants: &[Participant],
    two_triples: &[(Participant, Vec<TriplePair>)],
    key_packages: &[(Participant, ecdsa::KeygenOutput)],
    threshold: ReconstructionLowerBound,
    latency: &LatencyModel,
) -> (
    Vec<(Participant, ot_based_ecdsa::PresignOutput)>,
    SimulationMetrics,
) {
    let mut sorted_triples = two_triples.to_owned();
    sorted_triples.sort_by_key(|(p, _)| *p);

    let (shares, pubs): (Vec<_>, Vec<_>) =
        sorted_triples.into_iter().flat_map(|(_, vec)| vec).unzip();
    let (shares0, shares1) = split_even_odd(shares);
    let (pub0, pub1) = split_even_odd(pubs);

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = _>>)> =
        Vec::with_capacity(participants.len());
    for (((p, keygen_out), share0), share1) in key_packages.iter().zip(shares0).zip(shares1) {
        let protocol = ot_based_ecdsa::presign::presign(
            participants,
            *p,
            ot_based_ecdsa::PresignArguments {
                triple0: (share0, pub0[0].clone()),
                triple1: (share1, pub1[0].clone()),
                keygen_out: keygen_out.clone(),
                threshold,
            },
        )
        .expect("Presigning should succeed");
        protocols.push((*p, Box::new(protocol)));
    }
    run_simulation(protocols, latency)
}

fn ot_run_sign(
    participants: &[Participant],
    presign_outputs: &[(Participant, ot_based_ecdsa::PresignOutput)],
    threshold: ReconstructionLowerBound,
    coordinator: Participant,
    pk: frost_secp256k1::VerifyingKey,
    latency: &LatencyModel,
    rng: &mut MockCryptoRng,
) -> SimulationMetrics {
    let (args, msg_hash) =
        ecdsa_generate_rerandpresig_args(rng, participants, pk, presign_outputs[0].1.big_r);
    let derived_pk = args
        .tweak
        .derive_verifying_key(&pk)
        .to_element()
        .to_affine();

    let rerand: Vec<_> = presign_outputs
        .iter()
        .map(|(p, presig)| {
            (
                *p,
                ot_based_ecdsa::RerandomizedPresignOutput::rerandomize_presign(presig, &args)
                    .expect("Rerandomize should succeed"),
            )
        })
        .collect();

    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = ecdsa::SignatureOption>>,
    )> = Vec::with_capacity(participants.len());
    for (p, presig) in rerand {
        let protocol = ot_based_ecdsa::sign::sign(
            participants,
            coordinator,
            threshold,
            p,
            derived_pk,
            presig,
            msg_hash,
        )
        .expect("Signing should succeed");
        protocols.push((p, Box::new(protocol)));
    }

    let (results, metrics) = run_simulation(protocols, latency);
    assert!(results.iter().any(|(_, sig)| sig.is_some()));
    metrics
}

fn robust_run_presign(
    participants: &[Participant],
    key_packages: &[(Participant, ecdsa::KeygenOutput)],
    max_malicious: MaxMalicious,
    latency: &LatencyModel,
    rng: &mut MockCryptoRng,
) -> (
    Vec<(Participant, robust_ecdsa::PresignOutput)>,
    SimulationMetrics,
) {
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = robust_ecdsa::PresignOutput>>,
    )> = Vec::with_capacity(participants.len());
    for (p, keygen_out) in key_packages {
        let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
        let protocol = robust_ecdsa::presign::presign(
            participants,
            *p,
            robust_ecdsa::PresignArguments {
                keygen_out: keygen_out.clone(),
                max_malicious,
            },
            rng_p,
        )
        .expect("Presign should succeed");
        protocols.push((*p, Box::new(protocol)));
    }
    run_simulation(protocols, latency)
}

fn robust_run_sign(
    participants: &[Participant],
    presign_outputs: &[(Participant, robust_ecdsa::PresignOutput)],
    max_malicious: MaxMalicious,
    coordinator: Participant,
    pk: frost_secp256k1::VerifyingKey,
    latency: &LatencyModel,
    rng: &mut MockCryptoRng,
) -> SimulationMetrics {
    let (args, msg_hash) =
        ecdsa_generate_rerandpresig_args(rng, participants, pk, presign_outputs[0].1.big_r);
    let derived_pk = args
        .tweak
        .derive_verifying_key(&pk)
        .to_element()
        .to_affine();

    let rerand: Vec<_> = presign_outputs
        .iter()
        .map(|(p, presig)| {
            (
                *p,
                robust_ecdsa::RerandomizedPresignOutput::rerandomize_presign(presig, &args)
                    .expect("Rerandomize should succeed"),
            )
        })
        .collect();

    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = ecdsa::SignatureOption>>,
    )> = Vec::with_capacity(participants.len());
    for (p, presig) in rerand {
        let protocol = robust_ecdsa::sign::sign(
            participants,
            coordinator,
            max_malicious,
            p,
            derived_pk,
            presig,
            msg_hash,
        )
        .expect("Signing should succeed");
        protocols.push((p, Box::new(protocol)));
    }

    let (results, metrics) = run_simulation(protocols, latency);
    assert!(results.iter().any(|(_, sig)| sig.is_some()));
    metrics
}

fn bench_cait_sith(
    participants: &[Participant],
    key_packages: &[(Participant, ecdsa::KeygenOutput)],
    threshold: ReconstructionLowerBound,
    coordinator: Participant,
    pk: frost_secp256k1::VerifyingKey,
    config: &BenchConfig,
) {
    let mut triple_rng = MockCryptoRng::seed_from_u64(55);
    let (triples, _) = ot_run_triples(participants, threshold, &config.latency, &mut triple_rng);
    let mut presign_rng = MockCryptoRng::seed_from_u64(55);
    let (triples_for_presign, _) =
        ot_run_triples(participants, threshold, &config.latency, &mut presign_rng);
    let (presign_outputs, _) = ot_run_presign(
        participants,
        &triples_for_presign,
        key_packages,
        threshold,
        &config.latency,
    );

    bench_simulation(
        "Cait-Sith: triples",
        &|| {
            let mut rng = MockCryptoRng::seed_from_u64(55);
            ot_run_triples(participants, threshold, &config.latency, &mut rng).1
        },
        config.samples,
    );
    bench_simulation(
        "Cait-Sith: presign",
        &|| {
            ot_run_presign(
                participants,
                &triples,
                key_packages,
                threshold,
                &config.latency,
            )
            .1
        },
        config.samples,
    );
    bench_simulation(
        "Cait-Sith: sign",
        &|| {
            let mut rng = MockCryptoRng::seed_from_u64(77);
            ot_run_sign(
                participants,
                &presign_outputs,
                threshold,
                coordinator,
                pk,
                &config.latency,
                &mut rng,
            )
        },
        config.samples,
    );
}

fn bench_damgard(
    participants: &[Participant],
    key_packages: &[(Participant, ecdsa::KeygenOutput)],
    max_malicious: MaxMalicious,
    coordinator: Participant,
    pk: frost_secp256k1::VerifyingKey,
    config: &BenchConfig,
) {
    let mut presign_rng = MockCryptoRng::seed_from_u64(66);
    let (presign_outputs, _) = robust_run_presign(
        participants,
        key_packages,
        max_malicious,
        &config.latency,
        &mut presign_rng,
    );

    bench_simulation(
        "DamgardEtAl: presign",
        &|| {
            let mut rng = MockCryptoRng::seed_from_u64(66);
            robust_run_presign(
                participants,
                key_packages,
                max_malicious,
                &config.latency,
                &mut rng,
            )
            .1
        },
        config.samples,
    );
    bench_simulation(
        "DamgardEtAl: sign",
        &|| {
            let mut rng = MockCryptoRng::seed_from_u64(77);
            robust_run_sign(
                participants,
                &presign_outputs,
                max_malicious,
                coordinator,
                pk,
                &config.latency,
                &mut rng,
            )
        },
        config.samples,
    );
}

fn main() {
    let config = BenchConfig::from_env();
    let threshold = ReconstructionLowerBound::from(config.threshold);
    let max_malicious = MaxMalicious::from(config.threshold - 1);

    println!("Protocol simulation: ECDSA (Cait-Sith vs DamgardEtAl)");
    println!(
        "Participants: {}, threshold: {}, latency: {}ms, samples: {}",
        config.num_participants,
        config.threshold,
        config.latency_ms(),
        config.samples
    );
    println!();

    let mut setup_rng = MockCryptoRng::seed_from_u64(42);
    let participants =
        generate_participants_with_random_ids(config.num_participants, &mut setup_rng);
    let coordinator = participants[0];

    eprint!("Setting up (keygen)...");
    let key_packages: Vec<(Participant, ecdsa::KeygenOutput)> =
        run_keygen(&participants, config.threshold, &mut setup_rng);
    let pk = key_packages[0].1.public_key;
    eprintln!(" done");

    config.warmup(&|| {
        let mut rng = MockCryptoRng::seed_from_u64(66);
        robust_run_presign(
            &participants,
            &key_packages,
            max_malicious,
            &config.latency,
            &mut rng,
        );
    });

    bench_cait_sith(
        &participants,
        &key_packages,
        threshold,
        coordinator,
        pk,
        &config,
    );
    bench_damgard(
        &participants,
        &key_packages,
        max_malicious,
        coordinator,
        pk,
        &config,
    );
}
