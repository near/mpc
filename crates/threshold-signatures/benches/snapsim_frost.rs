#![allow(clippy::indexing_slicing, clippy::missing_panics_doc)]

use rand::RngCore;
use rand_core::SeedableRng;

mod bench_utils;
use bench_utils::ed25519_build_presign_protocols;

use threshold_signatures::{
    frost::eddsa,
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        bench_simulation, generate_participants_with_random_ids, record_trace,
        reconstruct_timeline, time_all_participants, BenchConfig, MockCryptoRng,
    },
    ReconstructionLowerBound,
};

fn main() {
    let config = BenchConfig::from_env();
    let threshold = ReconstructionLowerBound::from(config.threshold);

    println!("Snap-then-simulate: EdDSA FROST signing");
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
    let message = b"test message for eddsa signing benchmark".to_vec();

    eprint!("Setting up (keygen)...");
    let key_packages: Vec<(Participant, eddsa::KeygenOutput)> =
        threshold_signatures::test_utils::run_keygen(
            &participants,
            config.threshold,
            &mut setup_rng,
        );
    eprintln!(" done");

    // ── FROST v1 sign ──

    let make_sign_v1 = || {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        build_sign_v1_protocols(
            &participants,
            &key_packages,
            threshold,
            coordinator,
            &message,
            &mut rng,
        )
    };

    eprint!("Recording trace (frost_v1)...");
    let (_, trace_v1) = record_trace(make_sign_v1());
    eprintln!(" done");

    config.warmup(&|| {
        let timings = time_all_participants(make_sign_v1(), &trace_v1);
        reconstruct_timeline(&trace_v1, &timings, &config.latency);
    });

    bench_simulation(
        "frost_v1 (snap-then-simulate)",
        &|| {
            let timings = time_all_participants(make_sign_v1(), &trace_v1);
            reconstruct_timeline(&trace_v1, &timings, &config.latency)
        },
        config.samples,
    );

    // ── FROST v2 presign ──

    let make_presign = || {
        let mut rng = MockCryptoRng::seed_from_u64(77);
        ed25519_build_presign_protocols(&participants, &key_packages, threshold, &mut rng)
    };

    eprint!("Recording trace (frost_v2: presign)...");
    let (presign_outputs, trace_presign) = record_trace(make_presign());
    eprintln!(" done");

    bench_simulation(
        "frost_v2: presign (snap-then-simulate)",
        &|| {
            let timings = time_all_participants(make_presign(), &trace_presign);
            reconstruct_timeline(&trace_presign, &timings, &config.latency)
        },
        config.samples,
    );

    // ── FROST v2 sign ──

    let make_sign_v2 = || {
        build_sign_v2_protocols(
            &participants,
            &key_packages,
            &presign_outputs,
            threshold,
            coordinator,
            &message,
        )
    };

    eprint!("Recording trace (frost_v2: sign)...");
    let (_, trace_sign) = record_trace(make_sign_v2());
    eprintln!(" done");

    bench_simulation(
        "frost_v2: sign (snap-then-simulate)",
        &|| {
            let timings = time_all_participants(make_sign_v2(), &trace_sign);
            reconstruct_timeline(&trace_sign, &timings, &config.latency)
        },
        config.samples,
    );
}

fn build_sign_v1_protocols(
    participants: &[Participant],
    key_packages: &[(Participant, eddsa::KeygenOutput)],
    threshold: ReconstructionLowerBound,
    coordinator: Participant,
    message: &[u8],
    rng: &mut MockCryptoRng,
) -> Vec<(Participant, Box<dyn Protocol<Output = eddsa::SignatureOption>>)> {
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = eddsa::SignatureOption>>,
    )> = Vec::with_capacity(participants.len());
    for (p, keygen_out) in key_packages {
        let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
        let protocol = eddsa::sign::sign_v1(
            participants,
            threshold,
            *p,
            coordinator,
            keygen_out.clone(),
            message.to_vec(),
            rng_p,
        )
        .expect("sign_v1 should succeed");
        protocols.push((*p, Box::new(protocol) as Box<dyn Protocol<Output = _>>));
    }
    protocols
}

fn build_sign_v2_protocols(
    participants: &[Participant],
    key_packages: &[(Participant, eddsa::KeygenOutput)],
    presign_outputs: &[(Participant, eddsa::PresignOutput)],
    threshold: ReconstructionLowerBound,
    coordinator: Participant,
    message: &[u8],
) -> Vec<(Participant, Box<dyn Protocol<Output = eddsa::SignatureOption>>)> {
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = eddsa::SignatureOption>>,
    )> = Vec::with_capacity(participants.len());
    for ((p, keygen_out), (_, presign_out)) in key_packages.iter().zip(presign_outputs) {
        let protocol = eddsa::sign::sign_v2(
            participants,
            threshold,
            *p,
            coordinator,
            keygen_out.clone(),
            presign_out.clone(),
            message.to_vec(),
        )
        .expect("sign_v2 should succeed");
        protocols.push((*p, Box::new(protocol) as Box<dyn Protocol<Output = _>>));
    }
    protocols
}
