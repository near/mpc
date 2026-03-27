use rand::Rng;
use rand_core::{CryptoRngCore, SeedableRng};

use threshold_signatures::{
    ecdsa::{self, robust_ecdsa},
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        ecdsa_generate_rerandpresig_args, generate_participants_with_random_ids, run_keygen,
        MockCryptoRng,
    },
    MaxMalicious,
};

use super::{PreparedPresig, PreparedSig, MAX_MALICIOUS};

/// Used to prepare robust ecdsa presignatures for benchmarking
pub fn robust_ecdsa_prepare_presign<R: CryptoRngCore + SeedableRng + Send + 'static>(
    num_participants: usize,
    rng: &mut R,
) -> RobustECDSAPreparedPresig {
    let participants = generate_participants_with_random_ids(num_participants, rng);
    let key_packages = run_keygen(&participants, *MAX_MALICIOUS + 1, rng);
    let mut protocols: Vec<_> = Vec::with_capacity(participants.len());

    for (p, keygen_out) in &key_packages {
        let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
        let protocol = robust_ecdsa::presign::presign(
            &participants,
            *p,
            robust_ecdsa::PresignArguments {
                keygen_out: keygen_out.clone(),
                max_malicious: (*MAX_MALICIOUS).into(),
            },
            rng_p,
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
    max_malicious: MaxMalicious,
    pk: frost_secp256k1::VerifyingKey,
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

    let mut protocols = Vec::with_capacity(result.len());

    for (p, presignature) in result.clone() {
        let protocol = robust_ecdsa::sign::sign(
            &participants,
            coordinator,
            max_malicious,
            p,
            derived_pk,
            presignature,
            msg_hash,
        )
        .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = ecdsa::SignatureOption>>)
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

pub type RobustECDSAPreparedPresig =
    PreparedPresig<robust_ecdsa::PresignOutput, ecdsa::KeygenOutput>;
pub type RobustECDSASig = PreparedSig<robust_ecdsa::RerandomizedPresignOutput>;
