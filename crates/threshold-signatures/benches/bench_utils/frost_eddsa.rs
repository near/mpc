use rand::Rng;
use rand_core::{CryptoRngCore, SeedableRng};

use threshold_signatures::{
    confidential_key_derivation::{
        self as ckd,
        ciphersuite::{Field as _, Group as _},
    },
    frost::eddsa,
    participants::Participant,
    protocol::Protocol,
    test_utils::{generate_participants_with_random_ids, run_keygen, MockCryptoRng},
    ReconstructionLowerBound,
};

use super::{PreparedPresig, MAX_MALICIOUS};

/// Build presign protocol instances for all participants.
pub fn ed25519_build_presign_protocols<R: CryptoRngCore + SeedableRng + Send + 'static>(
    participants: &[Participant],
    key_packages: &[(Participant, eddsa::KeygenOutput)],
    threshold: ReconstructionLowerBound,
    rng: &mut R,
) -> Vec<(
    Participant,
    Box<dyn Protocol<Output = eddsa::PresignOutput>>,
)> {
    let mut protocols = Vec::with_capacity(participants.len());
    for (p, keygen_out) in key_packages {
        let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
        let protocol = eddsa::presign(
            participants,
            *p,
            &eddsa::PresignArguments {
                keygen_out: keygen_out.clone(),
                threshold,
            },
            rng_p,
        )
        .map(|presig| Box::new(presig) as Box<dyn Protocol<Output = eddsa::PresignOutput>>)
        .expect("Presignature should succeed");
        protocols.push((*p, protocol));
    }
    protocols
}

/// Used to prepare ed25519 presignatures for benchmarking
pub fn ed25519_prepare_presign<R: CryptoRngCore + SeedableRng + Send + 'static>(
    num_participants: usize,
    rng: &mut R,
) -> FrostEd25519PreparedPresig {
    let participants = generate_participants_with_random_ids(num_participants, rng);
    let key_packages = run_keygen(&participants, *MAX_MALICIOUS + 1, rng);
    let threshold = ReconstructionLowerBound::from(*MAX_MALICIOUS + 1);
    let protocols = ed25519_build_presign_protocols(&participants, &key_packages, threshold, rng);
    FrostEd25519PreparedPresig {
        protocols,
        key_packages,
        participants,
    }
}

/// Used to prepare ed25519 signatures for benchmarking
pub fn ed25519_prepare_sign_v1<R: CryptoRngCore + SeedableRng + Send + 'static>(
    threshold: ReconstructionLowerBound,
    rng: &mut R,
) -> FrostEd25519SigV1 {
    let num_participants = threshold.value();
    let participants = generate_participants_with_random_ids(num_participants, rng);
    let key_packages = run_keygen(&participants, *MAX_MALICIOUS + 1, rng);

    // choose a coordinator at random
    let coordinator_index = rng.gen_range(0..num_participants);
    let coordinator = participants[coordinator_index];

    let mut protocols = Vec::with_capacity(participants.len());

    let mut message: [u8; 32] = [0u8; 32];
    rng.fill_bytes(&mut message);
    let message = message.to_vec();

    for (p, keygen_out) in &key_packages {
        let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
        let protocol = eddsa::sign::sign_v1(
            &participants,
            threshold,
            *p,
            coordinator,
            keygen_out.clone(),
            message.clone(),
            rng_p,
        )
        .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = eddsa::SignatureOption>>)
        .expect("Signing should succeed");
        protocols.push((*p, protocol));
    }

    FrostEd25519SigV1 {
        protocols,
        index: coordinator_index,
        key_packages,
        message,
    }
}

pub fn ed25519_prepare_sign_v2<R: CryptoRngCore + SeedableRng + Send + 'static>(
    result: &[(Participant, eddsa::PresignOutput)],
    key_packages: Vec<(Participant, eddsa::KeygenOutput)>,
    threshold: ReconstructionLowerBound,
    rng: &mut R,
) -> FrostEd25519SigV2 {
    let num_participants = threshold.value();
    // collect all participants
    let participants: Vec<_> = result.iter().map(|(participant, _)| *participant).collect();

    // choose a coordinator at random
    let coordinator_index = rng.gen_range(0..num_participants);
    let coordinator = participants[coordinator_index];

    let mut protocols = Vec::with_capacity(participants.len());

    let mut message: [u8; 32] = [0u8; 32];
    rng.fill_bytes(&mut message);
    let message = message.to_vec();

    for ((p, keygen_out), (p_redundancy, presign)) in key_packages.iter().zip(result) {
        assert_eq!(p, p_redundancy);
        let protocol = eddsa::sign::sign_v2(
            &participants,
            threshold,
            *p,
            coordinator,
            keygen_out.clone(),
            presign.clone(),
            message.clone(),
        )
        .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = eddsa::SignatureOption>>)
        .expect("Signing should succeed");
        protocols.push((*p, protocol));
    }

    FrostEd25519SigV2 {
        protocols,
        index: coordinator_index,
        presig: result[coordinator_index].1.clone(),
        key_packages,
        message,
    }
}

pub struct FrostEd25519SigV1 {
    pub protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = eddsa::SignatureOption>>,
    )>,
    pub index: usize,
    pub key_packages: Vec<(Participant, eddsa::KeygenOutput)>,
    pub message: Vec<u8>,
}

pub type FrostEd25519PreparedPresig = PreparedPresig<eddsa::PresignOutput, eddsa::KeygenOutput>;
pub struct FrostEd25519SigV2 {
    pub protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = eddsa::SignatureOption>>,
    )>,
    pub index: usize,
    pub presig: eddsa::PresignOutput,
    pub key_packages: Vec<(Participant, eddsa::KeygenOutput)>,
    pub message: Vec<u8>,
}

pub fn prepare_ckd<R: CryptoRngCore + SeedableRng + Send + 'static>(
    threshold: ReconstructionLowerBound,
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

    let mut app_id: [u8; 32] = [0u8; 32];
    rng.fill_bytes(&mut app_id);
    let app_id = ckd::AppId::try_new(app_id).expect("cannot fail");

    let scalar_rng = MockCryptoRng::seed_from_u64(rng.next_u64());
    let app_sk = ckd::Scalar::random(scalar_rng);
    let app_pk = ckd::ElementG1::generator() * app_sk;

    for (p, keygen_out) in &key_packages {
        let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
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
    }

    PreparedCkdPackage {
        protocols,
        index: coordinator_index,
        key_packages,
        app_id,
        app_pk,
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
}
