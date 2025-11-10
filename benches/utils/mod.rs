#![allow(clippy::missing_panics_doc)]
use std::{env, sync::LazyLock};

use k256::AffinePoint;
use threshold_signatures::{
    ecdsa::{RerandomizationArguments, Scalar, Secp256K1Sha256, Tweak},
    participants::{Participant, ParticipantList},
    test_utils::random_32_bytes,
};

use frost_secp256k1::{Secp256K1ScalarField, VerifyingKey};
use rand_core::{CryptoRngCore, OsRng};

// fix malicious number of participants
pub static MAX_MALICIOUS: LazyLock<usize> = std::sync::LazyLock::new(|| {
    env::var("MAX_MALICIOUS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6)
});

// Outputs pk, R, hash, participants, entropy, randomness
pub fn ecdsa_generate_rerandpresig_args(
    rng: &mut impl CryptoRngCore,
    participants: &[Participant],
    pk: VerifyingKey,
    big_r: AffinePoint,
) -> (RerandomizationArguments, Scalar) {
    let pk = pk.to_element().to_affine();
    let tweak = Tweak::new(frost_core::random_nonzero::<Secp256K1Sha256, _>(&mut OsRng));

    let msg_hash = <Secp256K1ScalarField as frost_core::Field>::random(&mut OsRng);
    let entropy = random_32_bytes(rng);
    // Generate unique ten ParticipantId values
    let participants =
        ParticipantList::new(participants).expect("Participant list generation should not fail");

    let args = RerandomizationArguments::new(
        pk,
        tweak,
        msg_hash.to_bytes().into(),
        big_r,
        participants,
        entropy,
    );
    (args, msg_hash)
}
