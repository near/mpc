use k256::AffinePoint;
use rand_core::CryptoRngCore;

use crate::ecdsa::{RerandomizationArguments, Tweak};
use crate::frost_secp256k1::Secp256K1Sha256;
use crate::{Participant, ParticipantList, Scalar, VerifyingKey};

/// Generates at random 32 bytes
fn random_32_bytes(rng: &mut impl CryptoRngCore) -> [u8; 32] {
    let mut bytes: [u8; 32] = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

// +++++++++++++++++ Presignature Rerandomization +++++++++++++++++ //
/// Rerandomizes an ECDSA presignature.
/// Takes pk and R as input and generates a random message hash and entropy.
/// Outputs rerandomization arguments and the message hash
pub fn ecdsa_generate_rerandpresig_args(
    rng: &mut impl CryptoRngCore,
    participants: &[Participant],
    pk: VerifyingKey<Secp256K1Sha256>,
    big_r: AffinePoint,
) -> (RerandomizationArguments, Scalar<Secp256K1Sha256>) {
    let pk = pk.to_element().to_affine();
    let tweak = Tweak::new(frost_core::random_nonzero::<Secp256K1Sha256, _>(rng));

    let msg_hash = <frost_secp256k1::Secp256K1ScalarField as frost_core::Field>::random(rng);
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
