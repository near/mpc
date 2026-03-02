use frost_core::{Field, Group};
use frost_secp256k1::Secp256K1Sha256;
use k256::AffinePoint;
use rand_core::CryptoRngCore;
use std::error::Error;

use crate::ecdsa::{RerandomizationArguments, Tweak};
use crate::frost;
use crate::test_utils::{run_protocol, GenProtocol};
use crate::{
    Ciphersuite, Participant, ParticipantList, ReconstructionLowerBound, Scalar, VerifyingKey,
};

/// Generates at random 32 bytes
fn random_32_bytes(rng: &mut impl CryptoRngCore) -> [u8; 32] {
    let mut bytes: [u8; 32] = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

// +++++++++++++++++ ECDSA Presignature Rerandomization +++++++++++++++++ //
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

// +++++++++++++++++ EdDSA Presignature Rerandomization +++++++++++++++++ //
type BoxErr = Box<dyn Error>;
pub fn frost_run_presignature<C>(
    participants: &[(Participant, crate::KeygenOutput<C>)],
    threshold: impl Into<ReconstructionLowerBound> + Copy,
    actual_signers: usize,
    mut rng: impl CryptoRngCore + Send + Clone + 'static,
) -> Result<Vec<(Participant, frost::PresignOutput<C>)>, BoxErr>
where
    C: Ciphersuite + Send,
    <<<C as frost_core::Ciphersuite>::Group as Group>::Field as Field>::Scalar: Send,
    <<C as frost_core::Ciphersuite>::Group as frost_core::Group>::Element: std::marker::Send,
{
    let mut protocols: GenProtocol<frost::PresignOutput<C>> =
        Vec::with_capacity(participants.len());

    let participants_list = participants
        .iter()
        .take(actual_signers)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();

    for (participant, keygen_out) in participants.iter().take(actual_signers) {
        let args = crate::frost::PresignArguments {
            keygen_out: keygen_out.clone(),
            threshold: threshold.into(),
        };
        rng.next_u64();
        // run the signing scheme
        let protocol =
            crate::frost::presign::<C>(&participants_list, *participant, &args, rng.clone())?;

        protocols.push((*participant, Box::new(protocol)));
    }

    Ok(run_protocol(protocols)?)
}
