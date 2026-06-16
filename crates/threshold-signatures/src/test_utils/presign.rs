use frost_core::Identifier;
use frost_core::round1::{SigningCommitments, SigningNonces};
use frost_secp256k1::Secp256K1Sha256;
use k256::AffinePoint;
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Debug;

use crate::ecdsa::{RerandomizationArguments, Tweak};
use crate::frost;
use crate::test_utils::{GenProtocol, run_protocol};
use crate::{
    Ciphersuite, Participant, ParticipantList, ReconstructionLowerBound, Scalar, VerifyingKey,
};

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
    C: Ciphersuite,
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
            private_share: keygen_out.private_share,
            threshold: threshold.into(),
        };
        rng.next_u64();
        // run the signing scheme
        let protocol =
            crate::frost::presign::<C, _>(&participants_list, *participant, &args, rng.clone())?;

        protocols.push((*participant, Box::new(protocol)));
    }

    Ok(run_protocol(protocols)?)
}

/// Asserts that a batch of FROST presignatures from a single run is well-formed.
///
/// Every participant identifier is unique, every participant's secret nonces
/// are distinct, and every participant observes the same commitments map.
pub fn assert_frost_presignatures_well_formed<C>(
    presignatures: &[(Participant, frost::PresignOutput<C>)],
) where
    C: Ciphersuite + Send + 'static,
    SigningNonces<C>: PartialEq + Debug,
    BTreeMap<Identifier<C>, SigningCommitments<C>>: PartialEq + Debug,
{
    assert!(
        presignatures.len() >= 2,
        "expected at least 2 presignatures to compare; got {}",
        presignatures.len()
    );
    for (i, (p1, presig1)) in presignatures.iter().enumerate() {
        for (p2, presig2) in presignatures.iter().skip(i + 1) {
            assert_ne!(p1, p2);
            assert_ne!(presig1.nonces, presig2.nonces);
            assert_eq!(presig1.commitments_map, presig2.commitments_map);
        }
    }
}
