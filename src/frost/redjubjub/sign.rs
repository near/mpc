//! This module and the frost one are supposed to have the same helper function
use super::{KeygenOutput, PresignOutput, SignatureOption};
use crate::{
    errors::{InitializationError, ProtocolError},
    frost::assert_sign_inputs,
    participants::{Participant, ParticipantList},
    protocol::{
        helpers::recv_from_others,
        internal::{make_protocol, Comms, SharedChannel},
        Protocol,
    },
    ReconstructionLowerBound,
};

use reddsa::frost::redjubjub::{
    aggregate,
    keys::{KeyPackage, PublicKeyPackage},
    round2,
    round2::SignatureShare,
    Identifier, RandomizedParams, Randomizer, SigningPackage,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Depending on whether the current participant is a coordinator or not,
/// runs the signature protocol as either a participant or a coordinator.
///
/// WARNING: Extracted from FROST documentation:
/// In all of the main FROST ciphersuites, the entire message must be sent
/// to participants. In some cases, where the message is too big, it may be
/// necessary to send a hash of the message instead. We strongly suggest
/// creating a specific ciphersuite for this, and not just sending the hash
/// as if it were the message.
/// For reference, see how RFC 8032 handles "pre-hashing".
///
/// /!\ Warning: the threshold in this scheme is the exactly the
///              same as the max number of malicious parties.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
    randomizer: Option<Randomizer>,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;

    let comms = Comms::new();
    let chan = comms.shared_channel();
    let fut = fut_wrapper(
        chan,
        participants,
        threshold,
        me,
        coordinator,
        keygen_output,
        presignature,
        message,
        randomizer,
    );
    Ok(make_protocol(comms, fut))
}

#[allow(clippy::too_many_arguments)]
async fn fut_wrapper(
    chan: SharedChannel,
    participants: ParticipantList,
    threshold: ReconstructionLowerBound,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
    randomizer: Option<Randomizer>,
) -> Result<SignatureOption, ProtocolError> {
    if me == coordinator {
        match randomizer {
            Some(randomizer) => {
                do_sign_coordinator(
                    chan,
                    participants,
                    threshold,
                    me,
                    keygen_output,
                    presignature,
                    message,
                    randomizer,
                )
                .await
            }
            None => Err(ProtocolError::InvalidInput(
                "Randomizer should not be some".to_string(),
            )),
        }
    } else {
        match randomizer {
            Some(_) => Err(ProtocolError::InvalidInput(
                "Randomizer should be none".to_string(),
            )),
            None => {
                do_sign_participant(
                    chan,
                    threshold,
                    me,
                    coordinator,
                    keygen_output,
                    presignature,
                    message,
                )
                .await
            }
        }
    }
}

/// Returns a future that executes signature protocol for *the Coordinator*.
///
/// WARNING: Extracted from FROST documentation:
/// In all of the main FROST ciphersuites, the entire message must be sent
/// to participants. In some cases, where the message is too big, it may be
/// necessary to send a hash of the message instead. We strongly suggest
/// creating a specific ciphersuite for this, and not just sending the hash
/// as if it were the message.
/// For reference, see how RFC 8032 handles "pre-hashing".
#[allow(clippy::too_many_arguments)]
async fn do_sign_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    threshold: ReconstructionLowerBound,
    me: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
    randomizer: Randomizer,
) -> Result<SignatureOption, ProtocolError> {
    // --- Round 1
    let key_package = construct_key_package(threshold, me, &keygen_output)?;
    let key_package = Zeroizing::new(key_package);
    let signing_package = SigningPackage::new(presignature.commitments_map, &message);
    let randomized_params =
        RandomizedParams::from_randomizer(&keygen_output.public_key, randomizer);

    let randomizer = randomized_params.randomizer();
    // Send the Randomizer to everyone
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &randomizer)?;

    // Round 2
    let signature_share = round2::sign(
        &signing_package,
        &presignature.nonces,
        &key_package,
        *randomizer,
    )
    .map_err(|_| ProtocolError::ErrorFrostSigningFailed)?;

    let sign_waitpoint = chan.next_waitpoint();
    let mut signature_shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
    signature_shares.insert(me.to_identifier()?, signature_share);
    for (from, signature_share) in
        recv_from_others(&chan, sign_waitpoint, &participants, me).await?
    {
        signature_shares.insert(from.to_identifier()?, signature_share);
    }

    // --- Signature aggregation.
    // * Converted collected signature shares into the signature.
    // * Signature is verified internally during `aggregate()` call.

    // We use empty BTreeMap because "cheater-detection" feature is disabled
    // Feature "cheater-detection" unveils existant malicious participants
    let pk_package = PublicKeyPackage::new(BTreeMap::new(), keygen_output.public_key);

    let signature = aggregate(
        &signing_package,
        &signature_shares,
        &pk_package,
        &randomized_params,
    )
    .map_err(|_| ProtocolError::ErrorFrostAggregation)?;
    Ok(Some(signature))
}

/// Returns a future that executes signature protocol for *a Participant*.
///
/// WARNING: Extracted from FROST documentation:
/// In all of the main FROST ciphersuites, the entire message must be sent
/// to participants. In some cases, where the message is too big, it may be
/// necessary to send a hash of the message instead. We strongly suggest
/// creating a specific ciphersuite for this, and not just sending the hash
/// as if it were the message.
/// For reference, see how RFC 8032 handles "pre-hashing".
async fn do_sign_participant(
    mut chan: SharedChannel,
    threshold: ReconstructionLowerBound,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
) -> Result<SignatureOption, ProtocolError> {
    // --- Round 1.
    if coordinator == me {
        return Err(ProtocolError::InvalidInput(
            "the do_sign_participant function cannot be called
            for a coordinator"
                .to_string(),
        ));
    }

    // Receive the Randomizer from the coordinator
    let wait_round_1 = chan.next_waitpoint();
    let randomizer = loop {
        let (from, randomizer): (_, Randomizer) = chan.recv(wait_round_1).await?;
        if from != coordinator {
            continue;
        }
        break randomizer;
    };

    let key_package = construct_key_package(threshold, me, &keygen_output)?;
    let key_package = Zeroizing::new(key_package);
    let nonces = Zeroizing::new(presignature.nonces);
    let signing_package = SigningPackage::new(presignature.commitments_map, &message);
    let signature_share = round2::sign(&signing_package, &nonces, &key_package, randomizer)
        .map_err(|_| ProtocolError::ErrorFrostSigningFailed)?;

    let sign_waitpoint = chan.next_waitpoint();
    chan.send_private(sign_waitpoint, coordinator, &signature_share)?;

    Ok(None)
}

/// A function that takes a signing share and a keygenOutput
/// and construct a public key package used for frost signing
fn construct_key_package(
    threshold: ReconstructionLowerBound,
    me: Participant,
    keygen_output: &KeygenOutput,
) -> Result<KeyPackage, ProtocolError> {
    let identifier = me.to_identifier()?;
    let signing_share = keygen_output.private_share;
    let verifying_share = signing_share.into();
    let verifying_key = keygen_output.public_key;
    let key_package = KeyPackage::new(
        identifier,
        signing_share,
        verifying_share,
        verifying_key,
        u16::try_from(threshold.value()).map_err(|_| {
            ProtocolError::Other("threshold cannot be converted to u16".to_string())
        })?,
    );

    // Ensures the values are zeroized on drop
    Ok(key_package)
}

#[cfg(test)]
mod test {
    use crate::{
        crypto::hash::hash,
        frost::redjubjub::{
            sign::sign,
            test::{build_key_packages_with_dealer, run_sign_with_presign},
            PresignOutput, SignatureOption,
        },
        test_utils::{one_coordinator_output, MockCryptoRng},
        Protocol,
    };
    use frost_core::Field;
    use rand::{Rng, SeedableRng};
    use rand_core::RngCore;
    use reddsa::frost::redjubjub::{
        round1::commit, JubjubBlake2b512, JubjubScalarField, Randomizer,
    };
    use std::collections::BTreeMap;

    #[test]
    fn stress() {
        let mut rng = MockCryptoRng::seed_from_u64(42);

        let max_signers = 7;
        let msg = "hello_near";
        let msg_hash = hash(&msg).unwrap();

        for threshold in 2..max_signers {
            for actual_signers in threshold..=max_signers {
                let key_packages = build_key_packages_with_dealer(max_signers, threshold, &mut rng);
                let threshold: usize = threshold.into();
                let coordinator = key_packages[0].0;
                let data = run_sign_with_presign(
                    &key_packages,
                    actual_signers.into(),
                    coordinator,
                    threshold,
                    msg_hash,
                )
                .unwrap();
                one_coordinator_output(data, coordinator).unwrap();
            }
        }
    }

    #[test]
    fn test_signature_correctness() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let threshold = 6;
        let keys = build_key_packages_with_dealer(11, threshold, &mut rng);
        let public_key = keys[0].1.public_key.to_element();

        let msg = b"hello world".to_vec();
        let index = rng.gen_range(0..keys.len());
        let coordinator = keys[index as usize].0;
        let mut participants_sign_builder = keys
            .iter()
            .map(|(p, keygen_output)| {
                let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
                (*p, (keygen_output.clone(), rng_p))
            })
            .collect::<Vec<_>>();

        let mut commitments_map = BTreeMap::new();
        let mut nonces_map = BTreeMap::new();
        for (p, (keygen, rng_p)) in &mut participants_sign_builder {
            // Creating two commitments and corresponding nonces
            let (nonces, commitments) = commit(&keygen.private_share, rng_p);
            commitments_map.insert(p.to_identifier().unwrap(), commitments);
            nonces_map.insert(*p, nonces);
        }

        let mut rng = MockCryptoRng::seed_from_u64(644_221);
        let randomizer_scalar = JubjubScalarField::random(&mut rng);
        // Only for testing
        let randomizer = Randomizer::from_scalar(randomizer_scalar);
        // This checks the output signature validity internally
        let result = crate::test_utils::run_sign::<JubjubBlake2b512, _, _, _>(
            participants_sign_builder,
            coordinator,
            public_key,
            JubjubScalarField::zero(), // not important
            |participants, coordinator, me, _, (keygen_output, _), _| {
                let nonces = nonces_map.get(&me).unwrap().clone();
                let presignature = PresignOutput {
                    nonces,
                    commitments_map: commitments_map.clone(),
                };
                let randomize = if me == coordinator {
                    Some(randomizer)
                } else {
                    None
                };
                sign(
                    participants,
                    threshold as usize,
                    me,
                    coordinator,
                    keygen_output,
                    presignature,
                    msg.clone(),
                    randomize,
                )
                .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
            },
        )
        .unwrap();
        let signature = one_coordinator_output(result, coordinator).unwrap();
        insta::assert_json_snapshot!(signature);
    }
}
