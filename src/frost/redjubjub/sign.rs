//! This module and the frost one are supposed to have the same helper function
use super::{KeygenOutput, PresignOutput, SignatureOption};
use crate::errors::{InitializationError, ProtocolError};
use crate::participants::{Participant, ParticipantList};
use crate::protocol::{
    helpers::recv_from_others,
    internal::{make_protocol, Comms, SharedChannel},
    Protocol,
};
use crate::thresholds::ReconstructionLowerBound;

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
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // validate threshold
    if threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: threshold.value(),
            max: participants.len(),
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }

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
    let randomizer_waitpoint = chan.next_waitpoint();
    chan.send_many(randomizer_waitpoint, &randomizer)?;

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
    let randomizer_waitpoint = chan.next_waitpoint();
    let randomizer = loop {
        let (from, randomizer): (_, Randomizer) = chan.recv(randomizer_waitpoint).await?;
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
    use crate::crypto::hash::hash;
    use crate::frost::redjubjub::test::{build_key_packages_with_dealer, test_run_signature};

    use crate::test_utils::{one_coordinator_output, MockCryptoRng};
    use rand::SeedableRng;

    #[test]
    fn stress() {
        let mut rng = MockCryptoRng::seed_from_u64(42);

        let max_signers = 7;
        let msg = "hello_near";
        let msg_hash = hash(&msg).unwrap();

        for min_signers in 2..max_signers {
            for actual_signers in min_signers..=max_signers {
                let key_packages =
                    build_key_packages_with_dealer(max_signers, min_signers, &mut rng);
                let min_signers: usize = min_signers.into();
                let coordinators = vec![key_packages[0].0];
                let data = test_run_signature(
                    &key_packages,
                    actual_signers.into(),
                    &coordinators,
                    min_signers,
                    msg_hash,
                )
                .unwrap();
                one_coordinator_output(data, coordinators[0]).unwrap();
            }
        }
    }
}
