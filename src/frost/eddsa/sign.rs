//! This module wraps a signature generation functionality from `Frost` library
//!  into `cait-sith::Protocol` representation.
use super::{KeygenOutput, SignatureOption};
use crate::errors::{InitializationError, ProtocolError};
use crate::participants::{Participant, ParticipantList};
use crate::protocol::helpers::recv_from_others;
use crate::protocol::internal::{make_protocol, Comms, SharedChannel};
use crate::protocol::Protocol;
use crate::ReconstructionLowerBound;

use frost_ed25519::keys::{KeyPackage, PublicKeyPackage, SigningShare};
use frost_ed25519::{aggregate, rand_core, round1, round2, VerifyingKey};
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// A function that takes a signing share and a keygenOutput
/// and construct a public key package used for frost signing
fn construct_key_package(
    threshold: usize,
    me: Participant,
    signing_share: SigningShare,
    verifying_key: &VerifyingKey,
) -> Result<KeyPackage, ProtocolError> {
    let identifier = me.to_identifier()?;
    let verifying_share = signing_share.into();

    Ok(KeyPackage::new(
        identifier,
        signing_share,
        verifying_share,
        *verifying_key,
        u16::try_from(threshold).map_err(|_| {
            ProtocolError::Other("threshold cannot be converted to u16".to_string())
        })?,
    ))
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
async fn do_sign_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    threshold: usize,
    me: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    rng: &mut impl CryptoRngCore,
) -> Result<SignatureOption, ProtocolError> {
    // --- Round 1.
    // * Wait for other parties' commitments.

    let mut commitments_map: BTreeMap<frost_ed25519::Identifier, round1::SigningCommitments> =
        BTreeMap::new();

    // signing share is the private_share
    let signing_share = keygen_output.private_share;

    // Step 1.1 (and implicitely 1.2)
    let (nonces, commitments) = round1::commit(&signing_share, rng);
    let nonces = Zeroizing::new(nonces);
    commitments_map.insert(me.to_identifier()?, commitments);

    // Step 1.3
    let commit_waitpoint = chan.next_waitpoint();

    // Step 1.4
    for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
        commitments_map.insert(from.to_identifier()?, commitment);
    }

    let signing_package = frost_ed25519::SigningPackage::new(commitments_map, message.as_slice());

    let mut signature_shares: BTreeMap<frost_ed25519::Identifier, round2::SignatureShare> =
        BTreeMap::new();

    // Step 1.5
    let r2_wait_point = chan.next_waitpoint();
    chan.send_many(r2_wait_point, &signing_package)?;

    // --- Round 2
    // * Wait for each other's signature share
    // Step 2.3 (2.1 and 2.2 are implicit)
    let vk_package = keygen_output.public_key;
    let key_package = construct_key_package(threshold, me, signing_share, &vk_package)?;
    let key_package = Zeroizing::new(key_package);
    let signature_share = round2::sign(&signing_package, &nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    // Step 2.5 (2.4 is implicit)
    signature_shares.insert(me.to_identifier()?, signature_share);
    for (from, signature_share) in recv_from_others(&chan, r2_wait_point, &participants, me).await?
    {
        signature_shares.insert(from.to_identifier()?, signature_share);
    }

    // --- Signature aggregation.
    // * Converted collected signature shares into the signature.
    // * Signature is verified internally during `aggregate()` call.

    // Step 2.6 and 2.7
    // We supply empty map as `verifying_shares` because we have disabled "cheater-detection" feature flag.
    // Feature "cheater-detection" only points to a malicious participant, if there's such.
    // It doesn't bring any additional guarantees.
    let public_key_package = PublicKeyPackage::new(BTreeMap::new(), vk_package);
    let signature = aggregate(&signing_package, &signature_shares, &public_key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

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
    threshold: usize,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    rng: &mut impl CryptoRngCore,
) -> Result<SignatureOption, ProtocolError> {
    // --- Round 1.
    if coordinator == me {
        return Err(ProtocolError::AssertionFailed(
            "the do_sign_participant function cannot be called
            for a coordinator"
                .to_string(),
        ));
    }

    // signing share is the private_share
    let signing_share = keygen_output.private_share;

    // Step 1.1
    let (nonces, commitments) = round1::commit(&signing_share, rng);
    // Ensures the values are zeroized on drop
    let nonces = Zeroizing::new(nonces);

    // * Wait for an initial message from a coordinator.
    // * Send coordinator our commitment.

    // Step 1.2
    let commit_waitpoint = chan.next_waitpoint();
    chan.send_private(commit_waitpoint, coordinator, &commitments)?;

    // --- Round 2.
    // * Wait for a signing package.
    // * Send our signature share.

    // Step 2.1
    let r2_wait_point = chan.next_waitpoint();
    let signing_package = loop {
        let (from, signing_package): (_, frost_ed25519::SigningPackage) =
            chan.recv(r2_wait_point).await?;
        if from != coordinator {
            continue;
        }
        break signing_package;
    };

    // Step 2.2
    if signing_package.message() != message.as_slice() {
        return Err(ProtocolError::AssertionFailed(
            "Expected message doesn't match with the actual message received in a signing package"
                .to_string(),
        ));
    }

    // Step 2.3
    let vk_package = keygen_output.public_key;
    let key_package = construct_key_package(threshold, me, signing_share, &vk_package)?;
    // Ensures the values are zeroized on drop
    let key_package = Zeroizing::new(key_package);
    let signature_share = round2::sign(&signing_package, &nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    // Step 2.4
    chan.send_private(r2_wait_point, coordinator, &signature_share)?;

    Ok(None)
}

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
pub fn sign(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    let threshold = usize::from(threshold.into());
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
    if threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold,
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
        message,
        rng,
    );
    Ok(make_protocol(comms, fut))
}

#[allow(clippy::too_many_arguments)]
async fn fut_wrapper(
    chan: SharedChannel,
    participants: ParticipantList,
    threshold: usize,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    mut rng: impl CryptoRngCore,
) -> Result<SignatureOption, ProtocolError> {
    if me == coordinator {
        do_sign_coordinator(
            chan,
            participants,
            threshold,
            me,
            keygen_output,
            message,
            &mut rng,
        )
        .await
    } else {
        do_sign_participant(
            chan,
            threshold,
            me,
            coordinator,
            keygen_output,
            message,
            &mut rng,
        )
        .await
    }
}

#[cfg(test)]
mod test {
    use crate::crypto::hash::hash;
    use crate::frost::eddsa::{
        sign::sign,
        test::{build_key_packages_with_dealer, test_run_signature_protocols},
        KeygenOutput, SignatureOption,
    };
    use crate::participants::{Participant, ParticipantList};
    use crate::protocol::Protocol;
    use crate::test_utils::{
        assert_public_key_invariant, generate_participants, one_coordinator_output, run_keygen,
        run_refresh, run_reshare, MockCryptoRng,
    };
    use frost_core::{Field, Group};
    use frost_ed25519::{Ed25519Group, Ed25519ScalarField, Ed25519Sha512};
    use rand::{Rng, RngCore, SeedableRng};

    #[test]
    fn basic_two_participants() {
        let mut rng = MockCryptoRng::seed_from_u64(42);

        let max_signers = 2;
        let threshold = 2;
        let actual_signers = 2;
        let msg = "hello_near";
        let msg_hash = hash(&msg).unwrap();

        let key_packages = build_key_packages_with_dealer(max_signers, threshold, &mut rng);
        let coordinators = vec![key_packages[0].0];
        let threshold: usize = threshold.into();
        let data = test_run_signature_protocols(
            &key_packages,
            actual_signers,
            &coordinators,
            threshold,
            msg_hash,
        )
        .unwrap();
        one_coordinator_output(data, coordinators[0]).unwrap();
    }

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
                let coordinators = vec![key_packages[0].0];
                let min_signers: usize = min_signers.into();
                let data = test_run_signature_protocols(
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

    #[test]
    fn dkg_sign_test() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let participants = vec![
            Participant::from(0u32),
            Participant::from(31u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let actual_signers = participants.len();
        let threshold = 2;
        let msg = "hello_near";
        let msg_hash = hash(&msg).unwrap();

        // test dkg
        let key_packages = run_keygen(&participants, threshold, &mut rng);
        assert_public_key_invariant(&key_packages);
        let coordinators = vec![key_packages[0].0];
        let data = test_run_signature_protocols(
            &key_packages,
            actual_signers,
            &coordinators,
            threshold,
            msg_hash,
        )
        .unwrap();
        let signature = one_coordinator_output(data, coordinators[0]).unwrap();

        assert!(key_packages[0]
            .1
            .public_key
            .verify(msg_hash.as_ref(), &signature)
            .is_ok());

        // // test refresh
        let key_packages1 = run_refresh(&participants, &key_packages, threshold, &mut rng);
        assert_public_key_invariant(&key_packages1);
        let msg = "hello_near_2";
        let msg_hash = hash(&msg).unwrap();
        let data = test_run_signature_protocols(
            &key_packages1,
            actual_signers,
            &coordinators,
            threshold,
            msg_hash,
        )
        .unwrap();
        let signature = one_coordinator_output(data, coordinators[0]).unwrap();
        let pub_key = key_packages1[2].1.public_key;
        assert!(key_packages1[0]
            .1
            .public_key
            .verify(msg_hash.as_ref(), &signature)
            .is_ok());

        // test reshare
        let mut new_participant = participants.clone();
        new_participant.push(Participant::from(20u32));
        let new_threshold = 4;
        let key_packages2 = run_reshare(
            &participants,
            &pub_key,
            &key_packages1,
            threshold,
            new_threshold,
            &new_participant,
            &mut rng,
        );
        assert_public_key_invariant(&key_packages2);
        let msg = "hello_near_3";
        let msg_hash = hash(&msg).unwrap();
        let coordinators = vec![key_packages2[0].0];
        let data = test_run_signature_protocols(
            &key_packages2,
            actual_signers,
            &coordinators,
            new_threshold,
            msg_hash,
        )
        .unwrap();
        let signature = one_coordinator_output(data, coordinators[0]).unwrap();
        assert!(key_packages2[0]
            .1
            .public_key
            .verify(msg_hash.as_ref(), &signature)
            .is_ok());
    }

    #[test]
    fn test_reshare_sign_more_participants() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let participants = generate_participants(4);
        let threshold = 3;
        let result0 = run_keygen(&participants, threshold, &mut rng);
        assert_public_key_invariant(&result0);

        let pub_key = result0[2].1.public_key;

        // Run heavy reshare
        let new_threshold = 5;
        let mut new_participant = participants.clone();
        new_participant.push(Participant::from(31u32));
        new_participant.push(Participant::from(32u32));
        let key_packages = run_reshare(
            &participants,
            &pub_key,
            &result0,
            threshold,
            new_threshold,
            &new_participant,
            &mut rng,
        );
        assert_public_key_invariant(&key_packages);

        let participants: Vec<_> = key_packages
            .iter()
            .take(key_packages.len())
            .map(|(val, _)| *val)
            .collect();
        let shares: Vec<_> = key_packages
            .iter()
            .take(key_packages.len())
            .map(|(_, keygen)| keygen.private_share.to_scalar())
            .collect();

        // Test public key
        let p_list = ParticipantList::new(&participants).unwrap();
        let mut x = Ed25519ScalarField::zero();
        for (p, share) in participants.iter().zip(shares.iter()) {
            x += p_list.lagrange::<Ed25519Sha512>(*p).unwrap() * share;
        }
        assert_eq!(<Ed25519Group>::generator() * x, pub_key.to_element());

        // Sign
        let actual_signers = participants.len();
        let msg = "hello_near";
        let msg_hash = hash(&msg).unwrap();

        let coordinators = vec![key_packages[0].0];
        let data = test_run_signature_protocols(
            &key_packages,
            actual_signers,
            &coordinators,
            new_threshold,
            msg_hash,
        )
        .unwrap();
        let signature = one_coordinator_output(data, coordinators[0]).unwrap();
        assert!(key_packages[0]
            .1
            .public_key
            .verify(msg_hash.as_ref(), &signature)
            .is_ok());
    }

    #[test]
    fn test_reshare_sign_less_participants() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let participants = generate_participants(5);
        let threshold = 4;
        let result0 = run_keygen(&participants, threshold, &mut rng);
        assert_public_key_invariant(&result0);
        let coordinators = vec![result0[0].0];

        let pub_key = result0[2].1.public_key;

        // Run heavy reshare
        let new_threshold = 3;
        let mut new_participant = participants.clone();
        new_participant.pop();
        let key_packages = run_reshare(
            &participants,
            &pub_key,
            &result0,
            threshold,
            new_threshold,
            &new_participant,
            &mut rng,
        );
        assert_public_key_invariant(&key_packages);

        let participants: Vec<_> = key_packages
            .iter()
            .take(key_packages.len())
            .map(|(val, _)| *val)
            .collect();
        let shares: Vec<_> = key_packages
            .iter()
            .take(key_packages.len())
            .map(|(_, keygen)| keygen.private_share.to_scalar())
            .collect();

        // Test public key
        let p_list = ParticipantList::new(&participants).unwrap();
        let mut x = Ed25519ScalarField::zero();
        for (p, share) in participants.iter().zip(shares.iter()) {
            x += p_list.lagrange::<Ed25519Sha512>(*p).unwrap() * share;
        }
        assert_eq!(<Ed25519Group>::generator() * x, pub_key.to_element());

        // Sign
        let msg = "hello_near";
        let msg_hash = hash(&msg).unwrap();

        let data = test_run_signature_protocols(
            &key_packages,
            new_threshold,
            &coordinators,
            new_threshold,
            msg_hash,
        )
        .unwrap();
        let signature = one_coordinator_output(data, coordinators[0]).unwrap();
        assert!(key_packages[0]
            .1
            .public_key
            .verify(msg_hash.as_ref(), &signature)
            .is_ok());
    }

    #[test]
    fn test_signature_correctness() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let threshold = 6;
        let keys = build_key_packages_with_dealer(11, threshold, &mut rng);
        let public_key = keys[0].1.public_key.to_element();

        let msg = b"hello worldhello worldhello worlregerghwhrth".to_vec();
        let index = rng.gen_range(0..keys.len());
        let coordinator = keys[index as usize].0;

        let participants_sign_builder = keys
            .iter()
            .map(|(p, keygen_output)| {
                let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
                (*p, (keygen_output.clone(), rng_p))
            })
            .collect();

        // This checks the output signature validity internally
        let result =
            crate::test_utils::run_sign::<Ed25519Sha512, (KeygenOutput, MockCryptoRng), _, _>(
                participants_sign_builder,
                coordinator,
                public_key,
                Ed25519ScalarField::zero(),
                |participants, coordinator, me, _, (keygen_output, p_rng), _| {
                    sign(
                        participants,
                        threshold as usize,
                        me,
                        coordinator,
                        keygen_output,
                        msg.clone(),
                        p_rng,
                    )
                    .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
                },
            )
            .unwrap();
        let signature = one_coordinator_output(result, coordinator).unwrap();

        insta::assert_json_snapshot!(signature);
    }
}
