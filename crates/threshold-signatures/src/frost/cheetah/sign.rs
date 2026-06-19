//! Wraps FROST signature generation for the Cheetah (SchnorrCheetah) ciphersuite
//! into a `cait-sith`-style `Protocol`. Mirrors `frost/eddsa/sign.rs`, but over the
//! generic `frost_core` types parameterized by [`CheetahTip5`] (Cheetah has no
//! off-the-shelf ciphersuite crate). Produced signatures are Nockchain-valid; the
//! chain signature is `(c, s = z)` (see `frost/cheetah.rs`).

use super::{CheetahTip5, KeygenOutput, PresignOutput, SignatureOption};
use crate::{
    Participant, ParticipantList, ReconstructionThreshold,
    errors::{InitializationError, ProtocolError},
    frost::assert_sign_inputs,
    protocol::{
        Protocol,
        helpers::recv_from_others,
        internal::{Comms, SharedChannel, make_protocol},
    },
};

use frost_core::{
    CheaterDetection, Identifier, SigningPackage, VerifyingKey, aggregate_custom,
    keys::{KeyPackage, PublicKeyPackage, SigningShare},
    round1, round2,
};
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

// for backwards compatibility / parity with the other ciphersuites
pub use sign_v1 as sign;

/// Max incoming buffer entries for the coordinator in the Cheetah sign v1 protocol.
pub(crate) const CHEETAH_SIGN_V1_MAX_INCOMING_COORDINATOR_ENTRIES: usize = 2;
/// Max incoming buffer entries for the coordinator in the Cheetah sign v2 protocol.
pub(crate) const CHEETAH_SIGN_V2_MAX_INCOMING_COORDINATOR_ENTRIES: usize = 1;

type CheetahIdentifier = Identifier<CheetahTip5>;
type CheetahSigningPackage = SigningPackage<CheetahTip5>;
type CheetahSigningCommitments = round1::SigningCommitments<CheetahTip5>;
type CheetahSignatureShare = round2::SignatureShare<CheetahTip5>;
type CheetahKeyPackage = KeyPackage<CheetahTip5>;
type CheetahVerifyingKey = VerifyingKey<CheetahTip5>;
type CheetahSigningShare = SigningShare<CheetahTip5>;

/// Sign from scratch (round-1 commitments computed inline). Runs as coordinator or
/// participant depending on `me == coordinator`.
///
/// WARNING (from FROST docs): the entire message must be sent to participants. For
/// large messages, pre-hash via a dedicated ciphersuite — here `message` is the
/// 5-belt Nockchain sig-hash digest (40 LE bytes; see `super::message_from_digest`).
pub fn sign_v1<T, R>(
    participants: &[Participant],
    threshold: T,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    rng: R,
) -> Result<impl Protocol<Output = SignatureOption> + use<T, R>, InitializationError>
where
    T: Into<ReconstructionThreshold>,
    R: CryptoRngCore + Send + 'static,
{
    let threshold = threshold.into();
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;

    let comms = Comms::with_buffer_capacity(CHEETAH_SIGN_V1_MAX_INCOMING_COORDINATOR_ENTRIES);
    let chan = comms.shared_channel();
    let fut = fut_wrapper_v1(
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

/// Sign using a precomputed presignature (one online round).
pub fn sign_v2<T>(
    participants: &[Participant],
    threshold: T,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
) -> Result<impl Protocol<Output = SignatureOption> + use<T>, InitializationError>
where
    T: Into<ReconstructionThreshold> + Copy,
{
    let participants = assert_sign_inputs(participants, threshold, me, coordinator)?;

    let comms = Comms::with_buffer_capacity(CHEETAH_SIGN_V2_MAX_INCOMING_COORDINATOR_ENTRIES);
    let chan = comms.shared_channel();
    let fut = fut_wrapper_v2(
        chan,
        participants,
        threshold.into(),
        me,
        coordinator,
        keygen_output,
        presignature,
        message,
    );
    Ok(make_protocol(comms, fut))
}

async fn do_sign_coordinator_v1(
    mut chan: SharedChannel,
    participants: ParticipantList,
    threshold: ReconstructionThreshold,
    me: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    rng: &mut impl CryptoRngCore,
) -> Result<SignatureOption, ProtocolError> {
    let mut commitments_map: BTreeMap<CheetahIdentifier, CheetahSigningCommitments> =
        BTreeMap::new();

    let signing_share = keygen_output.private_share;

    let (nonces, commitments) = round1::commit(&signing_share, rng);
    let nonces = Zeroizing::new(nonces);
    commitments_map.insert(me.to_identifier()?, commitments);

    let commit_waitpoint = chan.next_waitpoint();
    for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
        commitments_map.insert(from.to_identifier()?, commitment);
    }

    let signing_package = CheetahSigningPackage::new(commitments_map, message.as_slice());

    let mut signature_shares: BTreeMap<CheetahIdentifier, CheetahSignatureShare> = BTreeMap::new();

    let r2_wait_point = chan.next_waitpoint();
    chan.send_many(r2_wait_point, &signing_package)?;

    let vk_package = keygen_output.public_key;
    let key_package = construct_key_package(threshold, me, signing_share, &vk_package)?;
    let key_package = Zeroizing::new(key_package);
    let signature_share = round2::sign(&signing_package, &nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    signature_shares.insert(me.to_identifier()?, signature_share);
    for (from, signature_share) in recv_from_others(&chan, r2_wait_point, &participants, me).await? {
        signature_shares.insert(from.to_identifier()?, signature_share);
    }

    // cheater-detection disabled: empty verifying-shares map (no extra guarantees).
    let public_key_package = PublicKeyPackage::new(BTreeMap::new(), vk_package, None);
    let signature = aggregate_custom(
        &signing_package,
        &signature_shares,
        &public_key_package,
        CheaterDetection::Disabled,
    )
    .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    Ok(Some(signature))
}

async fn do_sign_coordinator_v2(
    mut chan: SharedChannel,
    participants: ParticipantList,
    threshold: ReconstructionThreshold,
    me: Participant,
    keygen_output: KeygenOutput,
    presignature: &PresignOutput,
    message: Vec<u8>,
) -> Result<SignatureOption, ProtocolError> {
    let signing_package =
        CheetahSigningPackage::new(presignature.commitments_map.clone(), message.as_slice());

    let mut signature_shares: BTreeMap<CheetahIdentifier, CheetahSignatureShare> = BTreeMap::new();

    let vk_package = keygen_output.public_key;
    let key_package =
        construct_key_package(threshold, me, keygen_output.private_share, &vk_package)?;
    let key_package = Zeroizing::new(key_package);
    let signature_share = round2::sign(&signing_package, &presignature.nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;
    signature_shares.insert(me.to_identifier()?, signature_share);

    let sign_waitpoint = chan.next_waitpoint();
    for (from, signature_share) in recv_from_others(&chan, sign_waitpoint, &participants, me).await?
    {
        signature_shares.insert(from.to_identifier()?, signature_share);
    }

    let public_key_package = PublicKeyPackage::new(BTreeMap::new(), vk_package, None);
    let signature = aggregate_custom(
        &signing_package,
        &signature_shares,
        &public_key_package,
        CheaterDetection::Disabled,
    )
    .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    Ok(Some(signature))
}

async fn do_sign_participant_v1(
    mut chan: SharedChannel,
    threshold: ReconstructionThreshold,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    rng: &mut impl CryptoRngCore,
) -> Result<SignatureOption, ProtocolError> {
    if coordinator == me {
        return Err(ProtocolError::AssertionFailed(
            "do_sign_participant cannot be called for a coordinator".to_string(),
        ));
    }

    let signing_share = keygen_output.private_share;

    let (nonces, commitments) = round1::commit(&signing_share, rng);
    let nonces = Zeroizing::new(nonces);

    let commit_waitpoint = chan.next_waitpoint();
    chan.send_private(commit_waitpoint, coordinator, &commitments)?;

    let r2_wait_point = chan.next_waitpoint();
    let signing_package = loop {
        let (from, signing_package): (_, CheetahSigningPackage) = chan.recv(r2_wait_point).await?;
        if from != coordinator {
            continue;
        }
        break signing_package;
    };

    if signing_package.message() != message.as_slice() {
        return Err(ProtocolError::AssertionFailed(
            "signing-package message doesn't match the expected message".to_string(),
        ));
    }

    let vk_package = keygen_output.public_key;
    let key_package = construct_key_package(threshold, me, signing_share, &vk_package)?;
    let key_package = Zeroizing::new(key_package);
    let signature_share = round2::sign(&signing_package, &nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    chan.send_private(r2_wait_point, coordinator, &signature_share)?;

    Ok(None)
}

fn do_sign_participant_v2(
    mut chan: SharedChannel,
    threshold: ReconstructionThreshold,
    me: Participant,
    coordinator: Participant,
    keygen_output: &KeygenOutput,
    presignature: &PresignOutput,
    message: &[u8],
) -> Result<SignatureOption, ProtocolError> {
    if coordinator == me {
        return Err(ProtocolError::AssertionFailed(
            "do_sign_participant cannot be called for a coordinator".to_string(),
        ));
    }

    let key_package = construct_key_package(
        threshold,
        me,
        keygen_output.private_share,
        &keygen_output.public_key,
    )?;
    let key_package = Zeroizing::new(key_package);

    let signing_package =
        CheetahSigningPackage::new(presignature.commitments_map.clone(), message);
    let signature_share = round2::sign(&signing_package, &presignature.nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    let sign_waitpoint = chan.next_waitpoint();
    chan.send_private(sign_waitpoint, coordinator, &signature_share)?;

    Ok(None)
}

/// Build the FROST `KeyPackage` for this signer from its share + the group key.
fn construct_key_package(
    threshold: ReconstructionThreshold,
    me: Participant,
    signing_share: CheetahSigningShare,
    verifying_key: &CheetahVerifyingKey,
) -> Result<CheetahKeyPackage, ProtocolError> {
    let identifier = me.to_identifier()?;
    let verifying_share = signing_share.into();

    Ok(KeyPackage::new(
        identifier,
        signing_share,
        verifying_share,
        *verifying_key,
        u16::try_from(threshold.value()).map_err(|_| {
            ProtocolError::Other("threshold cannot be converted to u16".to_string())
        })?,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn fut_wrapper_v1(
    chan: SharedChannel,
    participants: ParticipantList,
    threshold: ReconstructionThreshold,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    mut rng: impl CryptoRngCore,
) -> Result<SignatureOption, ProtocolError> {
    if me == coordinator {
        do_sign_coordinator_v1(
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
        do_sign_participant_v1(
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

#[allow(clippy::too_many_arguments)]
async fn fut_wrapper_v2(
    chan: SharedChannel,
    participants: ParticipantList,
    threshold: ReconstructionThreshold,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
) -> Result<SignatureOption, ProtocolError> {
    if me == coordinator {
        do_sign_coordinator_v2(
            chan,
            participants,
            threshold,
            me,
            keygen_output,
            &presignature,
            message,
        )
        .await
    } else {
        do_sign_participant_v2(
            chan,
            threshold,
            me,
            coordinator,
            &keygen_output,
            &presignature,
            &message,
        )
    }
}
