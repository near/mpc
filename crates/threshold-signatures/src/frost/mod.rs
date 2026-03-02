use frost_core::{
    keys::SigningShare,
    round1::{commit, SigningCommitments, SigningNonces},
    Field, Group, Identifier,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{
    errors::{InitializationError, ProtocolError},
    participants::{Participant, ParticipantList},
    protocol::{
        helpers::recv_from_others,
        internal::{make_protocol, Comms, SharedChannel},
        Protocol,
    },
    Ciphersuite, KeygenOutput, ReconstructionLowerBound,
};

pub mod eddsa;
pub mod redjubjub;

/// The necessary inputs for the creation of a presignature.
pub struct PresignArguments<C: Ciphersuite> {
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    pub keygen_out: KeygenOutput<C>,
    /// The threshold for the scheme
    pub threshold: ReconstructionLowerBound,
}

/// The output of the presigning protocol.
///
/// This output is basically all the parts of the signature that we can perform
/// without knowing the message.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PresignOutput<C: Ciphersuite + Send + 'static> {
    /// The public nonce commitment.
    pub nonces: SigningNonces<C>,
    pub commitments_map: BTreeMap<Identifier<C>, SigningCommitments<C>>,
}

/// Runs Presigning of either `EdDSA` or `RedDSA`
pub fn presign<C>(
    participants: &[Participant],
    me: Participant,
    args: &PresignArguments<C>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = PresignOutput<C>>, InitializationError>
where
    C: Ciphersuite + Send,
    <<<C as frost_core::Ciphersuite>::Group as Group>::Field as Field>::Scalar: Send,
    <<C as frost_core::Ciphersuite>::Group as frost_core::Group>::Element: std::marker::Send,
{
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // validate threshold
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.into(),
            max: participants.len(),
        });
    }

    let ctx = Comms::new();
    let fut = do_presign(
        ctx.shared_channel(),
        participants,
        me,
        args.keygen_out.private_share,
        rng,
    );
    Ok(make_protocol(ctx, fut))
}

async fn do_presign<C: Ciphersuite + Send>(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    signing_share: SigningShare<C>,
    mut rng: impl CryptoRngCore,
) -> Result<PresignOutput<C>, ProtocolError> {
    // Round 1
    let mut commitments_map: BTreeMap<Identifier<C>, SigningCommitments<C>> = BTreeMap::new();

    // Creating two commitments and corresponding nonces
    let (nonces, commitments) = commit(&signing_share, &mut rng);
    commitments_map.insert(me.to_identifier()?, commitments);

    let commit_waitpoint = chan.next_waitpoint();
    // Sending the commitments to all
    chan.send_many(commit_waitpoint, &commitments)?;

    // Collecting the commitments
    for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
        commitments_map.insert(from.to_identifier()?, commitment);
    }

    Ok(PresignOutput {
        nonces,
        commitments_map,
    })
}

/// Verifies that the sign inputs are valid
pub fn assert_sign_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionLowerBound>,
    me: Participant,
    coordinator: Participant,
) -> Result<ParticipantList, InitializationError> {
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
    Ok(participants)
}
