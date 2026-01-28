use super::{PresignArguments, PresignOutput};
use crate::{
    errors::{InitializationError, ProtocolError},
    participants::{Participant, ParticipantList},
    protocol::{
        helpers::recv_from_others,
        internal::{make_protocol, Comms, SharedChannel},
        Protocol,
    },
};
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;

use reddsa::frost::redjubjub::{
    keys::SigningShare,
    round1::{commit, SigningCommitments},
    Identifier,
};

pub fn presign(
    participants: &[Participant],
    me: Participant,
    args: &PresignArguments,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = PresignOutput>, InitializationError> {
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
    if args.threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold,
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

#[allow(clippy::too_many_lines)]
async fn do_presign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    signing_share: SigningShare,
    mut rng: impl CryptoRngCore,
) -> Result<PresignOutput, ProtocolError> {
    // Round 1
    let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();

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

#[cfg(test)]
mod test {
    use crate::frost::redjubjub::test::{build_key_packages_with_dealer, test_run_presignature};
    use crate::test_utils::MockCryptoRng;
    use rand::SeedableRng;

    #[test]
    fn check_presignatures_terms() {
        let mut rng = MockCryptoRng::seed_from_u64(42);

        let max_signers = 10;
        let threshold = 10;
        let actual_signers = 10;

        let key_packages = build_key_packages_with_dealer(max_signers, threshold, &mut rng);
        // add the presignatures here
        let presignatures =
            test_run_presignature(&key_packages, threshold as usize, actual_signers).unwrap();

        for (i, (p1, presig1)) in presignatures.iter().enumerate() {
            for (p2, presig2) in presignatures.iter().skip(i + 1) {
                assert_ne!(p1, p2);
                assert_ne!(presig1.nonces, presig2.nonces);
                assert_eq!(presig1.commitments_map, presig2.commitments_map);
            }
        }
    }

    #[test]
    fn check_presignatures_terms_with_less_active_participants() {
        let mut rng = MockCryptoRng::seed_from_u64(42);

        let max_signers = 10;
        let threshold = 7;
        let actual_signers = 8;

        let key_packages = build_key_packages_with_dealer(max_signers, threshold, &mut rng);
        // add the presignatures here
        let mut presignatures =
            test_run_presignature(&key_packages, threshold as usize, actual_signers).unwrap();
        while let Some((p1, presig1)) = presignatures.pop() {
            for (p2, presig2) in &presignatures {
                assert!(p1 != *p2);
                assert!(presig1.nonces != presig2.nonces);
                assert_eq!(presig1.commitments_map, presig2.commitments_map);
            }
        }
    }
}
