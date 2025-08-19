use frost_ed25519::keys::SigningShare;
use frost_ed25519::{Ed25519Sha512, VerifyingKey};

use crate::eddsa::KeygenOutput;
use crate::generic_dkg::*;
use crate::protocol::internal::{make_protocol, Comms};
use crate::protocol::{InitializationError, Participant, Protocol};
use futures::FutureExt;

type E = Ed25519Sha512;

/// Performs the Ed25519 DKG protocol
pub fn keygen(
    participants: &[Participant],
    me: Participant,
    threshold: usize,
) -> Result<impl Protocol<Output = KeygenOutput>, InitializationError> {
    let comms = Comms::new();
    let participants = assert_keygen_invariants(participants, me, threshold)?;
    let fut =
        do_keygen(comms.shared_channel(), participants, me, threshold).map(|x| x.map(Into::into));
    Ok(make_protocol(comms, fut))
}

/// Performs the Ed25519 Reshare protocol
pub fn reshare(
    old_participants: &[Participant],
    old_threshold: usize,
    old_signing_key: Option<SigningShare>,
    old_public_key: VerifyingKey,
    new_participants: &[Participant],
    new_threshold: usize,
    me: Participant,
) -> Result<impl Protocol<Output = KeygenOutput>, InitializationError> {
    let comms = Comms::new();
    let threshold = new_threshold;
    let (participants, old_participants) = reshare_assertions::<E>(
        new_participants,
        me,
        threshold,
        old_signing_key,
        old_threshold,
        old_participants,
    )?;
    let fut = do_reshare(
        comms.shared_channel(),
        participants,
        me,
        threshold,
        old_signing_key,
        old_public_key,
        old_participants,
    )
    .map(|x| x.map(Into::into));
    Ok(make_protocol(comms, fut))
}

/// Performs the Ed25519 Refresh protocol
pub fn refresh(
    old_signing_key: Option<SigningShare>,
    old_public_key: VerifyingKey,
    new_participants: &[Participant],
    new_threshold: usize,
    me: Participant,
) -> Result<impl Protocol<Output = KeygenOutput>, InitializationError> {
    if old_signing_key.is_none() {
        return Err(InitializationError::BadParameters(format!(
            "The participant {me:?} is running refresh without an old share",
        )));
    }
    let comms = Comms::new();
    let threshold = new_threshold;
    let (participants, old_participants) = reshare_assertions::<E>(
        new_participants,
        me,
        threshold,
        old_signing_key,
        threshold,
        new_participants,
    )?;
    let fut = do_reshare(
        comms.shared_channel(),
        participants,
        me,
        threshold,
        old_signing_key,
        old_public_key,
        old_participants,
    )
    .map(|x| x.map(Into::into));
    Ok(make_protocol(comms, fut))
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::eddsa::test::{assert_public_key_invariant, run_keygen, run_refresh, run_reshare};
    use crate::participants::ParticipantList;
    use crate::protocol::Participant;
    use frost_core::Group;
    use frost_ed25519::Ed25519Group;
    use std::error::Error;

    #[test]
    fn test_keygen() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(31u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let threshold = 3;

        let result = run_keygen(&participants, threshold)?;
        assert_public_key_invariant(&result)?;

        assert!(result.len() == participants.len());
        assert_eq!(result[0].1.public_key, result[1].1.public_key);
        assert_eq!(result[1].1.public_key, result[2].1.public_key);

        let pub_key = result[2].1.public_key.to_element();

        let participants = vec![result[0].0, result[1].0, result[2].0];
        let shares = [
            result[0].1.private_share.to_scalar(),
            result[1].1.private_share.to_scalar(),
            result[2].1.private_share.to_scalar(),
        ];
        let p_list = ParticipantList::new(&participants).unwrap();
        let x = p_list.lagrange::<E>(participants[0]).unwrap() * shares[0]
            + p_list.lagrange::<E>(participants[1]).unwrap() * shares[1]
            + p_list.lagrange::<E>(participants[2]).unwrap() * shares[2];
        assert_eq!(<Ed25519Group>::generator() * x, pub_key);
        Ok(())
    }

    #[test]
    fn test_refresh() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(31u32),
            Participant::from(2u32),
        ];
        let threshold = 3;

        let result0 = run_keygen(&participants, threshold)?;
        assert_public_key_invariant(&result0)?;

        let pub_key = result0[2].1.public_key.to_element();

        let result1 = run_refresh(&participants, result0, threshold)?;
        assert_public_key_invariant(&result1)?;

        let participants = vec![result1[0].0, result1[1].0, result1[2].0];
        let shares = [
            result1[0].1.private_share.to_scalar(),
            result1[1].1.private_share.to_scalar(),
            result1[2].1.private_share.to_scalar(),
        ];
        let p_list = ParticipantList::new(&participants).unwrap();
        let x = p_list.lagrange::<E>(participants[0]).unwrap() * shares[0]
            + p_list.lagrange::<E>(participants[1]).unwrap() * shares[1]
            + p_list.lagrange::<E>(participants[2]).unwrap() * shares[2];
        assert_eq!(<Ed25519Group>::generator() * x, pub_key);
        Ok(())
    }

    #[test]
    fn test_reshare() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let threshold0 = 2;
        let threshold1 = 3;

        let result0 = run_keygen(&participants, threshold0)?;
        assert_public_key_invariant(&result0)?;

        let pub_key = result0[2].1.public_key;

        let mut new_participant = participants.clone();
        new_participant.push(Participant::from(31u32));
        let result1 = run_reshare(
            &participants,
            &pub_key,
            result0,
            threshold0,
            threshold1,
            new_participant,
        )?;
        assert_public_key_invariant(&result1)?;

        let participants = vec![result1[0].0, result1[1].0, result1[2].0, result1[3].0];
        let shares = [
            result1[0].1.private_share.to_scalar(),
            result1[1].1.private_share.to_scalar(),
            result1[2].1.private_share.to_scalar(),
            result1[3].1.private_share.to_scalar(),
        ];
        let p_list = ParticipantList::new(&participants).unwrap();
        let x = p_list.lagrange::<E>(participants[0]).unwrap() * shares[0]
            + p_list.lagrange::<E>(participants[1]).unwrap() * shares[1]
            + p_list.lagrange::<E>(participants[2]).unwrap() * shares[2]
            + p_list.lagrange::<E>(participants[3]).unwrap() * shares[3];
        assert_eq!(<Ed25519Group>::generator() * x, pub_key.to_element());

        Ok(())
    }
}
