use frost_secp256k1::keys::SigningShare;
use frost_secp256k1::*;

use crate::ecdsa::KeygenOutput;
use crate::generic_dkg::*;
use crate::protocol::internal::{make_protocol, Comms};
use crate::protocol::{InitializationError, Participant, Protocol};
use futures::FutureExt;

type E = Secp256K1Sha256;

/// Performs the Ed25519 DKG protocol
pub fn keygen(
    participants: &[Participant],
    me: Participant,
    threshold: usize,
) -> Result<impl Protocol<Output = KeygenOutput>, InitializationError> {
    let ctx = Comms::new();
    let participants = assert_keygen_invariants(participants, me, threshold)?;
    let fut =
        do_keygen(ctx.shared_channel(), participants, me, threshold).map(|x| x.map(Into::into));
    Ok(make_protocol(ctx, fut))
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
    let ctx = Comms::new();
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
        ctx.shared_channel(),
        participants,
        me,
        threshold,
        old_signing_key,
        old_public_key,
        old_participants,
    )
    .map(|x| x.map(Into::into));
    Ok(make_protocol(ctx, fut))
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
    let ctx = Comms::new();
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
        ctx.shared_channel(),
        participants,
        me,
        threshold,
        old_signing_key,
        old_public_key,
        old_participants,
    )
    .map(|x| x.map(Into::into));
    Ok(make_protocol(ctx, fut))
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::ecdsa::test::{assert_public_key_invariant, run_keygen, run_refresh, run_reshare};
    use crate::participants::ParticipantList;
    use crate::protocol::Participant;
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
        let shares = vec![
            result[0].1.private_share.to_scalar(),
            result[1].1.private_share.to_scalar(),
            result[2].1.private_share.to_scalar(),
        ];
        let p_list = ParticipantList::new(&participants).unwrap();
        let x = p_list.generic_lagrange::<E>(participants[0]) * shares[0]
            + p_list.generic_lagrange::<E>(participants[1]) * shares[1]
            + p_list.generic_lagrange::<E>(participants[2]) * shares[2];
        assert_eq!(<Secp256K1Group>::generator() * x, pub_key);
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
        let shares = vec![
            result1[0].1.private_share.to_scalar(),
            result1[1].1.private_share.to_scalar(),
            result1[2].1.private_share.to_scalar(),
        ];
        let p_list = ParticipantList::new(&participants).unwrap();
        let x = p_list.generic_lagrange::<E>(participants[0]) * shares[0]
            + p_list.generic_lagrange::<E>(participants[1]) * shares[1]
            + p_list.generic_lagrange::<E>(participants[2]) * shares[2];
        assert_eq!(<Secp256K1Group>::generator() * x, pub_key);
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

        let pub_key = result0[2].1.public_key.clone();

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
        let shares = vec![
            result1[0].1.private_share.to_scalar(),
            result1[1].1.private_share.to_scalar(),
            result1[2].1.private_share.to_scalar(),
            result1[3].1.private_share.to_scalar(),
        ];
        let p_list = ParticipantList::new(&participants).unwrap();
        let x = p_list.generic_lagrange::<E>(participants[0]) * shares[0]
            + p_list.generic_lagrange::<E>(participants[1]) * shares[1]
            + p_list.generic_lagrange::<E>(participants[2]) * shares[2]
            + p_list.generic_lagrange::<E>(participants[3]) * shares[3];
        assert_eq!(<Secp256K1Group>::generator() * x, pub_key.to_element());

        Ok(())
    }
}
