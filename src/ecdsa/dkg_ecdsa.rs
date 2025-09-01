#[cfg(test)]
mod test {
    use frost_secp256k1::{Group, Secp256K1Group, Secp256K1Sha256};
    type E = Secp256K1Sha256;

    use crate::participants::ParticipantList;
    use crate::protocol::Participant;
    use crate::test::{
        assert_public_key_invariant, generate_participants, run_keygen, run_refresh, run_reshare,
    };
    use std::error::Error;

    #[test]
    fn test_keygen() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(31u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let threshold = 3;

        let result = run_keygen::<E>(&participants, threshold)?;
        assert_public_key_invariant(&result);

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

        let result0 = run_keygen::<E>(&participants, threshold)?;
        assert_public_key_invariant(&result0);

        let pub_key = result0[2].1.public_key.to_element();

        let result1 = run_refresh(&participants, result0, threshold)?;
        assert_public_key_invariant(&result1);

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
        assert_eq!(<Secp256K1Group>::generator() * x, pub_key);
        Ok(())
    }

    #[test]
    fn test_reshare() -> Result<(), Box<dyn Error>> {
        let participants = generate_participants(3);
        let threshold0 = 2;
        let threshold1 = 3;

        let result0 = run_keygen::<E>(&participants, threshold0)?;
        assert_public_key_invariant(&result0);

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
        assert_public_key_invariant(&result1);

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
        assert_eq!(<Secp256K1Group>::generator() * x, pub_key.to_element());

        Ok(())
    }
}
