use crate::confidential_key_derivation::{
    AppId, CKDCoordinatorOutput, CKDOutput, CoefficientCommitment, SigningShare, VerifyingKey,
};
use crate::participants::{ParticipantCounter, ParticipantList};
use crate::protocol::internal::{make_protocol, Comms, SharedChannel};
use crate::protocol::{errors::InitializationError, errors::ProtocolError, Participant, Protocol};

use frost_core::Ciphersuite;
use rand_core::CryptoRngCore;

use frost_secp256k1::Secp256K1Sha256;

use k256::ProjectivePoint;
use k256::{
    elliptic_curve::hash2curve::{ExpandMsgXof, GroupDigest},
    Secp256k1,
};

const DOMAIN: &[u8] = b"NEAR CURVE_XOF:SHAKE-256_SSWU_RO_";

fn hash2curve(app_id: &AppId) -> Result<ProjectivePoint, ProtocolError> {
    let hash = <Secp256k1 as GroupDigest>::hash_from_bytes::<ExpandMsgXof<sha3::Shake256>>(
        &[app_id.as_ref()],
        &[DOMAIN],
    )
    .map_err(|_| ProtocolError::HashingError)?;
    Ok(hash)
}

#[allow(clippy::too_many_arguments)]
async fn do_ckd_participant(
    mut chan: SharedChannel,
    participants: ParticipantList,
    coordinator: Participant,
    me: Participant,
    private_share: SigningShare,
    app_id: &AppId,
    app_pk: VerifyingKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutput, ProtocolError> {
    // y <- ZZq* , Y <- y * G
    let (y, big_y) = Secp256K1Sha256::generate_nonce(rng);
    // H(app_id) when H is a random oracle
    let hash_point = hash2curve(app_id)?;
    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();
    // C <- S + y . A
    let big_c = big_s + app_pk.to_element() * y;
    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<Secp256K1Sha256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = CoefficientCommitment::new(big_y * lambda_i);
    let norm_big_c = CoefficientCommitment::new(big_c * lambda_i);

    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
}

async fn do_ckd_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    private_share: SigningShare,
    app_id: &AppId,
    app_pk: VerifyingKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutput, ProtocolError> {
    // y <- ZZq* , Y <- y * G
    let (y, big_y) = Secp256K1Sha256::generate_nonce(rng);
    // H(app_id) when H is a random oracle
    let hash_point = hash2curve(app_id)?;
    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();
    // C <- S + y . A
    let big_c = big_s + app_pk.to_element() * y;
    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<Secp256K1Sha256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let mut norm_big_y = big_y * lambda_i;
    let mut norm_big_c = big_c * lambda_i;

    // Receive everyone's inputs and add them together
    let mut seen = ParticipantCounter::new(&participants);
    let waitpoint = chan.next_waitpoint();

    seen.put(me);
    while !seen.full() {
        let (from, (big_y, big_c)): (_, (CoefficientCommitment, CoefficientCommitment)) =
            chan.recv(waitpoint).await?;
        if !seen.put(from) {
            continue;
        }
        norm_big_y += big_y.value();
        norm_big_c += big_c.value();
    }
    let ckd_output = CKDCoordinatorOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
}

/// Runs the confidential key derivation protocol
/// This exact same function is called for both
/// a coordinator and a normal participant.
/// Depending on whether the current participant is a coordinator or not,
/// runs the signature protocol as either a participant or a coordinator.
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    private_share: SigningShare,
    app_id: impl Into<AppId>,
    app_pk: VerifyingKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutput>, InitializationError> {
    // not enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    };

    // kick out duplicates
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    };
    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    };

    let comms = Comms::new();
    let chan = comms.shared_channel();

    let fut = run_ckd_protocol(
        chan,
        coordinator,
        me,
        participants,
        private_share,
        app_id.into(),
        app_pk,
        rng,
    );
    Ok(make_protocol(comms, fut))
}

/// Depending on whether the current participant is a coordinator or not,
/// runs the ckd protocol as either a participant or a coordinator.
#[allow(clippy::too_many_arguments)]
async fn run_ckd_protocol(
    chan: SharedChannel,
    coordinator: Participant,
    me: Participant,
    participants: ParticipantList,
    private_share: SigningShare,
    app_id: AppId,
    app_pk: VerifyingKey,
    mut rng: impl CryptoRngCore,
) -> Result<CKDOutput, ProtocolError> {
    if me == coordinator {
        do_ckd_coordinator(
            chan,
            participants,
            me,
            private_share,
            &app_id,
            app_pk,
            &mut rng,
        )
        .await
    } else {
        do_ckd_participant(
            chan,
            participants,
            coordinator,
            me,
            private_share,
            &app_id,
            app_pk,
            &mut rng,
        )
        .await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::polynomials::Polynomial;
    use crate::protocol::run_protocol;
    use std::error::Error;

    use rand_core::{OsRng, RngCore};

    #[test]
    fn test_hash2curve() -> Result<(), Box<dyn Error>> {
        let app_id = b"Hello Near";
        let app_id_same = b"Hello Near";
        let pt1 = hash2curve(&AppId::from(app_id)).unwrap();
        let pt2 = hash2curve(&AppId::from(app_id_same)).unwrap();
        assert!(pt1 == pt2);

        let app_id = b"Hello Near!";
        let pt2 = hash2curve(&AppId::from(app_id)).unwrap();
        assert!(pt1 != pt2);
        Ok(())
    }

    #[test]
    fn test_ckd() -> Result<(), Box<dyn Error>> {
        let threshold = 3;

        let f =
            Polynomial::<Secp256K1Sha256>::generate_polynomial(None, threshold - 1, &mut OsRng)?;

        // Create the threshold signer's master secret key
        let msk = f.eval_at_zero()?;

        // Create the app necessary items
        let app_id = AppId::from(b"Near App");
        let (app_sk, app_pk) = Secp256K1Sha256::generate_nonce(&mut OsRng);
        let app_pk = VerifyingKey::new(app_pk);

        let expected_confidential_key = hash2curve(&app_id).unwrap() * msk.0;

        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];

        // choose a coordinator at random
        let index = OsRng.next_u32() % participants.len() as u32;
        let coordinator = participants[index as usize];

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = CKDOutput>>)> =
            Vec::with_capacity(participants.len());

        for p in &participants {
            let share = f.eval_at_participant(*p)?;
            let private_share = SigningShare::new(share.0);

            let protocol = ckd(
                &participants,
                coordinator,
                *p,
                private_share,
                app_id.clone(),
                app_pk,
                OsRng,
            )?;

            protocols.push((*p, Box::new(protocol)));
        }

        let result = run_protocol(protocols)?;

        // test one single some for the coordinator
        let mut some_iter = result.into_iter().filter(|(_, ckd)| ckd.is_some());

        let ckd = some_iter
            .next()
            .map(|(_, c)| c.unwrap())
            .expect("Expected exactly one Some(CKDCoordinatorOutput)");
        assert!(
            some_iter.next().is_none(),
            "More than one Some(CKDCoordinatorOutput)"
        );

        // compute msk . H(app_id)
        let confidential_key = ckd.unmask(app_sk);

        assert_eq!(
            confidential_key.value(),
            expected_confidential_key,
            "Keys should be equal"
        );
        Ok(())
    }

    #[test]
    fn test_ckd_duplicate_participants() {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(1u32),
        ];
        let coordinator = Participant::from(0u32);
        let me = Participant::from(0u32);
        let (_app_sk, app_pk) = Secp256K1Sha256::generate_nonce(&mut OsRng);
        let app_pk = VerifyingKey::new(app_pk);
        let f = Polynomial::<Secp256K1Sha256>::generate_polynomial(None, 2, &mut OsRng).unwrap();
        let private_share = SigningShare::new(f.eval_at_participant(me).unwrap().0);
        let app_id = AppId::from(b"test");

        let result = ckd(
            &participants,
            coordinator,
            me,
            private_share,
            app_id,
            app_pk,
            OsRng,
        );
        match result {
            Ok(_) => panic!("Expected an error, but got Ok"),
            Err(err) => assert_eq!(err, InitializationError::DuplicateParticipants),
        }
    }

    #[test]
    fn test_ckd_not_enough_participants() {
        let participants = vec![Participant::from(0u32)];
        let coordinator = Participant::from(0u32);
        let me = Participant::from(0u32);
        let (_app_sk, app_pk) = Secp256K1Sha256::generate_nonce(&mut OsRng);
        let app_pk = VerifyingKey::new(app_pk);
        let f = Polynomial::<Secp256K1Sha256>::generate_polynomial(None, 2, &mut OsRng).unwrap();
        let private_share = SigningShare::new(f.eval_at_participant(me).unwrap().0);
        let app_id = AppId::from(b"test");

        let result = ckd(
            &participants,
            coordinator,
            me,
            private_share,
            app_id,
            app_pk,
        );
        match result {
            Ok(_) => panic!("Expected an error, but got Ok"),
            Err(err) => assert_eq!(
                err,
                InitializationError::NotEnoughParticipants { participants: 1 }
            ),
        }
    }

    #[test]
    fn test_ckd_me_not_in_participants() {
        let participants = vec![Participant::from(0u32), Participant::from(1u32)];
        let coordinator = Participant::from(0u32);
        let me = Participant::from(2u32); // Me is not in the list
        let (_app_sk, app_pk) = Secp256K1Sha256::generate_nonce(&mut OsRng);
        let app_pk = VerifyingKey::new(app_pk);
        let f = Polynomial::<Secp256K1Sha256>::generate_polynomial(None, 2, &mut OsRng).unwrap();
        let private_share =
            SigningShare::new(f.eval_at_participant(Participant::from(0u32)).unwrap().0);
        let app_id = AppId::from(b"test");

        let result = ckd(
            &participants,
            coordinator,
            me,
            private_share,
            app_id,
            app_pk,
        );
        match result {
            Ok(_) => panic!("Expected an error, but got Ok"),
            Err(err) => assert_eq!(
                err,
                InitializationError::MissingParticipant {
                    role: "self",
                    participant: me
                }
            ),
        }
    }

    #[test]
    fn test_ckd_coordinator_not_in_participants() {
        let participants = vec![Participant::from(0u32), Participant::from(1u32)];
        let coordinator = Participant::from(2u32); // Coordinator is not in the list
        let me = Participant::from(0u32);
        let (_app_sk, app_pk) = Secp256K1Sha256::generate_nonce(&mut OsRng);
        let app_pk = VerifyingKey::new(app_pk);
        let f = Polynomial::<Secp256K1Sha256>::generate_polynomial(None, 2, &mut OsRng).unwrap();
        let private_share = SigningShare::new(f.eval_at_participant(me).unwrap().0);
        let app_id = AppId::from(b"test");

        let result = ckd(
            &participants,
            coordinator,
            me,
            private_share,
            app_id,
            app_pk,
        );
        match result {
            Ok(_) => panic!("Expected an error, but got Ok"),
            Err(err) => assert_eq!(
                err,
                InitializationError::MissingParticipant {
                    role: "coordinator",
                    participant: coordinator
                }
            ),
        }
    }
}
