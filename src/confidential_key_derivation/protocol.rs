use crate::confidential_key_derivation::ciphersuite::{hash2curve, BLS12381SHA256};
use crate::confidential_key_derivation::{
    AppId, CKDOutput, CKDOutputOption, ElementG1, PublicKey, Scalar, SigningShare,
};
use crate::participants::{ParticipantCounter, ParticipantList};
use crate::protocol::internal::{make_protocol, Comms, SharedChannel};
use crate::protocol::{errors::InitializationError, errors::ProtocolError, Participant, Protocol};

use elliptic_curve::{Field, Group};
use rand_core::CryptoRngCore;

fn ckd_helper(
    participants: &ParticipantList,
    me: Participant,
    private_share: SigningShare,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(ElementG1, ElementG1), ProtocolError> {
    // y <- ZZq* , Y <- y * G
    let y = Scalar::random(rng);
    let big_y = ElementG1::generator() * y;
    // H(app_id) when H is a random oracle
    let hash_point = hash2curve(app_id);
    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();
    // C <- S + y . A
    let big_c = big_s + app_pk * y;
    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
}

#[allow(clippy::too_many_arguments)]
fn do_ckd_participant(
    mut chan: SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    private_share: SigningShare,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        ckd_helper(participants, me, private_share, app_id, app_pk, rng)?;
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
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (mut norm_big_y, mut norm_big_c) =
        ckd_helper(&participants, me, private_share, app_id, app_pk, rng)?;

    // Receive everyone's inputs and add them together
    let mut seen = ParticipantCounter::new(&participants);
    let waitpoint = chan.next_waitpoint();

    seen.put(me);
    while !seen.full() {
        let (from, (big_y, big_c)): (_, (ElementG1, ElementG1)) = chan.recv(waitpoint).await?;
        if !seen.put(from) {
            continue;
        }
        norm_big_y += big_y;
        norm_big_c += big_c;
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
}

/// Runs the confidential key derivation protocol.
/// This exact same function is called for both
/// a coordinator and a normal participant.
///
/// Depending on whether the current participant is a coordinator or not,
/// runs the signature protocol as either a participant or a coordinator.
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    private_share: SigningShare,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutputOption>, InitializationError> {
    // not enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

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
    app_pk: PublicKey,
    mut rng: impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
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
            &participants,
            coordinator,
            me,
            private_share,
            &app_id,
            app_pk,
            &mut rng,
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::one_coordinator_output;
    use crate::{confidential_key_derivation::ciphersuite::hash2curve, protocol::run_protocol};
    use rand_core::{OsRng, RngCore};
    use std::error::Error;

    #[test]
    fn test_hash2curve() {
        let app_id = b"Hello Near";
        let app_id_same = b"Hello Near";
        let pt1 = hash2curve(&AppId::from(app_id));
        let pt2 = hash2curve(&AppId::from(app_id_same));
        assert_eq!(pt1, pt2);

        let app_id = b"Hello Near!";
        let pt2 = hash2curve(&AppId::from(app_id));
        assert_ne!(pt1, pt2);
    }

    #[test]
    fn test_ckd() -> Result<(), Box<dyn Error>> {
        let mut rng = OsRng;

        // Create the app necessary items
        let app_id = AppId::from(b"Near App");
        let app_sk = Scalar::random(&mut rng);
        let app_pk = ElementG1::generator() * app_sk;

        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];

        // choose a coordinator at random
        let index = OsRng.next_u32() % participants.len() as u32;
        let coordinator = participants[index as usize];

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = CKDOutputOption>>)> =
            Vec::with_capacity(participants.len());

        let mut private_shares = Vec::new();
        for p in &participants {
            let private_share = SigningShare::new(Scalar::random(&mut rng));
            private_shares.push(private_share);

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
        let ckd = one_coordinator_output(result, coordinator)?;

        // compute msk . H(app_id)
        let confidential_key = ckd.unmask(app_sk);

        let mut msk = Scalar::ZERO;
        let participants = ParticipantList::new(&participants).unwrap();
        for (i, private_share) in private_shares.iter().enumerate() {
            let lambda_i = participants
                .lagrange::<BLS12381SHA256>(participants.get_participant(i).unwrap())?;
            msk += lambda_i * private_share.to_scalar();
        }

        let expected_confidential_key = hash2curve(&app_id) * msk;

        assert_eq!(
            confidential_key, expected_confidential_key,
            "Keys should be equal"
        );
        Ok(())
    }
}
