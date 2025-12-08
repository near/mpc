use crate::confidential_key_derivation::ciphersuite::BLS12381SHA256;
use crate::confidential_key_derivation::{
    hash_app_id_with_pk, AppId, CKDOutput, CKDOutputOption, ElementG1, KeygenOutput, PublicKey,
    Scalar,
};
use crate::errors::{InitializationError, ProtocolError};
use crate::participants::{Participant, ParticipantList};
use crate::protocol::helpers::recv_from_others;
use crate::protocol::internal::{make_protocol, Comms, SharedChannel};
use crate::Protocol;

use elliptic_curve::{Field, Group};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

#[allow(clippy::too_many_arguments)]
fn do_ckd_participant(
    mut chan: SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        compute_signature_share(participants, me, key_pair, app_id, app_pk, rng)?;
    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
}

async fn do_ckd_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;

    // Receive everyone's inputs and add them together
    let waitpoint = chan.next_waitpoint();

    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
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
    key_pair: KeygenOutput,
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
        key_pair,
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
    key_pair: KeygenOutput,
    app_id: AppId,
    app_pk: PublicKey,
    mut rng: impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    if me == coordinator {
        do_ckd_coordinator(chan, participants, me, &key_pair, &app_id, app_pk, &mut rng).await
    } else {
        do_ckd_participant(
            chan,
            &participants,
            coordinator,
            me,
            &key_pair,
            &app_id,
            app_pk,
            &mut rng,
        )
    }
}

fn compute_signature_share(
    participants: &ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(ElementG1, ElementG1), ProtocolError> {
    // Ensures the value is zeroized on drop
    let private_share = Zeroizing::new(key_pair.private_share);

    // y <- ZZq* , Y <- y * G
    let y = Scalar::random(rng);

    // Ensures the value is zeroized on drop
    let y = Zeroizing::new(super::scalar_wrapper::ScalarWrapper(y));

    let big_y = ElementG1::generator() * y.0;

    // H(pk || app_id) when H is a random oracle
    let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);

    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;

    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::confidential_key_derivation::{
        ciphersuite::{hash_to_curve, G2Projective},
        hash_app_id_with_pk, SigningShare, VerifyingKey,
    };
    use crate::test_utils::{
        check_one_coordinator_output, generate_participants, run_protocol, GenProtocol,
        MockCryptoRng,
    };
    use rand::{Rng, RngCore, SeedableRng};

    #[test]
    fn test_hash2curve() {
        let app_id = b"Hello Near";
        let app_id_same = b"Hello Near";
        let pt1 = hash_to_curve(&AppId::try_from(app_id).unwrap());
        let pt2 = hash_to_curve(&AppId::try_from(app_id_same).unwrap());
        assert_eq!(pt1, pt2);

        let app_id = b"Hello Near!";
        let pt2 = hash_to_curve(&AppId::try_from(app_id).unwrap());
        assert_ne!(pt1, pt2);
    }

    #[test]
    fn test_ckd() {
        let mut rng = MockCryptoRng::seed_from_u64(42);

        // Create the app necessary items
        let app_id = AppId::try_from(b"Near App").unwrap();
        let app_sk = Scalar::random(&mut rng);
        let app_pk = ElementG1::generator() * app_sk;

        let participants = generate_participants(3);

        // choose a coordinator at random
        let index = rng.gen_range(0..participants.len());
        let coordinator = participants[index as usize];
        let participant_list = ParticipantList::new(&participants).unwrap();

        // Manually compute signing keys
        let mut private_shares = Vec::new();
        let mut msk = Scalar::ZERO;
        for (i, _) in participants.iter().enumerate() {
            let mut rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
            let private_share = SigningShare::new(Scalar::random(&mut rng_p));
            // compute lambda(i)
            let lambda_i = participant_list
                .lagrange::<BLS12381SHA256>(participant_list.get_participant(i).unwrap())
                .unwrap();

            msk += lambda_i * private_share.to_scalar();
            private_shares.push(private_share);
        }

        // Manually compute master verification
        let pk = VerifyingKey::new(G2Projective::generator() * msk);

        let mut protocols: GenProtocol<CKDOutputOption> = Vec::with_capacity(participants.len());
        for (i, p) in participants.iter().enumerate() {
            let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
            let key_pair = KeygenOutput {
                public_key: pk,
                private_share: private_shares[i],
            };

            let protocol = ckd(
                &participants,
                coordinator,
                *p,
                key_pair,
                app_id.clone(),
                app_pk,
                rng_p,
            )
            .unwrap();

            protocols.push((*p, Box::new(protocol)));
        }

        let result = run_protocol(protocols).unwrap();

        // test one single some for the coordinator
        let ckd_output = check_one_coordinator_output(result, coordinator).unwrap();

        // compute msk . H(pk, app_id)
        let confidential_key = ckd_output.unmask(app_sk);

        // H(pk || app_id) * msk
        let expected_confidential_key = hash_app_id_with_pk(&pk, &app_id) * msk;

        assert_eq!(
            confidential_key, expected_confidential_key,
            "Keys should be equal"
        );
        insta::assert_json_snapshot!(ckd_output);
    }
}
