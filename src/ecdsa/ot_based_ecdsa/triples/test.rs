use rand_core::{CryptoRngCore, OsRng};

use super::{
    batch_random_ot::{BatchRandomOTOutputReceiver, BatchRandomOTOutputSender},
    TriplePub, TripleShare,
};

use crate::ecdsa::{Field, Polynomial, ProjectivePoint, Secp256K1ScalarField};

use crate::protocol::{
    errors::ProtocolError,
    internal::{make_protocol, Comms},
    test::run_two_party_protocol,
    Participant,
};

/// Create a new triple from scratch.
///
/// This can be used to generate a triple if you then trust the person running
/// this code to forget about the values they generated.
/// We prevent users from using it in non-testing env and attribute it to #[cfg(test)]
pub fn deal(
    rng: &mut impl CryptoRngCore,
    participants: &[Participant],
    threshold: usize,
) -> Result<(TriplePub, Vec<TripleShare>), ProtocolError> {
    let a = Secp256K1ScalarField::random(&mut *rng);
    let b = Secp256K1ScalarField::random(&mut *rng);
    let c = a * b;

    let f_a = Polynomial::generate_polynomial(Some(a), threshold - 1, rng)?;
    let f_b = Polynomial::generate_polynomial(Some(b), threshold - 1, rng)?;
    let f_c = Polynomial::generate_polynomial(Some(c), threshold - 1, rng)?;

    let mut shares = Vec::with_capacity(participants.len());
    let mut participants_owned = Vec::with_capacity(participants.len());

    for p in participants {
        participants_owned.push(*p);
        shares.push(TripleShare {
            a: f_a.eval_at_participant(*p)?.0,
            b: f_b.eval_at_participant(*p)?.0,
            c: f_c.eval_at_participant(*p)?.0,
        });
    }

    let triple_pub = TriplePub {
        big_a: (ProjectivePoint::GENERATOR * a).into(),
        big_b: (ProjectivePoint::GENERATOR * b).into(),
        big_c: (ProjectivePoint::GENERATOR * c).into(),
        participants: participants_owned,
        threshold,
    };
    Ok((triple_pub, shares))
}

/// Run the batch random OT protocol between two parties.
pub(crate) fn run_batch_random_ot(
) -> Result<(BatchRandomOTOutputSender, BatchRandomOTOutputReceiver), ProtocolError> {
    let s = Participant::from(0u32);
    let r = Participant::from(1u32);
    let comms_s = Comms::new();
    let comms_r = Comms::new();

    run_two_party_protocol(
        s,
        r,
        &mut make_protocol(comms_s.clone(), {
            let y = super::batch_random_ot::batch_random_ot_sender_helper(&mut OsRng);
            super::batch_random_ot::batch_random_ot_sender(comms_s.private_channel(s, r), y)
        }),
        &mut make_protocol(comms_r.clone(), {
            let (delta, x) =
                super::batch_random_ot::batch_random_ot_receiver_random_helper(&mut OsRng);
            super::batch_random_ot::batch_random_ot_receiver(
                comms_r.private_channel(r, s),
                delta,
                x,
            )
        }),
    )
}
