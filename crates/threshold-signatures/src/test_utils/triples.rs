use rand_core::CryptoRngCore;

use crate::ReconstructionThreshold;
use crate::ecdsa::ot_based_ecdsa::triples::{TriplePub, TripleShare};
use crate::ecdsa::{Field, Polynomial, ProjectivePoint, Secp256K1ScalarField};
use crate::errors::ProtocolError;
use crate::participants::Participant;

/// Deals a triple from scratch, acting as a trusted dealer.
///
/// Only for tests: whoever runs this learns the triple's secrets.
pub fn deal_triple(
    rng: &mut impl CryptoRngCore,
    participants: &[Participant],
    threshold: ReconstructionThreshold,
) -> Result<(TriplePub, Vec<TripleShare>), ProtocolError> {
    let a = Secp256K1ScalarField::random(&mut *rng);
    let b = Secp256K1ScalarField::random(&mut *rng);
    let c = a * b;

    let degree = threshold.value().checked_sub(1).unwrap();
    let f_a = Polynomial::generate_polynomial(Some(a), degree, rng)?;
    let f_b = Polynomial::generate_polynomial(Some(b), degree, rng)?;
    let f_c = Polynomial::generate_polynomial(Some(c), degree, rng)?;

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
