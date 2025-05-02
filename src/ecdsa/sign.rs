use elliptic_curve::{ops::Invert, scalar::IsHigh, Field, Group, ScalarPrimitive};
use subtle::ConditionallySelectable;

use crate::protocol::internal::Comms;
use crate::{
    compat::{self, CSCurve},
    ecdsa::presign::PresignOutput,
    participants::{ParticipantCounter, ParticipantList},
    protocol::{
        internal::{make_protocol, SharedChannel},
        InitializationError, Participant, Protocol, ProtocolError,
    },
};

/// Represents a signature with extra information, to support different variants of ECDSA.
///
/// An ECDSA signature is usually two scalars. The first scalar is derived from
/// a point on the curve, and because this process is lossy, some other variants
/// of ECDSA also include some extra information in order to recover this point.
///
/// Furthermore, some signature formats may disagree on how precisely to serialize
/// different values as bytes.
///
/// To support these variants, this simply gives you a normal signature, along with the entire
/// first point.
#[derive(Clone)]
pub struct FullSignature<C: CSCurve> {
    /// This is the entire first point.
    pub big_r: C::AffinePoint,
    /// This is the second scalar, normalized to be in the lower range.
    pub s: C::Scalar,
}

impl<C: CSCurve> FullSignature<C> {
    #[must_use]
    pub fn verify(&self, public_key: &C::AffinePoint, msg_hash: &C::Scalar) -> bool {
        let r: C::Scalar = compat::x_coordinate::<C>(&self.big_r);
        if r.is_zero().into() || self.s.is_zero().into() {
            return false;
        }
        let s_inv = self.s.invert_vartime().unwrap();
        let reproduced = (C::ProjectivePoint::generator() * (*msg_hash * s_inv))
            + (C::ProjectivePoint::from(*public_key) * (r * s_inv));
        compat::x_coordinate::<C>(&reproduced.into()) == r
    }
}

async fn do_sign<C: CSCurve>(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    public_key: C::AffinePoint,
    presignature: PresignOutput<C>,
    msg_hash: C::Scalar,
) -> Result<FullSignature<C>, ProtocolError> {
    // Spec 1.1
    let lambda = participants.lagrange::<C>(me);
    let k_i = lambda * presignature.k;

    // Spec 1.2
    let sigma_i = lambda * presignature.sigma;

    // Spec 1.3
    let r = compat::x_coordinate::<C>(&presignature.big_r);
    let s_i: C::Scalar = msg_hash * k_i + r * sigma_i;

    // Spec 1.4
    let wait0 = chan.next_waitpoint();
    {
        let s_i: ScalarPrimitive<C> = s_i.into();
        chan.send_many(wait0, &s_i);
    }

    // Spec 2.1 + 2.2
    let mut seen = ParticipantCounter::new(&participants);
    let mut s: C::Scalar = s_i;
    seen.put(me);
    while !seen.full() {
        let (from, s_j): (_, ScalarPrimitive<C>) = chan.recv(wait0).await?;
        if !seen.put(from) {
            continue;
        }
        s += C::Scalar::from(s_j)
    }

    // Spec 2.3
    // Optionally, normalize s
    s.conditional_assign(&(-s), s.is_high());
    let sig = FullSignature {
        big_r: presignature.big_r,
        s,
    };
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }

    // Spec 2.4
    Ok(sig)
}

pub fn signature_share<C: CSCurve>(
    participants: Vec<Participant>,
    me: Participant,
    // public_key: C::AffinePoint,
    presignature: PresignOutput<C>,
    msg_hash: C::Scalar,
) -> Result<C::Scalar, ProtocolError> {
    let p_list = ParticipantList::new(&participants).unwrap();
    // Spec 1.1
    let lambda = p_list.lagrange::<C>(me);
    let k_i = lambda * presignature.k;

    // Spec 1.2
    let sigma_i = lambda * presignature.sigma;

    // Spec 1.3
    let r = compat::x_coordinate::<C>(&presignature.big_r);
    let s_i: C::Scalar = msg_hash * k_i + r * sigma_i;

    Ok(s_i)
}

pub async fn combine_signature_shares<C: CSCurve>(
    shares: Vec<C::Scalar>,
    public_key: C::AffinePoint,
    // presignature: PresignOutput<C>,
    presignature_big_r: C::AffinePoint,
    msg_hash: C::Scalar,
) -> Result<FullSignature<C>, ProtocolError> {
    let mut s: C::Scalar = shares[0];
    for s_j in shares.iter().skip(1) {
        s += *s_j
    }

    // Spec 2.3
    // Optionally, normalize s
    s.conditional_assign(&(-s), s.is_high());
    let sig = FullSignature {
        // big_r: presignature.big_r,
        big_r: presignature_big_r,
        s,
    };
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }

    // Spec 2.4
    Ok(sig)
}

/// The signature protocol, allowing us to use a presignature to sign a message.
///
/// **WARNING** You must absolutely hash an actual message before passing it to
/// this function. Allowing the signing of arbitrary scalars *is* a security risk,
/// and this function only tolerates this risk to allow for genericity.
pub fn sign<C: CSCurve>(
    participants: &[Participant],
    me: Participant,
    public_key: C::AffinePoint,
    presignature: PresignOutput<C>,
    msg_hash: C::Scalar,
) -> Result<impl Protocol<Output = FullSignature<C>>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };

    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    })?;

    let ctx = Comms::new();
    let fut = do_sign(
        ctx.shared_channel(),
        participants,
        me,
        public_key,
        presignature,
        msg_hash,
    );
    Ok(make_protocol(ctx, fut))
}

#[cfg(test)]
mod test {
    use std::error::Error;

    use ecdsa::Signature;
    use k256::{
        ecdsa::signature::Verifier, ecdsa::VerifyingKey, ProjectivePoint, PublicKey, Scalar,
        Secp256k1,
    };
    use rand_core::OsRng;

    use super::*;
    use crate::ecdsa::test::{
        assert_public_key_invariant, run_keygen, run_presign, run_reshare, run_sign,
    };
    use crate::ecdsa::triples::deal;
    use crate::{compat::scalar_hash, ecdsa::math::Polynomial, protocol::run_protocol};

    #[test]
    fn test_sign() -> Result<(), Box<dyn Error>> {
        let threshold = 2;
        let msg = b"hello?";

        // Run 4 times for flakiness reasons
        for _ in 0..4 {
            let f = Polynomial::<Secp256k1>::random(&mut OsRng, threshold);
            let x = f.evaluate_zero();
            let public_key = (ProjectivePoint::GENERATOR * x).to_affine();

            let g = Polynomial::<Secp256k1>::random(&mut OsRng, threshold);

            let k: Scalar = g.evaluate_zero();
            let big_k = (ProjectivePoint::GENERATOR * k.invert().unwrap()).to_affine();

            let sigma = k * x;

            let h = Polynomial::<Secp256k1>::extend_random(&mut OsRng, threshold, &sigma);

            let participants = vec![Participant::from(0u32), Participant::from(1u32)];
            #[allow(clippy::type_complexity)]
            let mut protocols: Vec<(
                Participant,
                Box<dyn Protocol<Output = FullSignature<Secp256k1>>>,
            )> = Vec::with_capacity(participants.len());
            for p in &participants {
                let p_scalar = p.scalar::<Secp256k1>();
                let presignature = PresignOutput {
                    big_r: big_k,
                    k: g.evaluate(&p_scalar),
                    sigma: h.evaluate(&p_scalar),
                };
                let protocol = sign(
                    &participants,
                    *p,
                    public_key,
                    presignature,
                    scalar_hash(msg),
                )?;
                protocols.push((*p, Box::new(protocol)));
            }

            let result = run_protocol(protocols)?;
            let sig = result[0].1.clone();
            let sig =
                Signature::from_scalars(compat::x_coordinate::<Secp256k1>(&sig.big_r), sig.s)?;
            VerifyingKey::from(&PublicKey::from_affine(public_key).unwrap())
                .verify(&msg[..], &sig)?;
        }
        Ok(())
    }

    #[test]
    fn test_reshare_sign_more_participants() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
            Participant::from(4u32),
        ];
        let threshold = 3;
        let result0 = run_keygen(&participants, threshold)?;
        assert_public_key_invariant(&result0)?;

        let pub_key = result0[2].1.public_key.clone();

        // Run heavy reshare
        let new_threshold = 5;
        let mut new_participant = participants.clone();
        new_participant.push(Participant::from(31u32));
        new_participant.push(Participant::from(32u32));
        new_participant.push(Participant::from(33u32));
        let mut key_packages = run_reshare(
            &participants,
            &pub_key,
            result0,
            threshold,
            new_threshold,
            new_participant.clone(),
        )?;
        assert_public_key_invariant(&key_packages)?;
        key_packages.sort_by_key(|(p, _)| *p);

        let public_key = key_packages[0].1.public_key.clone();
        // Prepare triples
        let (pub0, shares0) = deal(&mut OsRng, &new_participant, new_threshold);
        let (pub1, shares1) = deal(&mut OsRng, &new_participant, new_threshold);

        // Presign
        let mut presign_result =
            run_presign(key_packages, shares0, shares1, &pub0, &pub1, new_threshold);
        presign_result.sort_by_key(|(p, _)| *p);

        let msg = b"hello world";

        run_sign(presign_result, public_key.to_element().to_affine(), msg);
        Ok(())
    }

    #[test]
    fn test_reshare_sign_less_participants() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
            Participant::from(4u32),
        ];
        let threshold = 4;
        let result0 = run_keygen(&participants, threshold)?;
        assert_public_key_invariant(&result0)?;

        let pub_key = result0[2].1.public_key.clone();

        // Run heavy reshare
        let new_threshold = 3;
        let mut new_participant = participants.clone();
        new_participant.pop();
        let mut key_packages = run_reshare(
            &participants,
            &pub_key,
            result0,
            threshold,
            new_threshold,
            new_participant.clone(),
        )?;
        assert_public_key_invariant(&key_packages)?;
        key_packages.sort_by_key(|(p, _)| *p);

        let public_key = key_packages[0].1.public_key.clone();
        // Prepare triples
        let (pub0, shares0) = deal(&mut OsRng, &new_participant, new_threshold);
        let (pub1, shares1) = deal(&mut OsRng, &new_participant, new_threshold);

        // Presign
        let mut presign_result =
            run_presign(key_packages, shares0, shares1, &pub0, &pub1, new_threshold);
        presign_result.sort_by_key(|(p, _)| *p);

        let msg = b"hello world";

        run_sign(presign_result, public_key.to_element().to_affine(), msg);
        Ok(())
    }
}
