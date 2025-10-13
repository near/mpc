use super::{PresignArguments, PresignOutput};
use crate::ecdsa::{ProjectivePoint, Scalar, Secp256K1Sha256};
use crate::errors::{InitializationError, ProtocolError};
use crate::participants::{Participant, ParticipantList};
use crate::protocol::helpers::recv_from_others;
use crate::protocol::{
    internal::{make_protocol, Comms, SharedChannel},
    Protocol,
};

type Secp256 = Secp256K1Sha256;

/// The presignature protocol.
///
/// This is the first phase of performing a signature, in which we perform
/// all the work we can do without yet knowing the message to be signed.
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
pub fn presign(
    participants: &[Participant],
    me: Participant,
    args: PresignArguments,
) -> Result<impl Protocol<Output = PresignOutput>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    // Spec 1.1
    if args.threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold,
            max: participants.len(),
        });
    }

    // NOTE: We omit the check that the new participant set was present for
    // the triple generation, because presumably they need to have been present
    // in order to have shares.

    // Also check that we have enough participants to reconstruct shares.
    if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
        return Err(InitializationError::BadParameters(
            "New threshold must match the threshold of both triples".to_string(),
        ));
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    let ctx = Comms::new();
    let fut = do_presign(ctx.shared_channel(), participants, me, args);
    Ok(make_protocol(ctx, fut))
}

async fn do_presign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    args: PresignArguments,
) -> Result<PresignOutput, ProtocolError> {
    // Round 1
    // Extracting triples private variables (ai, bi, ci)
    let a_i = args.triple1.0.a;
    let b_i = args.triple1.0.b;
    let c_i = args.triple1.0.c;

    // Extracting triples public variables (A, B, _)
    // notice C is not used
    let big_a: ProjectivePoint = args.triple1.1.big_a.into();
    let big_b: ProjectivePoint = args.triple1.1.big_b.into();

    // Extracting triples private variables (ki, _, ei)
    // notice di is not used
    let k_i = args.triple0.0.a;
    let e_i = args.triple0.0.c;

    // Extracting triples public variables (K, D, E)
    let big_k: ProjectivePoint = args.triple0.1.big_a.into();
    let big_d = args.triple0.1.big_b;
    let big_e = args.triple0.1.big_c;

    // linearize ki ei ai bi ci xi
    // Spec 1.1
    let lambda_me = participants.lagrange::<Secp256>(me)?;

    let k_prime_i = lambda_me * k_i;
    let e_i: Scalar = lambda_me * e_i;

    let a_prime_i = lambda_me * a_i;
    let b_prime_i = lambda_me * b_i;

    let big_x: ProjectivePoint = args.keygen_out.public_key.to_element();
    let private_share = args.keygen_out.private_share.to_scalar();
    let x_prime_i = lambda_me * private_share;

    // Send ei
    // Spec 1.2
    let wait0 = chan.next_waitpoint();
    chan.send_many(wait0, &e_i)?;

    // Receive ej and compute e = SUM_j ej
    // Spec 1.3
    let mut e = e_i;

    for (_, e_j) in recv_from_others::<Scalar>(&chan, wait0, &participants, me).await? {
        if e_j.is_zero().into() {
            return Err(ProtocolError::AssertionFailed(
                "Received zero share of kd, indicating a triple wasn't available.".to_string(),
            ));
        }

        // Spec 1.4
        e += e_j;
    }

    // E =?= e*G
    // Spec 1.5
    if big_e != (ProjectivePoint::GENERATOR * e).to_affine() {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }

    // Round 2
    // alphai = ki' + ai'
    // Spec 2.1
    let alpha_i: Scalar = k_prime_i + a_prime_i;
    // betai = xi' + bi'
    let beta_i: Scalar = x_prime_i + b_prime_i;

    // Send alphai and betai
    // Spec 2.2
    let wait1 = chan.next_waitpoint();
    chan.send_many(wait1, &(alpha_i, beta_i))?;

    // Receive and compute alpha = SUM_j alphaj
    // Receive and compute beta = SUM_j betaj
    // Spec 2.3
    let mut alpha = alpha_i;
    let mut beta = beta_i;

    for (_, (alpha_j, beta_j)) in
        recv_from_others::<(Scalar, Scalar)>(&chan, wait1, &participants, me).await?
    {
        // Spec 2.4
        alpha += alpha_j;
        beta += beta_j;
    }

    // alpha*G =?= K + A
    // beta*G =?= X + B
    // Spec 2.5
    if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
        || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }

    // Compute R = 1/e * D
    // Spec 2.6
    let e_inv: Option<Scalar> = e.invert().into();
    let e_inv =
        e_inv.ok_or_else(|| ProtocolError::AssertionFailed("failed to invert kd".to_string()))?;
    let big_r = (big_d * e_inv).into();

    // sigmai = alpha*xi - beta*ai + ci
    // Spec 2.7
    let sigma_i = alpha * private_share - (beta * a_i - c_i);

    Ok(PresignOutput {
        big_r,
        k: k_i,
        sigma: sigma_i,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        ecdsa::{ot_based_ecdsa::triples::test::deal, KeygenOutput, Polynomial, ProjectivePoint},
        protocol::run_protocol,
        test::{generate_participants, GenProtocol},
    };
    use frost_secp256k1::{
        keys::{PublicKeyPackage, SigningShare},
        VerifyingKey,
    };
    use rand_core::OsRng;
    use std::collections::BTreeMap;

    #[test]
    fn test_presign() {
        let participants = generate_participants(4);
        let original_threshold = 2;
        let f = Polynomial::generate_polynomial(None, original_threshold - 1, &mut OsRng).unwrap();
        let big_x = ProjectivePoint::GENERATOR * f.eval_at_zero().unwrap().0;

        let threshold = 2;

        let (triple0_pub, triple0_shares) =
            deal(&mut OsRng, &participants, original_threshold).unwrap();
        let (triple1_pub, triple1_shares) =
            deal(&mut OsRng, &participants, original_threshold).unwrap();

        let mut protocols: GenProtocol<PresignOutput> = Vec::with_capacity(participants.len());

        for ((p, triple0), triple1) in participants
            .iter()
            .take(3)
            .zip(triple0_shares.into_iter())
            .zip(triple1_shares.into_iter())
        {
            let private_share = f.eval_at_participant(*p).unwrap().0;
            let verifying_key = VerifyingKey::new(big_x);
            let public_key_package = PublicKeyPackage::new(BTreeMap::new(), verifying_key);
            let keygen_out = KeygenOutput {
                private_share: SigningShare::new(private_share),
                public_key: *public_key_package.verifying_key(),
            };

            let protocol = presign(
                &participants[..3],
                *p,
                PresignArguments {
                    triple0: (triple0, triple0_pub.clone()),
                    triple1: (triple1, triple1_pub.clone()),
                    keygen_out,
                    threshold,
                },
            )
            .unwrap();
            protocols.push((*p, Box::new(protocol)));
        }

        let result = run_protocol(protocols).unwrap();

        assert!(result.len() == 3);
        assert_eq!(result[0].1.big_r, result[1].1.big_r);
        assert_eq!(result[1].1.big_r, result[2].1.big_r);

        let big_k = result[2].1.big_r;

        let participants = vec![result[0].0, result[1].0];
        let k_shares = [result[0].1.k, result[1].1.k];
        let sigma_shares = [result[0].1.sigma, result[1].1.sigma];
        let p_list = ParticipantList::new(&participants).unwrap();
        let k = p_list.lagrange::<Secp256>(participants[0]).unwrap() * k_shares[0]
            + p_list.lagrange::<Secp256>(participants[1]).unwrap() * k_shares[1];
        assert_eq!(ProjectivePoint::GENERATOR * k.invert().unwrap(), big_k);
        let sigma = p_list.lagrange::<Secp256>(participants[0]).unwrap() * sigma_shares[0]
            + p_list.lagrange::<Secp256>(participants[1]).unwrap() * sigma_shares[1];
        assert_eq!(sigma, k * f.eval_at_zero().unwrap().0);
    }
}
