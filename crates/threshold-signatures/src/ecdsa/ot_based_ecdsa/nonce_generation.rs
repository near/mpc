use crate::ReconstructionThreshold;
use crate::ecdsa::ot_based_ecdsa::triples::{TriplePub, TripleShare};
use crate::ecdsa::{AffinePoint, KeygenOutput, ProjectivePoint, Scalar, Secp256K1Sha256, Tweak};
use crate::errors::{InitializationError, ProtocolError};
use crate::participants::{Participant, ParticipantList};
use crate::protocol::{helpers::recv_from_others, internal::SharedChannel};
use zeroize::ZeroizeOnDrop;

type Secp256 = Secp256K1Sha256;

/// The arguments needed to create a signature.
///
/// Each of [`triple0`](Self::triple0) and [`triple1`](Self::triple1) must be an unmodified output
/// of [`generate_triple`](super::triples::generate_triple) or
/// [`generate_triple_many`](super::triples::generate_triple_many), used at most once: in one slot
/// of one run of [`sign`](super::sign::sign), aborted runs included. A reused or modified triple
/// leaks the private key, and no participant can detect this.
#[derive(Debug, Clone)]
pub struct SignArguments {
    /// The first triple's public information, and our share.
    pub triple0: (TripleShare, TriplePub),
    /// Ditto, for the second triple.
    pub triple1: (TripleShare, TriplePub),
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    /// This is of type `KeygenOutput<Secp256K1Sha256>` from Frost implementation
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the signature, which must match the original threshold
    pub threshold: ReconstructionThreshold,
}

/// The output of the nonce generation rounds.
///
/// This output is basically all the parts of the signature that we can perform
/// without knowing the message.
#[derive(ZeroizeOnDrop)]
pub struct NonceGenerationOutput {
    /// The public nonce commitment.
    #[zeroize(skip)]
    pub big_r: AffinePoint,
    /// Our share of the nonce value.
    pub k: Scalar,
    /// Our share of the sigma value.
    pub sigma: Scalar,
}

impl NonceGenerationOutput {
    /// The same output under the key derived with `tweak`: `sigma' = sigma + tweak * k`.
    ///
    /// Only sound when the output is consumed by the computation that produced it.
    pub(crate) fn with_tweak(&self, tweak: &Tweak) -> Self {
        Self {
            big_r: self.big_r,
            k: self.k,
            sigma: self.sigma + tweak.value() * self.k,
        }
    }
}

/// Checks the participant set against `args` and returns it as a [`ParticipantList`].
pub fn validate_sign_arguments(
    participants: &[Participant],
    me: Participant,
    args: &SignArguments,
) -> Result<ParticipantList, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    // Spec 1.1
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.value(),
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

    Ok(participants)
}

/// The two nonce generation rounds, run on a caller-owned channel so that a longer protocol
/// can continue on the same channel with further waitpoints.
pub async fn nonce_generation_rounds(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: Participant,
    args: SignArguments,
) -> Result<NonceGenerationOutput, ProtocolError> {
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

    for (_, e_j) in recv_from_others::<Scalar>(chan, wait0, participants, me).await? {
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
        recv_from_others::<(Scalar, Scalar)>(chan, wait1, participants, me).await?
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

    Ok(NonceGenerationOutput {
        big_r,
        k: k_i,
        sigma: sigma_i,
    })
}

#[cfg(test)]
#[allow(non_snake_case)]
mod test {
    use super::*;
    use crate::test_utils::MockCryptoRng;
    use rand_core::SeedableRng;

    #[test]
    fn with_tweak__should_shift_sigma_by_tweak_times_k() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let k = frost_core::random_nonzero::<Secp256, _>(&mut rng);
        let nonce_package = NonceGenerationOutput {
            big_r: (ProjectivePoint::GENERATOR * k.invert().unwrap()).into(),
            k,
            sigma: frost_core::random_nonzero::<Secp256, _>(&mut rng),
        };
        let tweak = Tweak::new(frost_core::random_nonzero::<Secp256, _>(&mut rng));

        // When
        let tweaked = nonce_package.with_tweak(&tweak);

        // Then
        assert_eq!(tweaked.big_r, nonce_package.big_r);
        assert_eq!(tweaked.k, nonce_package.k);
        assert_eq!(tweaked.sigma - nonce_package.sigma, tweak.value() * k);
    }
}
