use crate::participants::{Participant, ParticipantList};
use crate::{
    MaxMalicious, SigningShare,
    ecdsa::{
        AffinePoint, Field, KeygenOutput, Scalar, Secp256K1ScalarField, Secp256K1Sha256, Tweak,
    },
    errors::{InitializationError, ProtocolError},
    protocol::{helpers::recv_from_others, internal::SharedChannel},
};
use frost_secp256k1::{Group, Secp256K1Group};
use rand_core::CryptoRngCore;
use zeroize::ZeroizeOnDrop;

type C = Secp256K1Sha256;

/// The necessary inputs for the creation of a presignature.
pub struct PresignArguments {
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    /// This is of type `KeygenOutput<Secp256K1Sha256>` from Frost implementation
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the presignature, which must match the original threshold
    pub max_malicious: MaxMalicious,
}

/// The output of the presigning protocol.
/// Contains the signature precomputed elements
/// independently of the message
#[derive(ZeroizeOnDrop)]
pub struct PresignOutput {
    /// The public nonce commitment.
    #[zeroize(skip)]
    pub big_r: AffinePoint,

    /// Our secret shares of the nonces.
    pub c: Scalar,
    pub e: Scalar,
    pub alpha: Scalar,
    pub beta: Scalar,
}

impl PresignOutput {
    /// The presignature under the key derived with `tweak`, in the form the signing round
    /// consumes: `beta' = beta + c * tweak`.
    pub(crate) fn with_tweak(&self, tweak: &Tweak) -> Self {
        Self {
            big_r: self.big_r,
            c: self.c,
            alpha: self.alpha,
            beta: self.beta + self.c * tweak.value(),
            e: self.e,
        }
    }
}

/// Checks the participant set against `args` and returns it as a [`ParticipantList`].
pub fn validate_presign_arguments(
    participants: &[Participant],
    me: Participant,
    args: &PresignArguments,
) -> Result<ParticipantList, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    if args.max_malicious.value() > participants.len() {
        return Err(InitializationError::BadParameters(
            "max_malicious must be less than or equals to participant count".to_string(),
        ));
    }

    let robust_ecdsa_threshold = args
        .max_malicious
        .value()
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            InitializationError::BadParameters(
                "2*max_malicious+1 must be less than usize::MAX".to_string(),
            )
        })?;
    if robust_ecdsa_threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "2*max_malicious+1 must be less than or equals to participant count".to_string(),
        ));
    }

    // The removed scheme needed exactly 2*max_malicious+1 presigners to avoid
    // split-view attacks. The stub does not, but keeping the check preserves the
    // participant-count contract a replacement scheme is likely to need again.
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during presigning must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }

    Ok(participants)
}

/// The stub presigning protocol, run on a caller-owned channel so that a longer protocol can
/// continue on the same channel with further waitpoints. This is where the signing key leaks:
/// see the [module docs](super).
///
/// One broadcast round, in which every participant contributes a random summand to
/// the nonce `k`. All parties therefore learn `k` and agree on `R = k * G`. The
/// output fields are chosen so that [`super::sign::sign_round`]'s Lagrange linearization
/// recombines them into a valid ECDSA signature:
///
/// - `alpha = c = k^{-1}` are held identically by everybody, and Lagrange
///   coefficients at zero sum to one, so they recombine to `k^{-1}`;
/// - `beta = k^{-1} * x_i` is scaled by the party's real key share, so it recombines
///   to `k^{-1} * x`;
/// - `e = 0`, since the zero-sharing mask it carried in the removed scheme has
///   nothing to mask here.
pub async fn presign_round(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: Participant,
    args: PresignArguments,
    mut rng: impl CryptoRngCore,
) -> Result<PresignOutput, ProtocolError> {
    let k_me = frost_core::random_nonzero::<C, _>(&mut rng);
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &SigningShare::<C>::new(k_me))?;

    let mut k = k_me;
    for (_, k_p) in
        recv_from_others::<SigningShare<C>>(chan, wait_round_1, participants, me).await?
    {
        k += k_p.to_scalar();
    }

    let k_inv = Option::<Scalar>::from(k.invert()).ok_or(ProtocolError::ZeroScalar)?;

    let big_r = Secp256K1Group::generator() * k;
    let x_me = args.keygen_out.private_share.to_scalar();

    Ok(PresignOutput {
        big_r: big_r.to_affine(),
        alpha: k_inv,
        beta: k_inv * x_me,
        c: k_inv,
        e: Secp256K1ScalarField::zero(),
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::SeedableRng;

    use crate::test_utils::MockCryptoRng;

    #[test]
    #[allow(non_snake_case)]
    fn with_tweak__should_shift_beta_by_tweak_times_c() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let presignature = PresignOutput {
            big_r: (Secp256K1Group::generator() * Scalar::from(3u64)).to_affine(),
            c: Scalar::from(5u64),
            e: Scalar::from(7u64),
            alpha: Scalar::from(11u64),
            beta: Scalar::from(13u64),
        };
        let tweak = Tweak::new(frost_core::random_nonzero::<C, _>(&mut rng));

        // When
        let tweaked = presignature.with_tweak(&tweak);

        // Then
        assert_eq!(tweaked.big_r, presignature.big_r);
        assert_eq!(tweaked.alpha, presignature.alpha);
        assert_eq!(tweaked.e, presignature.e);
        assert_eq!(
            tweaked.beta,
            presignature.beta + presignature.c * tweak.value()
        );
    }
}
