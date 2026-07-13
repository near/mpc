use crate::participants::{Participant, ParticipantList, ParticipantMap};
use crate::{
    ecdsa::{
        AffinePoint, CoefficientCommitment, Polynomial, PolynomialCommitment, ProjectivePoint,
        RerandomizationArguments, Scalar, Secp256K1Sha256,
    },
    errors::{InitializationError, ProtocolError},
    protocol::{
        Protocol,
        helpers::recv_from_others,
        internal::{Comms, SharedChannel, make_protocol},
    },
};

use crate::ecdsa::robust_ecdsa::presign::{PresignArguments, Shares, zero_secret_polynomial};
use frost_secp256k1::{Group, Secp256K1Group};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

type C = Secp256K1Sha256;

/// The output of the additive-variant presigning protocol.
///
/// Unlike the parent `PresignOutput`, the nonce is *not* inverted yet:
/// `w` and `u` are degree-2t shares of `a * k` and `a * x` respectively,
/// and the \[BB89\] inversion happens during signing.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct AdditivePresignOutput {
    /// The public nonce commitment.
    #[zeroize(skip)]
    pub big_r: AffinePoint,

    /// Our degree-t share of the mask `a`.
    pub a: Scalar,
    /// Our degree-2t share of `w = a * k` (blinded by `b`).
    pub w: Scalar,
    /// Our degree-2t share of `a * x` (blinded by `d`).
    pub u: Scalar,
    /// Our degree-2t share of zero.
    pub e: Scalar,
}

impl_secret_debug!(AdditivePresignOutput {
    show: [big_r],
    redact: [a, w, u, e]
});

/// An additively rerandomized presignature for a specific signing context.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct AdditiveRerandomizedPresignOutput {
    /// The rerandomized public nonce commitment `R + delta * G`.
    #[zeroize(skip)]
    pub(super) big_r: AffinePoint,

    /// Our share of the denominator `a * (k + delta)`.
    pub(super) mu: Scalar,
    /// Our degree-t share of the mask `a`.
    pub(super) a: Scalar,
    /// Our degree-2t share of `a * (x + tweak)`.
    pub(super) u: Scalar,
    /// Our degree-2t share of zero.
    pub(super) e: Scalar,
}

impl_secret_debug!(AdditiveRerandomizedPresignOutput {
    show: [big_r],
    redact: [mu, a, u, e]
});

impl AdditiveRerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &AdditivePresignOutput,
        args: &RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != args.big_r {
            return Err(ProtocolError::IncompatibleRerandomizationInputs);
        }
        let delta = args.derive_randomness()?;

        // R + delta * G
        let rerandomized_big_r = ProjectivePoint::GENERATOR * delta + presignature.big_r;
        if rerandomized_big_r.ct_eq(&ProjectivePoint::IDENTITY).into() {
            return Err(ProtocolError::IdentityElement);
        }

        Ok(Self {
            big_r: rerandomized_big_r.to_affine(),
            // w + delta * a
            mu: presignature.w + delta * presignature.a,
            a: presignature.a,
            // u + tweak * a
            u: presignature.u + args.tweak.value() * presignature.a,
            e: presignature.e,
        })
    }

    #[cfg(test)]
    /// Outputs the same elements as in the `AdditivePresignOutput`
    /// Used for testing the core schemes without rerandomization
    pub fn new_without_rerandomization(presignature: &AdditivePresignOutput) -> Self {
        Self {
            big_r: presignature.big_r,
            mu: presignature.w,
            a: presignature.a,
            u: presignature.u,
            e: presignature.e,
        }
    }
}

/// Maximum incoming buffer entries for the additive robust ECDSA presign protocol.
pub(crate) const ADDITIVE_PRESIGN_MAX_INCOMING_BUFFER_ENTRIES: usize = 2;

/// The additive-variant presignature protocol.
///
/// This is the first phase of performing a signature, in which we perform
/// all the work we can do without yet knowing the message to be signed.
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
pub fn presign<R>(
    participants: &[Participant],
    me: Participant,
    args: PresignArguments,
    rng: R,
) -> Result<impl Protocol<Output = AdditivePresignOutput> + use<R>, InitializationError>
where
    R: CryptoRngCore + Send + 'static,
{
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

    // To prevent split-view attacks documented in docs/ecdsa/robust_ecdsa/signing.md
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during presigning must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }

    let ctx = Comms::with_buffer_capacity(ADDITIVE_PRESIGN_MAX_INCOMING_BUFFER_ENTRIES);
    let fut = do_presign(ctx.shared_channel(), participants, me, args, rng);
    Ok(make_protocol(ctx, fut))
}

/// /!\ Warning: the threshold in this scheme is the exactly the
///              same as the max number of malicious parties.
async fn do_presign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    args: PresignArguments,
    mut rng: impl CryptoRngCore,
) -> Result<AdditivePresignOutput, ProtocolError> {
    let rng = &mut rng;
    let threshold = args.max_malicious.value();
    // Round 1: identical to the parent presigning
    let degree = threshold
        .checked_mul(2)
        .ok_or(ProtocolError::IntegerOverflow)?;
    let polynomials = [
        // degree t random secret shares where t is the max number of malicious parties
        Polynomial::generate_polynomial(None, threshold, rng)?, // fk
        Polynomial::generate_polynomial(None, threshold, rng)?, // fa
        // degree 2t zero secret shares where t is the max number of malicious parties
        zero_secret_polynomial(degree, rng)?, // fb
        zero_secret_polynomial(degree, rng)?, // fd
        zero_secret_polynomial(degree, rng)?, // fe
    ];

    let wait_round_1 = chan.next_waitpoint();
    for p in participants.others(me) {
        let package = polynomials
            .iter()
            .map(|poly| poly.eval_at_participant(p))
            .collect::<Result<Vec<_>, _>>()?;
        chan.send_private(wait_round_1, p, &package)?;
    }

    let mut shares = Shares::new(&polynomials, me)?;

    // Round 2
    for (_, package) in recv_from_others(&chan, wait_round_1, &participants, me).await? {
        shares.add_shares(&package);
    }

    // Compute R_me = g^{k_me} and send it.
    // Unlike the parent presigning, w_me is kept secret: opening it here and
    // later opening mu = w + delta * a would reveal the nonce.
    let big_r_me = CoefficientCommitment::new(Secp256K1Group::generator() * shares.k());
    let wait_round_2 = chan.next_waitpoint();
    chan.send_many(wait_round_2, &big_r_me)?;

    // Round 3
    let mut verifyingshares_map = ParticipantMap::new(&participants);
    verifyingshares_map.put(me, big_r_me);
    while !verifyingshares_map.full() {
        let (from, big_r_p) = chan.recv(wait_round_2).await?;
        verifyingshares_map.put(from, big_r_p);
    }

    let identifiers: Vec<Scalar> = verifyingshares_map
        .participants()
        .iter()
        .map(Participant::scalar::<C>)
        .collect();

    let verifying_shares = verifyingshares_map
        .into_vec_or_none()
        .ok_or(ProtocolError::InvalidInterpolationArguments)?;

    let (threshold_plus1_identifiers, _) = identifiers
        .split_at_checked(threshold + 1)
        .ok_or_else(|| ProtocolError::AssertionFailed("Not enough identifiers".to_string()))?;
    let (threshold_plus1_verifying_shares, _) = verifying_shares
        .split_at_checked(threshold + 1)
        .ok_or_else(|| ProtocolError::AssertionFailed("Not enough verifying shares".to_string()))?;

    // check that the exponent interpolations match what has been received
    for (identifier, verifying_share) in identifiers
        .iter()
        .skip(threshold + 1)
        .zip(verifying_shares.iter().skip(threshold + 1))
    {
        let big_r_i = PolynomialCommitment::eval_exponent_interpolation(
            threshold_plus1_identifiers,
            threshold_plus1_verifying_shares,
            Some(identifier),
        )?;

        if big_r_i != *verifying_share {
            return Err(ProtocolError::AssertionFailed(
                "Exponent interpolation check failed.".to_string(),
            ));
        }

        chan.yield_point().await;
    }

    let big_r = PolynomialCommitment::eval_exponent_interpolation(
        threshold_plus1_identifiers,
        threshold_plus1_verifying_shares,
        None,
    )?;

    if big_r
        .value()
        .ct_eq(&<Secp256K1Group as Group>::identity())
        .into()
    {
        return Err(ProtocolError::IdentityElement);
    }

    let x_me = args.keygen_out.private_share.to_scalar();
    Ok(AdditivePresignOutput {
        big_r: big_r.value().to_affine(),
        a: shares.a(),
        w: shares.a() * shares.k() + shares.b(),
        u: shares.a() * x_me + shares.d(),
        e: shares.e(),
    })
}

#[cfg(test)]
#[expect(non_snake_case)]
mod test {
    use super::*;
    use frost_core::serialization::SerializableScalar;
    use rand::{RngCore, SeedableRng};
    use rstest::rstest;

    use crate::test_utils::{
        GenProtocol, MockCryptoRng, assert_buffer_capacity, generate_participants,
        generate_test_keys, make_keygen_output, run_protocol,
    };

    #[test]
    fn additive_presign__should_encode_nonce_mask_and_key_in_shares() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let participants = generate_participants(5);
        let max_malicious = 2;
        let (f, pk) = generate_test_keys(max_malicious, &mut rng);

        let mut protocols: GenProtocol<AdditivePresignOutput> =
            Vec::with_capacity(participants.len());
        for p in &participants {
            let keygen_out = make_keygen_output(&f, &pk, *p);
            let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
            let protocol = presign(
                &participants[..],
                *p,
                PresignArguments {
                    keygen_out,
                    max_malicious: max_malicious.into(),
                },
                rng_p,
            )
            .unwrap();
            protocols.push((*p, Box::new(protocol)));
        }

        // When
        let result = run_protocol(protocols).unwrap();

        // Then
        assert_eq!(result.len(), 5);
        assert!(result.windows(2).all(|w| w[0].1.big_r == w[1].1.big_r));

        let identifiers: Vec<Scalar> = result.iter().map(|(p, _)| p.scalar::<C>()).collect();
        let a_shares: Vec<_> = result
            .iter()
            .map(|(_, out)| SerializableScalar::<C>(out.a))
            .collect();
        let w_shares: Vec<_> = result
            .iter()
            .map(|(_, out)| SerializableScalar::<C>(out.w))
            .collect();
        let u_shares: Vec<_> = result
            .iter()
            .map(|(_, out)| SerializableScalar::<C>(out.u))
            .collect();
        let a = Polynomial::eval_interpolation(&identifiers, &a_shares, None)
            .unwrap()
            .0;
        let w = Polynomial::eval_interpolation(&identifiers, &w_shares, None)
            .unwrap()
            .0;
        let u = Polynomial::eval_interpolation(&identifiers, &u_shares, None)
            .unwrap()
            .0;
        let x = f.eval_at_zero().unwrap().0;

        // u encodes a * x
        assert_eq!(u, a * x);
        // w encodes a * k, i.e. g^{w / a} = R
        let k = w * a.invert().unwrap();
        assert_eq!(
            (ProjectivePoint::GENERATOR * k).to_affine(),
            result[0].1.big_r
        );
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn additive_presign__should_buffer_expected_entries(#[case] max_malicious: usize) {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let num_participants = 2 * max_malicious + 1;
        let participants = generate_participants(num_participants);
        let (f, pk) = generate_test_keys(max_malicious, &mut rng);

        // When + Then
        assert_buffer_capacity(
            &participants,
            &mut rng,
            |comms, p_list, p, rng_p| {
                let keygen_out = make_keygen_output(&f, &pk, p);
                do_presign(
                    comms.shared_channel(),
                    p_list,
                    p,
                    PresignArguments {
                        keygen_out,
                        max_malicious: max_malicious.into(),
                    },
                    rng_p,
                )
            },
            |_| ADDITIVE_PRESIGN_MAX_INCOMING_BUFFER_ENTRIES,
        );
    }
}
