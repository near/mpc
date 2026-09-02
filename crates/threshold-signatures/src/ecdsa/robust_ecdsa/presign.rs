use crate::participants::{Participant, ParticipantList};
use crate::{
    MaxMalicious, SigningShare,
    ecdsa::{
        AffinePoint, Field, KeygenOutput, RerandomizationArguments, Scalar, Secp256K1ScalarField,
        Secp256K1Sha256,
    },
    errors::{InitializationError, ProtocolError},
    protocol::{
        Protocol,
        helpers::recv_from_others,
        internal::{Comms, SharedChannel, make_protocol},
    },
};
use frost_secp256k1::{Group, Secp256K1Group};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
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
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
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

impl_secret_debug!(PresignOutput {
    show: [big_r],
    redact: [c, e, alpha, beta]
});

impl ConstantTimeEq for PresignOutput {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.big_r.ct_eq(&other.big_r)
            & self.c.ct_eq(&other.c)
            & self.e.ct_eq(&other.e)
            & self.alpha.ct_eq(&other.alpha)
            & self.beta.ct_eq(&other.beta)
    }
}

impl PartialEq for PresignOutput {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for PresignOutput {}

/// The output of the presigning protocol.
/// Contains the signature precomputed elements
/// independently of the message
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RerandomizedPresignOutput {
    /// The rerandomized public nonce commitment.
    #[zeroize(skip)]
    pub(super) big_r: AffinePoint,

    /// Our rerandomized secret shares of the nonces.
    pub(super) e: Scalar,
    pub(super) alpha: Scalar,
    pub(super) beta: Scalar,
}

impl_secret_debug!(RerandomizedPresignOutput {
    show: [big_r],
    redact: [e, alpha, beta]
});

impl RerandomizedPresignOutput {
    pub fn rerandomize_presign(
        presignature: &PresignOutput,
        args: &RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != args.big_r {
            return Err(ProtocolError::IncompatibleRerandomizationInputs);
        }
        let delta = args.derive_randomness()?;
        if delta.is_zero().into() {
            return Err(ProtocolError::ZeroScalar);
        }

        // cannot be zero due to the previous check
        let inv_delta = delta.invert().unwrap();

        // delta * R
        let rerandomized_big_r = presignature.big_r * delta;

        // alpha * delta^{-1}
        let rerandomized_alpha = presignature.alpha * inv_delta;

        // (beta + c*tweak) * delta^{-1}
        let rerandomized_beta =
            (presignature.beta + presignature.c * args.tweak.value()) * inv_delta;

        Ok(Self {
            big_r: rerandomized_big_r.into(),
            alpha: rerandomized_alpha,
            beta: rerandomized_beta,
            e: presignature.e,
        })
    }

    #[cfg(test)]
    /// Outputs the same elements as in the [`PresignatureOutput`]
    /// Used for testing the core schemes without rerandomization
    pub fn new_without_rerandomization(presignature: &PresignOutput) -> Self {
        Self {
            big_r: presignature.big_r,
            alpha: presignature.alpha,
            beta: presignature.beta,
            e: presignature.e,
        }
    }
}

/// Maximum incoming buffer entries for the robust ECDSA presign protocol.
pub(crate) const ROBUST_ECDSA_PRESIGN_MAX_INCOMING_BUFFER_ENTRIES: usize = 1;

/// The presignature protocol.
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
) -> Result<impl Protocol<Output = PresignOutput> + use<R>, InitializationError>
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

    let ctx = Comms::with_buffer_capacity(ROBUST_ECDSA_PRESIGN_MAX_INCOMING_BUFFER_ENTRIES);
    let fut = do_presign(ctx.shared_channel(), participants, me, args, rng);
    Ok(make_protocol(ctx, fut))
}

/// The stub presigning protocol.
///
/// One broadcast round: every participant contributes a random summand to the nonce
/// `k`, so all parties learn `k` in the clear and agree on `R = k * G`. The output
/// fields are then filled so that [`super::sign::sign`]'s unchanged Lagrange
/// linearization reconstructs a valid ECDSA signature:
///
/// - `alpha = c = k^{-1}` are held identically by everybody, and Lagrange
///   coefficients at zero sum to one, so they combine back to `k^{-1}`;
/// - `beta = k^{-1} * x_i` is scaled by the party's real key share, so it combines
///   to `k^{-1} * x`;
/// - `e = 0`, the real scheme's zero-sharing mask, is not needed here.
async fn do_presign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    args: PresignArguments,
    mut rng: impl CryptoRngCore,
) -> Result<PresignOutput, ProtocolError> {
    let k_me = frost_core::random_nonzero::<C, _>(&mut rng);
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &SigningShare::<C>::new(k_me))?;

    let mut k = k_me;
    for (_, k_p) in
        recv_from_others::<SigningShare<C>>(&chan, wait_round_1, &participants, me).await?
    {
        k += k_p.to_scalar();
    }

    if k.is_zero().into() {
        return Err(ProtocolError::ZeroScalar);
    }
    // cannot be zero due to the previous check
    let k_inv = k.invert().unwrap();

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
    use rand::{RngCore, SeedableRng};

    use crate::test_utils::{
        GenProtocol, MockCryptoRng, generate_participants, generate_test_keys, make_keygen_output,
        run_protocol,
    };
    use rstest::rstest;

    #[test]
    fn test_presign() {
        let mut rng = MockCryptoRng::seed_from_u64(42);

        let participants = generate_participants(5);

        let max_malicious = 2;

        let (f, pk) = generate_test_keys(max_malicious, &mut rng);

        let mut protocols: GenProtocol<PresignOutput> = Vec::with_capacity(participants.len());

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

        let result = run_protocol(protocols).unwrap();

        assert_eq!(result.len(), 5);
        // testing that big_r is the same accross participants
        assert!(result.windows(2).all(|w| w[0].1.big_r == w[1].1.big_r));

        insta::assert_json_snapshot!(result);
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn test_presign_buffer_entries(#[case] max_malicious: usize) {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let num_participants = 2 * max_malicious + 1;
        let participants = generate_participants(num_participants);
        let (f, pk) = generate_test_keys(max_malicious, &mut rng);

        // When + Then
        crate::test_utils::assert_buffer_capacity(
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
            |_| ROBUST_ECDSA_PRESIGN_MAX_INCOMING_BUFFER_ENTRIES,
        );
    }
}
