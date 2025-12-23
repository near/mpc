// TODO(#122): remove this exception
#![allow(clippy::indexing_slicing)]

use super::{PresignArguments, PresignOutput};
use crate::participants::{Participant, ParticipantList, ParticipantMap};
use crate::{
    ecdsa::{
        CoefficientCommitment, Field, Polynomial, PolynomialCommitment, Scalar,
        Secp256K1ScalarField, Secp256K1Sha256,
    },
    errors::{InitializationError, ProtocolError},
    protocol::{
        helpers::recv_from_others,
        internal::{make_protocol, Comms, SharedChannel},
        Protocol,
    },
    SigningShare,
};
use frost_core::serialization::SerializableScalar;
use frost_secp256k1::{Group, Secp256K1Group};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;

type C = Secp256K1Sha256;

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
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = PresignOutput>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    if args.threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "threshold must be less than or equals to participant count".to_string(),
        ));
    }

    // if 2 * args.threshold + 1 > participants.len()
    // this complex way prevents overflowing
    if args
        .threshold
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            InitializationError::BadParameters(
                "2*threshold+1 must be less than usize::MAX".to_string(),
            )
        })?
        > participants.len()
    {
        return Err(InitializationError::BadParameters(
            "2*threshold+1 must be less than or equals to participant count".to_string(),
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
    let fut = do_presign(ctx.shared_channel(), participants, me, args, rng);
    Ok(make_protocol(ctx, fut))
}

/// /!\ Warning: the threshold in this scheme is the exactly the
///              same as the max number of malicious parties.
#[allow(clippy::too_many_lines)]
async fn do_presign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    args: PresignArguments,
    mut rng: impl CryptoRngCore,
) -> Result<PresignOutput, ProtocolError> {
    let rng = &mut rng;
    let threshold = args.threshold;
    // Round 0

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

    // send polynomial evaluations to participants
    let wait_round_0 = chan.next_waitpoint();

    for p in participants.others(me) {
        // Securely send to each other participant a secret share
        let package = polynomials
            .iter()
            .map(|poly| poly.eval_at_participant(p))
            .collect::<Result<Vec<_>, _>>()?;

        // send the evaluation privately to participant p
        chan.send_private(wait_round_0, p, &package)?;
    }

    // Evaluate my secret shares for my polynomials
    let mut shares = Shares::new(&polynomials, me)?;

    // Round 1
    // Receive evaluations from all participants
    for (_, package) in recv_from_others(&chan, wait_round_0, &participants, me).await? {
        // calculate the respective sum of the different shares received from each participant
        shares.add_shares(&package);
    }

    // Compute R_me = g^{k_me}
    let big_r_me = CoefficientCommitment::new(Secp256K1Group::generator() * shares.k());

    // Compute w_me = a_me * k_me + b_me
    let w_me = shares.a() * shares.k() + shares.b();

    // Send and receive
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &(&big_r_me, &SigningShare::<C>::new(w_me)))?;

    // Store the sent items
    let mut signingshares_map = ParticipantMap::new(&participants);
    let mut verifyingshares_map = ParticipantMap::new(&participants);
    signingshares_map.put(me, SerializableScalar(w_me));
    verifyingshares_map.put(me, big_r_me);

    // Receive and interpolate
    while !signingshares_map.full() {
        let (from, (big_r_p, w_p)): (_, (_, SigningShare<C>)) = chan.recv(wait_round_1).await?;
        // collect big_r_p and w_p in maps that will be later ordered
        // if the sender has already sent elements then put will return immediately
        signingshares_map.put(from, SerializableScalar(w_p.to_scalar()));
        verifyingshares_map.put(from, big_r_p);
    }

    let identifiers: Vec<Scalar> = signingshares_map
        .participants()
        .iter()
        .map(Participant::scalar::<C>)
        .collect();

    let signingshares = signingshares_map
        .into_vec_or_none()
        .ok_or(ProtocolError::InvalidInterpolationArguments)?;

    // exponent interpolation of big R
    let verifying_shares = verifyingshares_map
        .into_vec_or_none()
        .ok_or(ProtocolError::InvalidInterpolationArguments)?;

    #[cfg(feature = "actively_secure_robust_ecdsa")]
    {
        // Round 2
        // check that the exponent interpolations match what has been received
        for i in threshold + 1..identifiers.len() {
            let p = &identifiers[i];
            // exponent interpolation for (R0, .., Rt; i)
            let big_r_i = PolynomialCommitment::eval_exponent_interpolation(
                &identifiers[..=threshold],
                &verifying_shares[..=threshold],
                Some(p),
            )?;

            // check the interpolated R values match the received ones
            if big_r_i != verifying_shares[i] {
                return Err(ProtocolError::AssertionFailed(
                    "Exponent interpolation check failed.".to_string(),
                ));
            }
        }
    }
    // get only the first t+1 elements to interpolate
    // we know that identifiers.len()>threshold+1
    // evaluate the exponent interpolation on zero
    let big_r = PolynomialCommitment::eval_exponent_interpolation(
        &identifiers[..=threshold],
        &verifying_shares[..=threshold],
        None,
    )?;

    // check R is not identity
    if big_r
        .value()
        .ct_eq(&<Secp256K1Group as Group>::identity())
        .into()
    {
        return Err(ProtocolError::IdentityElement);
    }

    // polynomial interpolation of w
    let w = Polynomial::eval_interpolation(&identifiers, &signingshares, None)?;

    // check w is non-zero
    if w.0.is_zero().into() {
        return Err(ProtocolError::ZeroScalar);
    }

    #[cfg(feature = "actively_secure_robust_ecdsa")]
    {
        // Still in Round 2
        // Compute W_me = R^{a_me}
        let big_w_me = CoefficientCommitment::new(big_r.value() * shares.a());
        // Send W_me
        let wait_round_active = chan.next_waitpoint();
        chan.send_many(wait_round_active, &big_w_me)?;

        // Receive W_i
        let mut wshares_map = ParticipantMap::new(&participants);
        wshares_map.put(me, big_w_me);
        while !wshares_map.full() {
            let (from, big_w_p) = chan.recv(wait_round_active).await?;
            wshares_map.put(from, big_w_p);
        }
        // Compute exponent interpolation checks
        let wshares = wshares_map
            .into_vec_or_none()
            .ok_or(ProtocolError::InvalidInterpolationArguments)?;

        for i in threshold + 1..identifiers.len() {
            let p = &identifiers[i];
            // exponent interpolation for (W0, .., Wt; i)
            let big_w_i = PolynomialCommitment::eval_exponent_interpolation(
                &identifiers[..=threshold],
                &wshares[..=threshold],
                Some(p),
            )?;
            // check the interpolated W values match the received ones
            if big_w_i != wshares[i] {
                return Err(ProtocolError::AssertionFailed(
                    "Exponent interpolation check failed.".to_string(),
                ));
            }
        }
        // compute W as exponent interpolation for (W0, .., Wt; 0)
        let big_w = PolynomialCommitment::eval_exponent_interpolation(
            &identifiers[..=threshold],
            &wshares[..=threshold],
            None,
        )?;

        // check W == g^w
        if big_w
            .value()
            .ct_ne(&(<Secp256K1Group as Group>::generator() * w.0))
            .into()
        {
            return Err(ProtocolError::AssertionFailed(
                "Exponent interpolation check failed.".to_string(),
            ));
        }
    }

    // w is non-zero due to previous check and so I can unwrap safely
    let c_me = w.0.invert().unwrap() * shares.a();

    // Some extra computation is pushed in this offline phase
    let alpha_me = c_me + shares.d();

    let x_me = args.keygen_out.private_share.to_scalar();
    let beta_me = c_me * x_me;

    Ok(PresignOutput {
        big_r: big_r.value().to_affine(),
        alpha: alpha_me,
        beta: beta_me,
        c: c_me,
        e: shares.e(),
    })
}

/// Generates a secret polynomial where the constant term is zero
fn zero_secret_polynomial(
    degree: usize,
    rng: &mut impl CryptoRngCore,
) -> Result<Polynomial, ProtocolError> {
    let secret = Secp256K1ScalarField::zero();
    Polynomial::generate_polynomial(Some(secret), degree, rng)
}

/// Contains five shares used during presigniture
/// (k, a, b, d, e)
#[derive(serde::Deserialize, serde::Serialize)]
struct Shares([SerializableScalar<C>; 5]);

impl Shares {
    /// Constructs a new Shares out of five polynomials
    pub(crate) fn new(
        polynomials: &[Polynomial; 5],
        p: Participant,
    ) -> Result<Self, ProtocolError> {
        // iterate over the polynomials and map them
        let shares = polynomials
            .iter()
            .map(|poly| poly.eval_at_participant(p))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| ProtocolError::Other("Unable to build Shares".to_string()))?;
        Ok(Self(shares))
    }

    /// Returns k element
    pub(crate) fn k(&self) -> Scalar {
        self.0[0].0
    }

    /// Returns a element
    pub(crate) fn a(&self) -> Scalar {
        self.0[1].0
    }

    /// Returns b element
    pub(crate) fn b(&self) -> Scalar {
        self.0[2].0
    }

    /// Returns d element
    pub(crate) fn d(&self) -> Scalar {
        self.0[3].0
    }

    /// Returns e element
    pub(crate) fn e(&self) -> Scalar {
        self.0[4].0
    }

    /// Adds two sets of shares together respectively and puts the result back into self
    pub(crate) fn add_shares(&mut self, shares: &Self) {
        for i in 0..self.0.len() {
            self.0[i].0 += shares.0[i].0;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use frost_secp256k1::VerifyingKey;
    use k256::ProjectivePoint;
    use rand::{RngCore, SeedableRng};

    use crate::ecdsa::KeygenOutput;
    use crate::test_utils::{generate_participants, run_protocol, GenProtocol, MockCryptoRng};

    #[test]
    fn test_presign() {
        let mut rng = MockCryptoRng::seed_from_u64(42);

        let participants = generate_participants(5);

        let max_malicious = 2;

        let f = Polynomial::generate_polynomial(None, max_malicious, &mut rng).unwrap();
        let big_x = ProjectivePoint::GENERATOR * f.eval_at_zero().unwrap().0;

        let mut protocols: GenProtocol<PresignOutput> = Vec::with_capacity(participants.len());

        for p in &participants {
            // simulating the key packages for each participant
            let private_share = f.eval_at_participant(*p).unwrap();
            let verifying_key = VerifyingKey::new(big_x);
            let keygen_out = KeygenOutput {
                private_share: SigningShare::new(private_share.0),
                public_key: verifying_key,
            };

            let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());

            let protocol = presign(
                &participants[..],
                *p,
                PresignArguments {
                    keygen_out,
                    threshold: max_malicious,
                },
                rng_p,
            )
            .unwrap();
            protocols.push((*p, Box::new(protocol)));
        }

        let result = run_protocol(protocols).unwrap();

        assert!(result.len() == 5);
        // testing that big_r is the same accross participants
        assert!(result.windows(2).all(|w| w[0].1.big_r == w[1].1.big_r));

        insta::assert_json_snapshot!(result);
    }
}
