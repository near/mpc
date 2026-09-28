//! The robust ECDSA signing protocol of `docs/ecdsa/robust_ecdsa/signing.md`, run
//! as a single protocol; it supersedes the stub in `presign.rs` and `sign.rs`.

use elliptic_curve::scalar::IsHigh;
use frost_core::serialization::SerializableScalar;
use frost_secp256k1::{Group, Secp256K1Group};
use rand_core::CryptoRngCore;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::ZeroizeOnDrop;

use super::presign::PresignArguments;
use crate::crypto::{
    constants::NEAR_ROBUST_ECDSA_SIGN_LABEL,
    hash::{HashOutput, hash},
    pedersen,
    proofs::{strobe_transcript::Transcript, w_opening},
};
use crate::participants::{Participant, ParticipantList, ParticipantMap};
use crate::{
    SigningShare,
    ecdsa::{
        AffinePoint, CoefficientCommitment, Field, Polynomial, PolynomialCommitment, Scalar,
        Secp256K1ScalarField, Secp256K1Sha256, Signature, SignatureOption, Tweak, x_coordinate,
    },
    errors::{InitializationError, ProtocolError},
    protocol::{
        Protocol,
        helpers::recv_from_others,
        internal::{Comms, SharedChannel, make_protocol},
    },
};

type C = Secp256K1Sha256;

/// The state carried from the presigning rounds into the signing round.
#[derive(ZeroizeOnDrop)]
struct Presignature {
    /// The public nonce commitment.
    #[zeroize(skip)]
    big_r: AffinePoint,

    /// Our secret shares of the nonce.
    e: Scalar,
    alpha: Scalar,
    beta: Scalar,
}

/// Maximum incoming buffer entries for the coordinator: the commitments, the share
/// evaluations, the `(R, w, eta)` triples, the proofs, and the signature shares.
pub(crate) const ROBUST_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES: usize = 5;

/// Runs the whole robust ECDSA signing protocol; only the coordinator obtains the signature.
pub fn presign_and_sign<R>(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    args: PresignArguments,
    tweak: Tweak,
    msg_hash: Scalar,
    rng: R,
) -> Result<impl Protocol<Output = SignatureOption> + use<R>, InitializationError>
where
    R: CryptoRngCore + Send + 'static,
{
    let participants = validate_arguments(participants, me, &args)?;

    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }

    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0".to_string(),
        ));
    }

    let ctx =
        Comms::with_buffer_capacity(ROBUST_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES);
    let fut = do_presign_and_sign(
        ctx.shared_channel(),
        participants,
        coordinator,
        me,
        args,
        tweak,
        msg_hash,
        rng,
    );
    Ok(make_protocol(ctx, fut))
}

#[allow(clippy::too_many_arguments)]
async fn do_presign_and_sign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    coordinator: Participant,
    me: Participant,
    mut args: PresignArguments,
    tweak: Tweak,
    msg_hash: Scalar,
    mut rng: impl CryptoRngCore,
) -> Result<SignatureOption, ProtocolError> {
    // key derivation is applied to the key shares before round 1
    let public_key = tweak
        .derive_verifying_key(&args.keygen_out.public_key)
        .to_element()
        .to_affine();
    args.keygen_out.private_share = tweak.derive_signing_share(&args.keygen_out.private_share);

    let presignature = presign_rounds(&mut chan, &participants, me, args, &mut rng).await?;
    chan.yield_point().await;

    sign_round(
        &mut chan,
        &participants,
        coordinator,
        me,
        public_key,
        &presignature,
        msg_hash,
    )
    .await
}

/// Validates the presigning inputs, enforcing exactly `2 * max_malicious + 1` participants.
fn validate_arguments(
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

    // To prevent split-view attacks documented in docs/ecdsa/robust_ecdsa/signing.md
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during presigning must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }

    Ok(participants)
}

/// /!\ Warning: the threshold in this scheme is the exactly the
///              same as the max number of malicious parties.
#[allow(clippy::too_many_lines)]
async fn presign_rounds(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: Participant,
    args: PresignArguments,
    rng: &mut impl CryptoRngCore,
) -> Result<Presignature, ProtocolError> {
    let threshold = args.max_malicious.value();
    // Round 1
    let degree = threshold
        .checked_mul(2)
        .ok_or(ProtocolError::IntegerOverflow)?;
    let polynomials = [
        // Steps 1.1 and 1.2: degree t random polynomials
        Polynomial::generate_polynomial(None, threshold, rng)?, // fk
        Polynomial::generate_polynomial(None, threshold, rng)?, // fa
        // Steps 1.3 and 1.4: degree 2t polynomials with zero constant term
        zero_secret_polynomial(degree, rng)?, // fb
        zero_secret_polynomial(degree, rng)?, // fd
        zero_secret_polynomial(degree, rng)?, // fe
        // blinding polynomials for the Pedersen commitments
        Polynomial::generate_polynomial(None, threshold, rng)?, // frho
        zero_secret_polynomial(degree, rng)?,                   // fsigma
    ];

    // Step 1.5: commit to fa and fb under the blinding polynomials
    let com_a = pedersen::commit_polynomial(&polynomials[1], &polynomials[5])?;
    let com_b = pedersen::commit_polynomial(&polynomials[2], &polynomials[6])?;
    // the constant term of com_b is the identity and is not sent
    let com_b = strip_identity_constant(&com_b)?;

    // Step 1.6
    let wait_commitments = chan.next_waitpoint();
    chan.send_many(wait_commitments, &(&com_a, &com_b))?;

    // send polynomial evaluations to participants
    let wait_round_1 = chan.next_waitpoint();

    // Step 1.7
    for p in participants.others(me) {
        // Securely send to each other participant a secret share
        let package = polynomials
            .iter()
            .map(|poly| poly.eval_at_participant(p))
            .collect::<Result<Vec<_>, _>>()?;

        // send the evaluation privately to participant p
        chan.send_private(wait_round_1, p, &package)?;
    }

    // Evaluate my secret shares for my polynomials
    let mut shares = Shares::new(&polynomials, me)?;

    // Round 2
    // Step 2.1: receive the committed polynomials, checking their degrees
    let mut commitments_map = ParticipantMap::new(participants);
    commitments_map.put(me, (com_a, com_b));
    while !commitments_map.full() {
        let (from, (com_a_p, com_b_p)): (_, (PolynomialCommitment, PolynomialCommitment)) =
            chan.recv(wait_commitments).await?;
        // com_b is of degree 2t - 1 on the wire as its identity constant is not sent
        if com_a_p.degree() != threshold || com_b_p.degree() != degree - 1 {
            return Err(ProtocolError::MaliciousParticipant(from));
        }
        commitments_map.put(from, (com_a_p, com_b_p));
    }

    // Step 2.8: hash the committed polynomials in canonical (sorted participant) order
    let eta = hash(&commitments_map)?;

    // Steps 2.2 to 2.4: receive the share evaluations, verify them against the
    // dealer's commitments (identifying a bad dealer to me alone), and sum them
    for (from, package) in recv_from_others::<Shares>(chan, wait_round_1, participants, me).await? {
        let (com_a_p, com_b_p) = commitments_map.index(from)?;
        let valid_a = pedersen::verify_share(com_a_p, me, &package.a(), &package.rho())?;
        let valid_b = pedersen::verify_share(
            &com_b_p.extend_with_identity()?,
            me,
            &package.b(),
            &package.sigma(),
        )?;
        if !(valid_a && valid_b) {
            return Err(ProtocolError::InvalidSecretShare(from));
        }
        shares.add_shares(&package);
    }

    // Step 2.6
    // Compute R_me = g^{k_me}
    let big_r_me = CoefficientCommitment::new(Secp256K1Group::generator() * shares.k());

    // Step 2.7
    // Compute w_me = a_me * k_me + b_me
    let w_me = shares.a() * shares.k() + shares.b();

    // Step 2.9
    // Send and receive
    let wait_round_2 = chan.next_waitpoint();
    chan.send_many(
        wait_round_2,
        &(&big_r_me, &SigningShare::<C>::new(w_me), &eta),
    )?;

    // Store the sent items
    let mut signingshares_map = ParticipantMap::new(participants);
    let mut verifyingshares_map = ParticipantMap::new(participants);
    signingshares_map.put(me, SerializableScalar(w_me));
    verifyingshares_map.put(me, big_r_me);

    // Round 3
    // Receive and interpolate
    while !signingshares_map.full() {
        // Step 3.1: receive, asserting that the commitment transcripts match
        let (from, (big_r_p, w_p, eta_p)): (_, (_, SigningShare<C>, HashOutput)) =
            chan.recv(wait_round_2).await?;
        if eta_p != eta {
            return Err(ProtocolError::AssertionFailed(
                "commitment hash mismatch in robust ecdsa presign".to_string(),
            ));
        }
        // collect big_r_p and w_p in maps that will be later ordered
        // if the sender has already sent elements then put will return immediately
        signingshares_map.put(from, SerializableScalar(w_p.to_scalar()));
        verifyingshares_map.put(from, big_r_p);
    }

    // the maps hold one entry per participant, in the same sorted order
    let identifiers: Vec<Scalar> = participants
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
        // Step 3.2
        // exponent interpolation for (R0, .., Rt; i)
        let big_r_i = PolynomialCommitment::eval_exponent_interpolation(
            threshold_plus1_identifiers,
            threshold_plus1_verifying_shares,
            Some(identifier),
        )?;

        // check the interpolated R values match the received ones
        if big_r_i != *verifying_share {
            return Err(ProtocolError::AssertionFailed(
                "Exponent interpolation check failed.".to_string(),
            ));
        }

        chan.yield_point().await;
    }
    // Step 3.3
    // get only the first t+1 elements to interpolate
    // we know that identifiers.len()>threshold+1
    // evaluate the exponent interpolation on zero
    let big_r = PolynomialCommitment::eval_exponent_interpolation(
        threshold_plus1_identifiers,
        threshold_plus1_verifying_shares,
        None,
    )?;

    // Step 3.4
    // check R is not identity
    if big_r
        .value()
        .ct_eq(&<Secp256K1Group as Group>::identity())
        .into()
    {
        return Err(ProtocolError::IdentityElement);
    }

    // Step 3.5
    // polynomial interpolation of w
    let (w_2tp1_identifiers, _) = identifiers
        .split_at_checked(2 * threshold + 1)
        .ok_or_else(|| ProtocolError::AssertionFailed("Not enough identifiers".to_string()))?;
    let (w_2tp1_verifying_shares, _) = signingshares
        .split_at_checked(2 * threshold + 1)
        .ok_or_else(|| ProtocolError::AssertionFailed("Not enough verifying shares".to_string()))?;
    let w = Polynomial::eval_interpolation(w_2tp1_identifiers, w_2tp1_verifying_shares, None)?;

    // Step 3.6
    // check w is non-zero
    if w.0.is_zero().into() {
        return Err(ProtocolError::ZeroScalar);
    }

    // Step 2.5: sum the committed polynomials
    let mut commitments = commitments_map
        .into_vec_or_none()
        .ok_or(ProtocolError::InvalidInterpolationArguments)?
        .into_iter();
    let (mut com_a_sum, mut com_b_sum) = commitments
        .next()
        .ok_or(ProtocolError::InvalidInterpolationArguments)?;
    for (com_a_p, com_b_p) in commitments {
        com_a_sum = com_a_sum.add(&com_a_p)?;
        com_b_sum = com_b_sum.add(&com_b_p)?;
    }
    // restore the identity constant term stripped from the wire form
    let com_b_sum = com_b_sum.extend_with_identity()?;

    // the Fiat-Shamir challenges are bound to eta and the prover's identity
    let mut transcript = Transcript::new(NEAR_ROBUST_ECDSA_SIGN_LABEL);
    transcript.message(b"eta", eta.as_ref());

    // Step 3.7: prove that w_me opens consistently with the committed a_me and b_me
    let big_w_me = Secp256K1Group::generator() * w_me;
    let big_r_me_point = big_r_me.value();
    let com_a_me = com_a_sum.eval_at_participant(me)?.value();
    let com_b_me = com_b_sum.eval_at_participant(me)?.value();
    let statement = w_opening::Statement::<C> {
        big_w: &big_w_me,
        big_r: &big_r_me_point,
        com_a: &com_a_me,
        com_b: &com_b_me,
        h_ped: &*pedersen::PEDERSEN_H,
    };
    let witness = w_opening::Witness::<C> {
        a: SerializableScalar(shares.a()),
        b: SerializableScalar(shares.b()),
        rho: SerializableScalar(shares.rho()),
        sigma: SerializableScalar(shares.sigma()),
    };
    let nonces = (
        frost_core::random_nonzero::<C, _>(rng),
        frost_core::random_nonzero::<C, _>(rng),
        frost_core::random_nonzero::<C, _>(rng),
        frost_core::random_nonzero::<C, _>(rng),
    );
    let pi = w_opening::prove_with_nonces(
        &mut transcript.fork(b"party", &me.bytes()),
        statement,
        &witness,
        &nonces,
    )?;

    // Step 3.8: broadcast the proof
    let wait_round_3 = chan.next_waitpoint();
    chan.send_many(wait_round_3, &pi)?;

    // Round 4
    // Steps 4.1 and 4.2: verify every proof, identifying a misbehaving party to me
    for (from, pi_p) in
        recv_from_others::<w_opening::Proof<C>>(chan, wait_round_3, participants, me).await?
    {
        let index = participants.index(from)?;
        let w_p = signingshares
            .get(index)
            .ok_or(ProtocolError::InvalidIndex)?;
        let big_r_p = verifying_shares
            .get(index)
            .ok_or(ProtocolError::InvalidIndex)?
            .value();
        let big_w_p = Secp256K1Group::generator() * w_p.0;
        let com_a_p = com_a_sum.eval_at_participant(from)?.value();
        let com_b_p = com_b_sum.eval_at_participant(from)?.value();
        let statement_p = w_opening::Statement::<C> {
            big_w: &big_w_p,
            big_r: &big_r_p,
            com_a: &com_a_p,
            com_b: &com_b_p,
            h_ped: &*pedersen::PEDERSEN_H,
        };
        let valid = w_opening::verify(
            &mut transcript.fork(b"party", &from.bytes()),
            statement_p,
            &pi_p,
        )?;
        if !valid {
            return Err(ProtocolError::InvalidProofOfKnowledge(from));
        }
        chan.yield_point().await;
    }

    // Step 4.3
    // w is non-zero due to previous check and so I can unwrap safely
    let c_me = w.0.invert().unwrap() * shares.a();

    // Step 4.4
    // Some extra computation is pushed in this offline phase
    let alpha_me = c_me + shares.d();

    // Step 4.5
    let x_me = args.keygen_out.private_share.to_scalar();
    let beta_me = c_me * x_me;

    Ok(Presignature {
        big_r: big_r.value().to_affine(),
        alpha: alpha_me,
        beta: beta_me,
        e: shares.e(),
    })
}

/// Runs the final signing round as either the coordinator or a participant.
async fn sign_round(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    public_key: AffinePoint,
    presignature: &Presignature,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    if me == coordinator {
        do_sign_coordinator(chan, participants, me, public_key, presignature, msg_hash).await
    } else {
        do_sign_participant(chan, participants, coordinator, me, presignature, msg_hash)
    }
}

/// Performs signing from any participant's perspective (except the coordinator)
fn do_sign_participant(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    presignature: &Presignature,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    let s_me = compute_signature_share(presignature, msg_hash, participants, me)?;
    let wait_round = chan.next_waitpoint();
    chan.send_private(wait_round, coordinator, &s_me)?;

    Ok(None)
}

/// Performs signing from only the coordinator's perspective
async fn do_sign_coordinator(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: Participant,
    public_key: AffinePoint,
    presignature: &Presignature,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    let mut s = compute_signature_share(presignature, msg_hash, participants, me)?.0;
    let wait_round = chan.next_waitpoint();

    for (_, s_i) in
        recv_from_others::<SerializableScalar<C>>(chan, wait_round, participants, me).await?
    {
        // Sum the linearized shares
        s += s_i.0;
    }

    // raise error if s is zero
    if s.is_zero().into() {
        return Err(ProtocolError::AssertionFailed(
            "signature part s cannot be zero".to_string(),
        ));
    }
    // Normalize s
    s.conditional_assign(&(-s), s.is_high());

    let sig = Signature {
        big_r: presignature.big_r,
        s,
    };

    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }

    Ok(Some(sig))
}

/// A common computation done by both the coordinator and the other participants
fn compute_signature_share(
    presignature: &Presignature,
    msg_hash: Scalar,
    participants: &ParticipantList,
    me: Participant,
) -> Result<SerializableScalar<C>, ProtocolError> {
    // (beta_i + tweak * k_i) * delta^{-1}
    let big_r = presignature.big_r;
    let big_r_x_coordinate = x_coordinate(&big_r);
    // beta * Rx + e
    let beta = presignature.beta * big_r_x_coordinate + presignature.e;

    let s_me = msg_hash * presignature.alpha + beta;
    // lambda_i * s_i
    let linearized_s_me = s_me * participants.lagrange::<C>(me)?;
    Ok(SerializableScalar::<C>(linearized_s_me))
}

/// Generates a secret polynomial where the constant term is zero
fn zero_secret_polynomial(
    degree: usize,
    rng: &mut impl CryptoRngCore,
) -> Result<Polynomial, ProtocolError> {
    let secret = Secp256K1ScalarField::zero();
    Polynomial::generate_polynomial(Some(secret), degree, rng)
}

/// Removes the identity constant term of a committed polynomial before sending.
fn strip_identity_constant(
    commitment: &PolynomialCommitment,
) -> Result<PolynomialCommitment, ProtocolError> {
    let coefficients = commitment.get_coefficients();
    let tail = coefficients
        .get(1..)
        .ok_or(ProtocolError::EmptyOrZeroCoefficients)?;
    PolynomialCommitment::new(tail)
}

/// Contains the seven shares used during presigning
/// (k, a, b, d, e, rho, sigma)
#[derive(serde::Deserialize, serde::Serialize)]
struct Shares([SerializableScalar<C>; 7]);

impl Shares {
    /// Constructs a new Shares out of seven polynomials
    pub(crate) fn new(
        polynomials: &[Polynomial; 7],
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

    /// Returns rho element
    pub(crate) fn rho(&self) -> Scalar {
        self.0[5].0
    }

    /// Returns sigma element
    pub(crate) fn sigma(&self) -> Scalar {
        self.0[6].0
    }

    /// Adds two sets of shares together respectively and puts the result back into self
    pub(crate) fn add_shares(&mut self, shares: &Self) {
        for (share, other_share) in self.0.iter_mut().zip(shares.0.iter()) {
            share.0 += other_share.0;
        }
    }
}
