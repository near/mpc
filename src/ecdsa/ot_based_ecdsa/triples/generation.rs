use frost_core::serialization::SerializableScalar;
use frost_core::Ciphersuite;
use rand_core::CryptoRngCore;

use crate::{
    crypto::{
        commitment::{commit, Commitment},
        hash::{hash, HashOutput},
        proofs::{dlog, dlogeq, strobe_transcript::Transcript},
        random::Randomness,
    },
    ecdsa::{
        CoefficientCommitment, Polynomial, PolynomialCommitment, ProjectivePoint, Scalar,
        Secp256K1Sha256,
    },
    participants::{ParticipantCounter, ParticipantList, ParticipantMap},
    protocol::{
        errors::{InitializationError, ProtocolError},
        internal::{make_protocol, Comms},
        Participant, Protocol,
    },
};

use super::{
    multiplication::{multiplication, multiplication_many},
    TriplePub, TripleShare,
};

/// Creates a transcript and internally encodes the following data:
///     LABEL,  NAME, Participants, threshold
fn create_transcript(
    participants: &ParticipantList,
    threshold: usize,
) -> Result<Transcript, ProtocolError> {
    let mut transcript = Transcript::new(LABEL);

    transcript.message(b"group", NAME);

    let enc = rmp_serde::encode::to_vec(participants).map_err(|_| ProtocolError::ErrorEncoding)?;
    transcript.message(b"participants", &enc);
    // To allow interop between platforms where usize is different
    transcript.message(
        b"threshold",
        &u64::try_from(threshold).unwrap().to_be_bytes(),
    );
    Ok(transcript)
}

/// The output of running the triple generation protocol.
pub type TripleGenerationOutput = (TripleShare, TriplePub);

pub type TripleGenerationOutputMany = Vec<(TripleShare, TriplePub)>;
type C = Secp256K1Sha256;

const LABEL: &[u8] = b"Near threshold signatures triple generation";
const NAME: &[u8] = b"Secp256K1Sha256";
async fn do_generation(
    comms: Comms,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
    mut rng: impl CryptoRngCore + Send + 'static,
) -> Result<TripleGenerationOutput, ProtocolError> {
    let mut chan = comms.shared_channel();
    let mut transcript = create_transcript(&participants, threshold)?;

    // Spec 1.2
    let e = Polynomial::generate_polynomial(None, threshold - 1, &mut rng)?;
    let f = Polynomial::generate_polynomial(None, threshold - 1, &mut rng)?;
    // Spec 1.3
    // We will generate a poly of degree threshold - 2 then later extend it with identity.
    // This is to prevent serialization from failing
    let mut l = Polynomial::generate_polynomial(None, threshold - 2, &mut rng)?;

    // Spec 1.4
    let big_e_i = e.commit_polynomial()?;
    let big_f_i = f.commit_polynomial()?;
    let big_l_i = l.commit_polynomial()?;

    // Spec 1.5
    let (my_commitment, my_randomizer) = commit(&mut rng, &(&big_e_i, &big_f_i, &big_l_i))
        .map_err(|_| ProtocolError::PointSerialization)?;

    // Spec 1.6
    let wait0 = chan.next_waitpoint();
    chan.send_many(wait0, &my_commitment)?;

    // Spec 2.1
    let mut all_commitments = ParticipantMap::new(&participants);
    all_commitments.put(me, my_commitment);
    while !all_commitments.full() {
        let (from, commitment) = chan.recv(wait0).await?;
        all_commitments.put(from, commitment);
    }

    // Spec 2.2
    let my_confirmation = hash(&all_commitments)?;

    // Spec 2.3
    transcript.message(b"confirmation", my_confirmation.as_ref());

    let my_phi_proof0_nonce = <C>::generate_nonce(&mut rng);
    let my_phi_proof1_nonce = <C>::generate_nonce(&mut rng);
    let my_phi_proof_nonce = frost_core::random_nonzero::<C, _>(&mut rng);

    // Spec 2.4
    let multiplication_task = {
        // cannot fail as both polynomials are non-empty (generated locally)
        let e0 = e.eval_at_zero()?;
        let f0 = f.eval_at_zero()?;
        multiplication(
            comms.clone(),
            my_confirmation,
            participants.clone(),
            me,
            e0.0,
            f0.0,
        )
    };

    struct ParallelToMultiplicationTaskOutput<'a> {
        seen: ParticipantCounter<'a>,
        big_e: PolynomialCommitment,
        big_f: PolynomialCommitment,
        big_l: PolynomialCommitment,
        big_c: ProjectivePoint,
        a_i: Scalar,
        b_i: Scalar,
    }

    let parallel_to_multiplication_task = async {
        // Spec 2.5
        let wait1 = chan.next_waitpoint();
        chan.send_many(wait1, &my_confirmation)?;

        // Spec 2.6
        let statement0 = dlog::Statement::<C> {
            public: &big_e_i.eval_at_zero()?.value(),
        };
        let witness0 = dlog::Witness::<C> {
            x: e.eval_at_zero()?,
        };
        let my_phi_proof0 = dlog::prove_with_nonce(
            &mut transcript.fork(b"dlog0", &me.bytes()),
            statement0,
            witness0,
            my_phi_proof0_nonce,
        )?;
        let statement1 = dlog::Statement::<C> {
            public: &big_f_i.eval_at_zero()?.value(),
        };
        let witness1 = dlog::Witness::<C> {
            x: f.eval_at_zero()?,
        };
        let my_phi_proof1 = dlog::prove_with_nonce(
            &mut transcript.fork(b"dlog1", &me.bytes()),
            statement1,
            witness1,
            my_phi_proof1_nonce,
        )?;

        // Spec 2.7
        let wait2 = chan.next_waitpoint();
        {
            chan.send_many(
                wait2,
                &(
                    &big_e_i,
                    &big_f_i,
                    &big_l_i,
                    my_randomizer,
                    my_phi_proof0,
                    my_phi_proof1,
                ),
            )?;
        }

        // Spec 2.8
        let wait3 = chan.next_waitpoint();
        for p in participants.others(me) {
            let a_i_j = e.eval_at_participant(p)?;
            let b_i_j = f.eval_at_participant(p)?;
            chan.send_private(wait3, p, &(a_i_j, b_i_j))?;
        }
        let mut a_i = e.eval_at_participant(me)?.0;
        let mut b_i = f.eval_at_participant(me)?.0;

        // Spec 3.1 + 3.2
        let mut seen = ParticipantCounter::new(&participants);
        seen.put(me);
        while !seen.full() {
            let (from, confirmation): (_, HashOutput) = chan.recv(wait1).await?;
            if !seen.put(from) {
                continue;
            }
            if confirmation != my_confirmation {
                return Err(ProtocolError::AssertionFailed(format!(
                    "confirmation from {from:?} did not match expectation"
                )));
            }
        }

        // Spec 3.3 + 3.4, and also part of 3.6, 5.3, for summing up the Es, Fs, and Ls.
        let mut big_e = big_e_i.clone();
        let mut big_f = big_f_i;
        let mut big_l = big_l_i;
        let mut big_e_j_zero = ParticipantMap::new(&participants);
        seen.clear();
        seen.put(me);
        while !seen.full() {
            let (
                from,
                (
                    their_big_e,
                    their_big_f,
                    their_big_l,
                    their_randomizer,
                    their_phi_proof0,
                    their_phi_proof1,
                ),
            ): (
                _,
                (
                    PolynomialCommitment,
                    PolynomialCommitment,
                    PolynomialCommitment,
                    _,
                    _,
                    _,
                ),
            ) = chan.recv(wait2).await?;
            if !seen.put(from) {
                continue;
            }

            if their_big_e.degree() != threshold - 1
                || their_big_f.degree() != threshold - 1
                // testing threshold - 2 because the identity element is non-serializable
                || their_big_l.degree() != threshold - 2
            {
                return Err(ProtocolError::AssertionFailed(format!(
                    "polynomial from {from:?} has the wrong length"
                )));
            }

            if !all_commitments[from]
                .check(
                    &(&their_big_e, &their_big_f, &their_big_l),
                    &their_randomizer,
                )
                .map_err(|_| ProtocolError::PointSerialization)?
            {
                return Err(ProtocolError::AssertionFailed(format!(
                    "commitment from {from:?} did not match revealed F"
                )));
            }

            let statement0 = dlog::Statement::<C> {
                public: &their_big_e.eval_at_zero()?.value(),
            };

            if !dlog::verify(
                &mut transcript.fork(b"dlog0", &from.bytes()),
                statement0,
                &their_phi_proof0,
            )? {
                return Err(ProtocolError::AssertionFailed(format!(
                    "dlog proof from {from:?} failed to verify"
                )));
            }

            let statement1 = dlog::Statement::<C> {
                public: &their_big_f.eval_at_zero()?.value(),
            };
            if !dlog::verify(
                &mut transcript.fork(b"dlog1", &from.bytes()),
                statement1,
                &their_phi_proof1,
            )? {
                return Err(ProtocolError::AssertionFailed(format!(
                    "dlog proof from {from:?} failed to verify"
                )));
            }

            big_e_j_zero.put(from, their_big_e.eval_at_zero()?);
            big_e = big_e.add(&their_big_e)?;
            big_f = big_f.add(&their_big_f)?;
            big_l = big_l.add(&their_big_l)?;
        }

        // Spec 3.5 + 3.6
        seen.clear();
        seen.put(me);
        while !seen.full() {
            let (from, (a_j_i, b_j_i)): (_, (SerializableScalar<C>, SerializableScalar<C>)) =
                chan.recv(wait3).await?;
            if !seen.put(from) {
                continue;
            }
            a_i += &a_j_i.0;
            b_i += &b_j_i.0;
        }

        // Spec 3.7
        if big_e.eval_at_participant(me)?.value() != ProjectivePoint::GENERATOR * a_i
            || big_f.eval_at_participant(me)?.value() != ProjectivePoint::GENERATOR * b_i
        {
            return Err(ProtocolError::AssertionFailed(
                "received bad private share".to_string(),
            ));
        }

        // Spec 3.8
        let big_c_i = big_f.eval_at_zero()?.value() * e.eval_at_zero()?.0;

        // Spec 3.9
        let statement = dlogeq::Statement::<C> {
            public0: &big_e_i.eval_at_zero()?.value(),
            generator1: &big_f.eval_at_zero()?.value(),
            public1: &big_c_i,
        };
        let witness = dlogeq::Witness {
            x: e.eval_at_zero()?,
        };
        let my_phi_proof = dlogeq::prove_with_nonce(
            &mut transcript.fork(b"dlogeq0", &me.bytes()),
            statement,
            witness,
            my_phi_proof_nonce,
        )?;

        // Spec 3.10
        let wait4 = chan.next_waitpoint();
        chan.send_many(wait4, &(CoefficientCommitment::new(big_c_i), my_phi_proof))?;

        // Spec 4.1 + 4.2 + 4.3
        seen.clear();
        seen.put(me);
        let mut big_c = big_c_i;
        while !seen.full() {
            let (from, (big_c_j, their_phi_proof)): (_, (CoefficientCommitment, _)) =
                chan.recv(wait4).await?;
            if !seen.put(from) {
                continue;
            }
            let big_c_j = big_c_j.value();

            let statement = dlogeq::Statement::<C> {
                public0: &big_e_j_zero[from].value(),
                generator1: &big_f.eval_at_zero()?.value(),
                public1: &big_c_j,
            };

            if !dlogeq::verify(
                &mut transcript.fork(b"dlogeq0", &from.bytes()),
                statement,
                &their_phi_proof,
            )? {
                return Err(ProtocolError::AssertionFailed(format!(
                    "dlogeq proof from {from:?} failed to verify"
                )));
            }

            big_c += big_c_j;
        }
        Ok(ParallelToMultiplicationTaskOutput {
            seen,
            big_e,
            big_f,
            // extend big_l of degree threshold - 2
            big_l: big_l.extend_with_identity()?,
            big_c,
            a_i,
            b_i,
        })
    };

    // Spec 4.4
    let (
        l0,
        ParallelToMultiplicationTaskOutput {
            mut seen,
            big_e,
            big_f,
            mut big_l,
            big_c,
            a_i,
            b_i,
        },
    ) = futures::future::try_join(multiplication_task, parallel_to_multiplication_task).await?;

    // Spec 4.5
    let hat_big_c_i = ProjectivePoint::GENERATOR * l0;

    // Spec 4.6
    let statement = dlog::Statement::<C> {
        public: &hat_big_c_i,
    };
    let witness = dlog::Witness::<C> {
        x: SerializableScalar::<C>(l0),
    };
    let my_phi_proof = dlog::prove(
        &mut rng,
        &mut transcript.fork(b"dlog2", &me.bytes()),
        statement,
        witness,
    )?;

    // Spec 4.7
    let wait5 = chan.next_waitpoint();
    chan.send_many(
        wait5,
        &(CoefficientCommitment::new(hat_big_c_i), my_phi_proof),
    )?;

    // Spec 4.8
    // extend to make the degree threshold - 1
    l = l.extend_with_zero()?;
    l.set_nonzero_constant(l0)?;
    let wait6 = chan.next_waitpoint();
    for p in participants.others(me) {
        let c_i_j = l.eval_at_participant(p)?;
        chan.send_private(wait6, p, &c_i_j)?;
    }
    let mut c_i = l.eval_at_participant(me)?.0;

    // Spec 5.1 + 5.2 + 5.3
    seen.clear();
    seen.put(me);
    let mut hat_big_c = hat_big_c_i;
    while !seen.full() {
        let (from, (their_hat_big_c, their_phi_proof)): (_, (CoefficientCommitment, _)) =
            chan.recv(wait5).await?;
        if !seen.put(from) {
            continue;
        }

        let their_hat_big_c = their_hat_big_c.value();
        let statement = dlog::Statement::<C> {
            public: &their_hat_big_c,
        };
        if !dlog::verify(
            &mut transcript.fork(b"dlog2", &from.bytes()),
            statement,
            &their_phi_proof,
        )? {
            return Err(ProtocolError::AssertionFailed(format!(
                "dlog proof from {from:?} failed to verify"
            )));
        }
        hat_big_c += &their_hat_big_c;
    }

    // Spec 5.3
    big_l.set_non_identity_constant(CoefficientCommitment::new(hat_big_c))?;

    // Spec 5.4
    if big_l.eval_at_zero()?.value() != big_c {
        return Err(ProtocolError::AssertionFailed(
            "final polynomial doesn't match C value".to_owned(),
        ));
    }

    // Spec 5.5 + 5.6
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, c_j_i): (_, SerializableScalar<C>) = chan.recv(wait6).await?;
        if !seen.put(from) {
            continue;
        }
        c_i += c_j_i.0;
    }

    // Spec 5.7
    if big_l.eval_at_participant(me)?.value() != ProjectivePoint::GENERATOR * c_i {
        return Err(ProtocolError::AssertionFailed(
            "received bad private share of c".to_string(),
        ));
    }

    let big_a = big_e.eval_at_zero()?.value().to_affine();
    let big_b = big_f.eval_at_zero()?.value().to_affine();
    let big_c = big_c.to_affine();

    Ok((
        TripleShare {
            a: a_i,
            b: b_i,
            c: c_i,
        },
        TriplePub {
            big_a,
            big_b,
            big_c,
            participants: participants.into(),
            threshold,
        },
    ))
}

async fn do_generation_many<const N: usize>(
    comms: Comms,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
    mut rng: impl CryptoRngCore + Send + 'static,
) -> Result<TripleGenerationOutputMany, ProtocolError> {
    assert!(N > 0);

    let mut chan = comms.shared_channel();
    let mut transcript = create_transcript(&participants, threshold)?;

    let mut my_commitments = vec![];
    let mut my_randomizers = vec![];
    let mut e_v = vec![];
    let mut f_v = vec![];
    let mut l_v = vec![];
    let mut big_e_i_v = vec![];
    let mut big_f_i_v = vec![];
    let mut big_l_i_v = vec![];

    for _ in 0..N {
        // Spec 1.2
        let e = Polynomial::generate_polynomial(None, threshold - 1, &mut rng)?;
        let f = Polynomial::generate_polynomial(None, threshold - 1, &mut rng)?;
        let l = Polynomial::generate_polynomial(None, threshold - 2, &mut rng)?;

        // Spec 1.4
        let big_e_i = e.commit_polynomial()?;
        let big_f_i = f.commit_polynomial()?;
        let big_l_i = l.commit_polynomial()?;

        // Spec 1.5
        let (my_commitment, my_randomizer) = commit(&mut rng, &(&big_e_i, &big_f_i, &big_l_i))
            .map_err(|_| ProtocolError::PointSerialization)?;

        my_commitments.push(my_commitment);
        my_randomizers.push(my_randomizer);
        e_v.push(e);
        f_v.push(f);
        l_v.push(l);
        big_e_i_v.push(big_e_i);
        big_f_i_v.push(big_f_i);
        big_l_i_v.push(big_l_i);
    }

    // Spec 1.6
    let wait0 = chan.next_waitpoint();
    chan.send_many(wait0, &my_commitments)?;

    // Spec 2.1
    let mut all_commitments_vec: Vec<ParticipantMap<Commitment>> = vec![];
    for comi in my_commitments.iter().take(N) {
        let mut m = ParticipantMap::new(&participants);
        m.put(me, *comi);
        all_commitments_vec.push(m);
    }

    while all_commitments_vec
        .iter()
        .any(|all_commitments| !all_commitments.full())
    {
        let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
        for i in 0..N {
            all_commitments_vec[i].put(from, commitments[i]);
        }
    }

    // Spec 2.2
    let mut my_confirmations = vec![];
    for c in all_commitments_vec.iter().take(N) {
        let my_confirmation = hash(c)?;
        my_confirmations.push(my_confirmation);
    }

    // Spec 2.3
    let enc_confirmations =
        rmp_serde::encode::to_vec(&my_confirmations).map_err(|_| ProtocolError::ErrorEncoding)?;
    transcript.message(b"confirmation", &enc_confirmations);

    let my_phi_proof0_nonces: Vec<_> = (0..N).map(|_| <C>::generate_nonce(&mut rng)).collect();
    let my_phi_proof1_nonces: Vec<_> = (0..N).map(|_| <C>::generate_nonce(&mut rng)).collect();
    let my_phi_proof_nonces: Vec<_> = (0..N)
        .map(|_| frost_core::random_nonzero::<C, _>(&mut rng))
        .collect();

    let my_l0_phi_proof_nonces: Vec<_> = (0..N).map(|_| <C>::generate_nonce(&mut rng)).collect();

    // Spec 2.4
    let multiplication_task = {
        let e0_v = e_v
            .iter()
            .map(|e| e.eval_at_zero().map(|x| x.0))
            .collect::<Result<Vec<_>, _>>()?;
        let f0_v = f_v
            .iter()
            .map(|f| f.eval_at_zero().map(|x| x.0))
            .collect::<Result<Vec<_>, _>>()?;
        multiplication_many::<N>(
            comms.clone(),
            my_confirmations.clone(),
            participants.clone(),
            me,
            e0_v,
            f0_v,
        )
    };

    struct ParallelToMultiplicationTaskOutput<'a> {
        seen: ParticipantCounter<'a>,
        big_e_v: Vec<PolynomialCommitment>,
        big_f_v: Vec<PolynomialCommitment>,
        big_l_v: Vec<PolynomialCommitment>,
        big_c_v: Vec<ProjectivePoint>,
        a_i_v: Vec<Scalar>,
        b_i_v: Vec<Scalar>,
    }
    let parallel_to_multiplication_task = async {
        // Spec 2.5
        let wait1 = chan.next_waitpoint();
        chan.send_many(wait1, &my_confirmations)?;

        let mut my_phi_proof0v = vec![];
        let mut my_phi_proof1v = vec![];

        for i in 0..N {
            let big_e_i = &big_e_i_v[i];
            let big_f_i = &big_f_i_v[i];
            let e = &e_v[i];
            let f = &f_v[i];
            // Spec 2.6
            let statement0 = dlog::Statement::<C> {
                public: &big_e_i.eval_at_zero()?.value(),
            };
            let witness0 = dlog::Witness::<C> {
                x: e.eval_at_zero()?,
            };
            let my_phi_proof0 = dlog::prove_with_nonce(
                &mut transcript.fork(b"dlog0", &me.bytes()),
                statement0,
                witness0,
                my_phi_proof0_nonces[i],
            )?;
            let statement1 = dlog::Statement::<C> {
                public: &big_f_i.eval_at_zero()?.value(),
            };
            let witness1 = dlog::Witness::<C> {
                x: f.eval_at_zero()?,
            };
            let my_phi_proof1 = dlog::prove_with_nonce(
                &mut transcript.fork(b"dlog1", &me.bytes()),
                statement1,
                witness1,
                my_phi_proof1_nonces[i],
            )?;
            my_phi_proof0v.push(my_phi_proof0);
            my_phi_proof1v.push(my_phi_proof1);
        }

        // Spec 2.7
        let wait2 = chan.next_waitpoint();
        {
            chan.send_many(
                wait2,
                &(
                    &big_e_i_v,
                    &big_f_i_v,
                    &big_l_i_v,
                    &my_randomizers,
                    &my_phi_proof0v,
                    &my_phi_proof1v,
                ),
            )?;
        }

        // Spec 2.8
        let wait3 = chan.next_waitpoint();
        for p in participants.others(me) {
            let mut a_i_j_v = vec![];
            let mut b_i_j_v = vec![];
            for i in 0..N {
                let e = &e_v[i];
                let f = &f_v[i];
                let a_i_j = e.eval_at_participant(p)?.0;
                let b_i_j = f.eval_at_participant(p)?.0;
                a_i_j_v.push(a_i_j);
                b_i_j_v.push(b_i_j);
            }
            chan.send_private(wait3, p, &(a_i_j_v, b_i_j_v))?;
        }
        let mut a_i_v = vec![];
        let mut b_i_v = vec![];
        for i in 0..N {
            let e = &e_v[i];
            let f = &f_v[i];
            let a_i = e.eval_at_participant(me)?;
            let b_i = f.eval_at_participant(me)?;
            a_i_v.push(a_i.0);
            b_i_v.push(b_i.0);
        }

        // Spec 3.1 + 3.2
        let mut seen = ParticipantCounter::new(&participants);
        seen.put(me);
        while !seen.full() {
            let (from, confirmation): (_, Vec<HashOutput>) = chan.recv(wait1).await?;
            if !seen.put(from) {
                continue;
            }
            if confirmation != my_confirmations {
                return Err(ProtocolError::AssertionFailed(format!(
                    "confirmation from {from:?} did not match expectation"
                )));
            }
        }

        // Spec 3.3 + 3.4, and also part of 3.6, 5.3, for summing up the Es, Fs, and Ls.
        let mut big_e_v = vec![];
        let mut big_f_v = vec![];
        let mut big_l_v = vec![];
        let mut big_e_j_zero_v = vec![];
        for i in 0..N {
            big_e_v.push(big_e_i_v[i].clone());
            big_f_v.push(big_f_i_v[i].clone());
            big_l_v.push(big_l_i_v[i].clone());
            big_e_j_zero_v.push(ParticipantMap::new(&participants));
        }
        seen.clear();
        seen.put(me);
        while !seen.full() {
            #[allow(clippy::type_complexity)]
            let (
                from,
                (
                    their_big_e_v,
                    their_big_f_v,
                    their_big_l_v,
                    their_randomizers,
                    their_phi_proof0_v,
                    their_phi_proof1_v,
                ),
            ): (
                _,
                (
                    Vec<PolynomialCommitment>,
                    Vec<PolynomialCommitment>,
                    Vec<PolynomialCommitment>,
                    Vec<Randomness>,
                    Vec<dlog::Proof<C>>,
                    Vec<dlog::Proof<C>>,
                ),
            ) = chan.recv(wait2).await?;
            if !seen.put(from) {
                continue;
            }

            for i in 0..N {
                let all_commitments = &all_commitments_vec[i];
                let their_big_e = &their_big_e_v[i];
                let their_big_f = &their_big_f_v[i];
                let their_big_l = &their_big_l_v[i];
                let their_randomizer = &their_randomizers[i];
                let their_phi_proof0 = &their_phi_proof0_v[i];
                let their_phi_proof1 = &their_phi_proof1_v[i];
                if their_big_e.degree() != threshold - 1
                    || their_big_f.degree() != threshold - 1
                    // degree is threshold - 2 because the constant element identity is not serializable
                    || their_big_l.degree() != threshold - 2
                {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "polynomial from {from:?} has the wrong length"
                    )));
                }

                if !all_commitments[from]
                    .check(
                        &(&their_big_e, &their_big_f, &their_big_l),
                        their_randomizer,
                    )
                    .map_err(|_| ProtocolError::PointSerialization)?
                {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "commitment from {from:?} did not match revealed F"
                    )));
                }
                let statement0 = dlog::Statement::<C> {
                    public: &their_big_e.eval_at_zero()?.value(),
                };
                if !dlog::verify(
                    &mut transcript.fork(b"dlog0", &from.bytes()),
                    statement0,
                    their_phi_proof0,
                )? {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "dlog proof from {from:?} failed to verify"
                    )));
                }

                let statement1 = dlog::Statement::<C> {
                    public: &their_big_f.eval_at_zero()?.value(),
                };
                if !dlog::verify(
                    &mut transcript.fork(b"dlog1", &from.bytes()),
                    statement1,
                    their_phi_proof1,
                )? {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "dlog proof from {from:?} failed to verify"
                    )));
                }

                big_e_j_zero_v[i].put(from, their_big_e.eval_at_zero()?);

                big_e_v[i] = big_e_v[i].add(their_big_e)?;
                big_f_v[i] = big_f_v[i].add(their_big_f)?;
                big_l_v[i] = big_l_v[i].add(their_big_l)?;
            }
        }

        // Spec 3.5 + 3.6
        seen.clear();
        seen.put(me);
        while !seen.full() {
            #[allow(clippy::type_complexity)]
            let (from, (a_j_i_v, b_j_i_v)): (
                _,
                (Vec<SerializableScalar<C>>, Vec<SerializableScalar<C>>),
            ) = chan.recv(wait3).await?;
            if !seen.put(from) {
                continue;
            }
            for i in 0..N {
                let a_j_i = &a_j_i_v[i];
                let b_j_i = &b_j_i_v[i];
                a_i_v[i] += &a_j_i.0;
                b_i_v[i] += &b_j_i.0;
            }
        }

        let mut big_c_i_points = vec![];
        let mut big_c_i_v = vec![];
        let mut my_phi_proofs = vec![];
        for i in 0..N {
            let big_e = &big_e_v[i];
            let big_f = &big_f_v[i];
            let a_i = &a_i_v[i];
            let b_i = &b_i_v[i];
            let e = &e_v[i];
            // Spec 3.7
            let check1 = big_e.eval_at_participant(me)?.value() != ProjectivePoint::GENERATOR * a_i;
            let check2 = big_f.eval_at_participant(me)?.value() != ProjectivePoint::GENERATOR * b_i;
            if check1 || check2 {
                return Err(ProtocolError::AssertionFailed(
                    "received bad private share".to_string(),
                ));
            }
            // Spec 3.8
            let big_c_i = big_f.eval_at_zero()?.value() * e.eval_at_zero()?.0;
            let big_e_i = &big_e_i_v[i];
            // Spec 3.9
            let statement = dlogeq::Statement::<C> {
                public0: &big_e_i.eval_at_zero()?.value(),
                generator1: &big_f.eval_at_zero()?.value(),
                public1: &big_c_i,
            };
            let witness = dlogeq::Witness {
                x: e.eval_at_zero()?,
            };
            let my_phi_proof = dlogeq::prove_with_nonce(
                &mut transcript.fork(b"dlogeq0", &me.bytes()),
                statement,
                witness,
                my_phi_proof_nonces[i],
            )?;
            big_c_i_points.push(CoefficientCommitment::new(big_c_i));
            big_c_i_v.push(big_c_i);
            my_phi_proofs.push(my_phi_proof);
        }

        // Spec 3.10
        let wait4 = chan.next_waitpoint();
        chan.send_many(wait4, &(&big_c_i_points, &my_phi_proofs))?;

        // Spec 4.1 + 4.2 + 4.3
        seen.clear();
        seen.put(me);
        let mut big_c_v = vec![];
        for big_c_i_v_i in big_c_i_v.iter().take(N) {
            big_c_v.push(*big_c_i_v_i);
        }
        while !seen.full() {
            #[allow(clippy::type_complexity)]
            let (from, (big_c_j_v, their_phi_proofs)): (
                _,
                (Vec<CoefficientCommitment>, Vec<dlogeq::Proof<C>>),
            ) = chan.recv(wait4).await?;
            if !seen.put(from) {
                continue;
            }
            for i in 0..N {
                let big_e_j_zero = &big_e_j_zero_v[i];
                let big_f = &big_f_v[i];

                let big_c_j = big_c_j_v[i].value();
                let their_phi_proof = &their_phi_proofs[i];

                let statement = dlogeq::Statement::<C> {
                    public0: &big_e_j_zero[from].value(),
                    generator1: &big_f.eval_at_zero()?.value(),
                    public1: &big_c_j,
                };

                if !dlogeq::verify(
                    &mut transcript.fork(b"dlogeq0", &from.bytes()),
                    statement,
                    their_phi_proof,
                )? {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "dlogeq proof from {from:?} failed to verify"
                    )));
                }
                big_c_v[i] += big_c_j;
            }
        }
        let big_l_v = big_l_v
            .iter()
            .map(|big_l| big_l.extend_with_identity())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ParallelToMultiplicationTaskOutput {
            seen,
            big_e_v,
            big_f_v,
            big_l_v,
            big_c_v,
            a_i_v,
            b_i_v,
        })
    };

    // Spec 4.4
    let (
        l0_v,
        ParallelToMultiplicationTaskOutput {
            mut seen,
            big_e_v,
            big_f_v,
            mut big_l_v,
            big_c_v,
            a_i_v,
            b_i_v,
        },
    ) = futures::future::try_join(multiplication_task, parallel_to_multiplication_task).await?;

    let mut hat_big_c_i_points = vec![];
    let mut hat_big_c_i_v = vec![];
    let mut my_phi_proofs = vec![];

    for (i, l0) in l0_v.iter().enumerate() {
        // Spec 4.5
        let hat_big_c_i = ProjectivePoint::GENERATOR * l0;

        // Spec 4.6
        let statement = dlog::Statement::<C> {
            public: &hat_big_c_i,
        };
        let witness = dlog::Witness::<C> {
            x: SerializableScalar::<C>(*l0),
        };
        let my_l0_phi_proof = dlog::prove_with_nonce(
            &mut transcript.fork(b"dlog2", &me.bytes()),
            statement,
            witness,
            my_l0_phi_proof_nonces[i],
        )?;
        hat_big_c_i_points.push(CoefficientCommitment::new(hat_big_c_i));
        hat_big_c_i_v.push(hat_big_c_i);
        my_phi_proofs.push(my_l0_phi_proof);
    }

    // Spec 4.8
    let wait5 = chan.next_waitpoint();
    chan.send_many(wait5, &(&hat_big_c_i_points, &my_phi_proofs))?;

    // Spec 4.9
    for i in 0..N {
        let l = &mut l_v[i];
        let l0 = &l0_v[i];
        // extend to make the degree threshold - 1
        *l = l.extend_with_zero()?;
        l.set_nonzero_constant(*l0)?;
    }
    let wait6 = chan.next_waitpoint();
    let mut c_i_v = vec![];
    for p in participants.others(me) {
        let mut c_i_j_v = Vec::new();
        for l in l_v.iter_mut() {
            let c_i_j = l.eval_at_participant(p)?.0;
            c_i_j_v.push(c_i_j);
        }
        chan.send_private(wait6, p, &c_i_j_v)?;
    }
    for l in l_v.iter_mut() {
        let c_i = l.eval_at_participant(me)?;
        c_i_v.push(c_i.0);
    }

    // Spec 5.1 + 5.2 + 5.3
    seen.clear();
    seen.put(me);
    let mut hat_big_c_v = vec![];
    for hat_big_c_i_v_i in hat_big_c_i_v.iter().take(N) {
        hat_big_c_v.push(*hat_big_c_i_v_i);
    }

    while !seen.full() {
        #[allow(clippy::type_complexity)]
        let (from, (their_hat_big_c_i_points, their_phi_proofs)): (
            _,
            (Vec<CoefficientCommitment>, Vec<dlog::Proof<C>>),
        ) = chan.recv(wait5).await?;
        if !seen.put(from) {
            continue;
        }
        for i in 0..N {
            let their_hat_big_c = their_hat_big_c_i_points[i].value();
            let their_phi_proof = &their_phi_proofs[i];

            let statement = dlog::Statement::<C> {
                public: &their_hat_big_c,
            };
            if !dlog::verify(
                &mut transcript.fork(b"dlog2", &from.bytes()),
                statement,
                their_phi_proof,
            )? {
                return Err(ProtocolError::AssertionFailed(format!(
                    "dlog proof from {from:?} failed to verify"
                )));
            }
            hat_big_c_v[i] += &their_hat_big_c;
        }
    }

    for i in 0..N {
        let big_l = &mut big_l_v[i];
        let hat_big_c = &hat_big_c_v[i];
        let big_c = &big_c_v[i];

        // Spec 5.3
        big_l.set_non_identity_constant(CoefficientCommitment::new(*hat_big_c))?;

        // Spec 5.4
        if big_l.eval_at_zero()?.value() != *big_c {
            return Err(ProtocolError::AssertionFailed(
                "final polynomial doesn't match C value".to_owned(),
            ));
        }
    }

    // Spec 5.5 + 5.6
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, c_j_i_v): (_, Vec<SerializableScalar<C>>) = chan.recv(wait6).await?;
        if !seen.put(from) {
            continue;
        }
        for i in 0..N {
            let c_j_i = c_j_i_v[i].0;
            c_i_v[i] += c_j_i;
        }
    }

    let mut ret = vec![];
    // Spec 5.7
    for i in 0..N {
        let big_l = &big_l_v[i];
        let c_i = &c_i_v[i];
        let a_i = &a_i_v[i];
        let b_i = &b_i_v[i];
        let big_e = &big_e_v[i];
        let big_f = &big_f_v[i];
        let big_c = &big_c_v[i];

        if big_l.eval_at_participant(me)?.value() != ProjectivePoint::GENERATOR * c_i {
            return Err(ProtocolError::AssertionFailed(
                "received bad private share of c".to_string(),
            ));
        }
        let big_a = big_e.eval_at_zero()?.value().to_affine();
        let big_b = big_f.eval_at_zero()?.value().to_affine();
        let big_c = (*big_c).into();

        ret.push((
            TripleShare {
                a: *a_i,
                b: *b_i,
                c: *c_i,
            },
            TriplePub {
                big_a,
                big_b,
                big_c,
                participants: participants.clone().into(),
                threshold,
            },
        ))
    }

    Ok(ret)
}

/// Generate a triple through a multi-party protocol.
///
/// This requires a setup phase to have been conducted with these parties
/// previously.
///
/// The resulting triple will be threshold shared, according to the threshold
/// provided to this function.
pub fn generate_triple(
    participants: &[Participant],
    me: Participant,
    threshold: usize,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = TripleGenerationOutput>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    };
    // Spec 1.1
    if threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold,
            max: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    let ctx = Comms::new();
    let fut = do_generation(ctx.clone(), participants, me, threshold, rng);
    Ok(make_protocol(ctx, fut))
}

/// As [`generate_triple`] but for many triples at once
pub fn generate_triple_many<const N: usize>(
    participants: &[Participant],
    me: Participant,
    threshold: usize,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = TripleGenerationOutputMany>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    };
    // Spec 1.1
    if threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold,
            max: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    let ctx = Comms::new();
    let fut = do_generation_many::<N>(ctx.clone(), participants, me, threshold, rng);
    Ok(make_protocol(ctx, fut))
}

#[cfg(test)]
mod test {
    use rand_core::OsRng;

    use crate::{
        ecdsa::{ot_based_ecdsa::triples::generate_triple, ProjectivePoint},
        participants::ParticipantList,
        protocol::{errors::ProtocolError, run_protocol, Participant, Protocol},
        test::generate_participants,
    };

    use super::{generate_triple_many, TripleGenerationOutput, TripleGenerationOutputMany, C};

    #[test]
    fn test_triple_generation() -> Result<(), ProtocolError> {
        let participants = generate_participants(3);
        let threshold = 3;

        #[allow(clippy::type_complexity)]
        let mut protocols: Vec<(
            Participant,
            Box<dyn Protocol<Output = TripleGenerationOutput>>,
        )> = Vec::with_capacity(participants.len());

        for &p in &participants {
            let protocol = generate_triple(&participants, p, threshold, OsRng).unwrap();
            protocols.push((p, Box::new(protocol)));
        }

        let result = run_protocol(protocols)?;

        assert!(result.len() == participants.len());
        assert_eq!(result[0].1 .1, result[1].1 .1);
        assert_eq!(result[1].1 .1, result[2].1 .1);

        let triple_pub = result[2].1 .1.clone();

        let participants = vec![result[0].0, result[1].0, result[2].0];
        let triple_shares = vec![
            result[0].1 .0.clone(),
            result[1].1 .0.clone(),
            result[2].1 .0.clone(),
        ];
        let p_list = ParticipantList::new(&participants).unwrap();

        let a = p_list.lagrange::<C>(participants[0])? * triple_shares[0].a
            + p_list.lagrange::<C>(participants[1])? * triple_shares[1].a
            + p_list.lagrange::<C>(participants[2])? * triple_shares[2].a;
        assert_eq!(ProjectivePoint::GENERATOR * a, triple_pub.big_a);

        let b = p_list.lagrange::<C>(participants[0])? * triple_shares[0].b
            + p_list.lagrange::<C>(participants[1])? * triple_shares[1].b
            + p_list.lagrange::<C>(participants[2])? * triple_shares[2].b;
        assert_eq!(ProjectivePoint::GENERATOR * b, triple_pub.big_b);

        let c = p_list.lagrange::<C>(participants[0])? * triple_shares[0].c
            + p_list.lagrange::<C>(participants[1])? * triple_shares[1].c
            + p_list.lagrange::<C>(participants[2])? * triple_shares[2].c;
        assert_eq!(ProjectivePoint::GENERATOR * c, triple_pub.big_c);

        assert_eq!(a * b, c);

        Ok(())
    }

    #[test]
    fn test_triple_generation_many() -> Result<(), ProtocolError> {
        let participants = generate_participants(3);
        let threshold = 3;

        #[allow(clippy::type_complexity)]
        let mut protocols: Vec<(
            Participant,
            Box<dyn Protocol<Output = TripleGenerationOutputMany>>,
        )> = Vec::with_capacity(participants.len());

        for &p in &participants {
            let protocol = generate_triple_many::<1>(&participants, p, threshold, OsRng).unwrap();
            protocols.push((p, Box::new(protocol)));
        }

        let result = run_protocol(protocols)?;

        assert!(result.len() == participants.len());
        assert_eq!(result[0].1[0].1, result[1].1[0].1);
        assert_eq!(result[1].1[0].1, result[2].1[0].1);

        let triple_pub = result[2].1[0].1.clone();

        let participants = vec![result[0].0, result[1].0, result[2].0];
        let triple_shares = vec![
            result[0].1[0].0.clone(),
            result[1].1[0].0.clone(),
            result[2].1[0].0.clone(),
        ];
        let p_list = ParticipantList::new(&participants).unwrap();

        let a = p_list.lagrange::<C>(participants[0])? * triple_shares[0].a
            + p_list.lagrange::<C>(participants[1])? * triple_shares[1].a
            + p_list.lagrange::<C>(participants[2])? * triple_shares[2].a;
        assert_eq!(ProjectivePoint::GENERATOR * a, triple_pub.big_a);

        let b = p_list.lagrange::<C>(participants[0])? * triple_shares[0].b
            + p_list.lagrange::<C>(participants[1])? * triple_shares[1].b
            + p_list.lagrange::<C>(participants[2])? * triple_shares[2].b;
        assert_eq!(ProjectivePoint::GENERATOR * b, triple_pub.big_b);

        let c = p_list.lagrange::<C>(participants[0])? * triple_shares[0].c
            + p_list.lagrange::<C>(participants[1])? * triple_shares[1].c
            + p_list.lagrange::<C>(participants[2])? * triple_shares[2].c;
        assert_eq!(ProjectivePoint::GENERATOR * c, triple_pub.big_c);

        assert_eq!(a * b, c);

        Ok(())
    }
}
