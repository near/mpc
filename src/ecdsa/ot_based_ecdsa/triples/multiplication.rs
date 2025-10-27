use crate::crypto::constants::{BITS, SECURITY_PARAMETER};
use crate::{
    crypto::hash::{hash, HashOutput},
    ecdsa::{
        ot_based_ecdsa::triples::{
            batch_random_ot::{
                batch_random_ot_receiver_random_helper, batch_random_ot_sender_helper,
            },
            mta::{mta_receiver_random_helper, mta_sender_random_helper},
        },
        Scalar,
    },
    errors::ProtocolError,
    participants::{Participant, ParticipantList},
    protocol::internal::{Comms, PrivateChannel},
};
use rand_core::CryptoRngCore;
use std::sync::Arc;

use super::{
    batch_random_ot::{batch_random_ot_receiver, batch_random_ot_sender},
    mta::{mta_receiver, mta_sender},
    random_ot_extension::{
        random_ot_extension_receiver, random_ot_extension_sender, RandomOtExtensionParams,
    },
};
use std::collections::VecDeque;

pub async fn multiplication_sender(
    chan: PrivateChannel,
    sid: &[u8],
    a_i: &Scalar,
    b_i: &Scalar,
    mut rng: impl CryptoRngCore + Send + 'static,
) -> Result<Scalar, ProtocolError> {
    // First, run a fresh batch random OT ourselves
    let (delta, x) = batch_random_ot_receiver_random_helper(&mut rng);
    let (delta, k) = batch_random_ot_receiver(chan.child(0), delta, x).await?;

    let batch_size = BITS + SECURITY_PARAMETER;
    // Step 1
    let mut res0 = random_ot_extension_sender(
        chan.child(1),
        RandomOtExtensionParams {
            sid,
            batch_size: 2 * batch_size,
        },
        delta,
        &k,
        &mut rng,
    )
    .await?;
    let res1 = res0.split_off(batch_size);

    // Step 2
    let delta0 = mta_sender_random_helper(res0.len(), &mut rng);
    let task0 = mta_sender(chan.child(2), res0, *a_i, delta0);
    let delta1 = mta_sender_random_helper(res1.len(), &mut rng);
    let task1 = mta_sender(chan.child(3), res1, *b_i, delta1);

    // Step 3
    let (gamma0, gamma1) = futures::future::join(task0, task1).await;

    Ok(gamma0? + gamma1?)
}

pub async fn multiplication_receiver(
    chan: PrivateChannel,
    sid: &[u8],
    a_i: &Scalar,
    b_i: &Scalar,
    mut rng: impl CryptoRngCore + Send + 'static,
) -> Result<Scalar, ProtocolError> {
    // First, run a fresh batch random OT ourselves
    let y = batch_random_ot_sender_helper(&mut rng);
    let (k0, k1) = batch_random_ot_sender(chan.child(0), y).await?;

    let batch_size = BITS + SECURITY_PARAMETER;
    // Step 1
    let mut res0 = random_ot_extension_receiver(
        chan.child(1),
        RandomOtExtensionParams {
            sid,
            batch_size: 2 * batch_size,
        },
        &k0,
        &k1,
        &mut rng,
    )
    .await?;
    let res1 = res0.split_off(batch_size);

    // Step 2
    let seed0 = mta_receiver_random_helper(&mut rng);
    let task0 = mta_receiver(chan.child(2), res0, *b_i, seed0);
    let seed1 = mta_receiver_random_helper(&mut rng);
    let task1 = mta_receiver(chan.child(3), res1, *a_i, seed1);

    // Step 3
    let (gamma0, gamma1) = futures::future::join(task0, task1).await;

    Ok(gamma0? + gamma1?)
}

pub async fn multiplication(
    comms: Comms,
    sid: HashOutput,
    participants: ParticipantList,
    me: Participant,
    a_i: Scalar,
    b_i: Scalar,
    rng: impl CryptoRngCore + Send + Copy + 'static,
) -> Result<Scalar, ProtocolError> {
    let mut tasks = Vec::with_capacity(participants.len() - 1);
    for p in participants.others(me) {
        let fut = {
            let chan = comms.private_channel(me, p);
            async move {
                if p < me {
                    multiplication_sender(chan, sid.as_ref(), &a_i, &b_i, rng).await
                } else {
                    multiplication_receiver(chan, sid.as_ref(), &a_i, &b_i, rng).await
                }
            }
        };
        tasks.push(fut);
    }
    let mut out = a_i * b_i;
    for result in futures::future::try_join_all(tasks).await? {
        out += result;
    }
    Ok(out)
}

pub async fn multiplication_many<const N: usize>(
    comms: Comms,
    sid: Vec<HashOutput>,
    participants: ParticipantList,
    me: Participant,
    av_iv: Vec<Scalar>,
    bv_iv: Vec<Scalar>,
    rng: impl CryptoRngCore + Send + Copy + 'static,
) -> Result<Vec<Scalar>, ProtocolError> {
    if N == 0 {
        return Err(ProtocolError::AssertionFailed(
            "N must be greater than 0".to_string(),
        ));
    }
    let sid_arc = Arc::new(sid);
    let av_iv_arc = Arc::new(av_iv);
    let bv_iv_arc = Arc::new(bv_iv);
    let mut tasks = Vec::with_capacity(participants.len() - 1);
    for i in 0..N {
        let order_key_me = hash(&(i, me))?;
        for p in participants.others(me) {
            let sid_arc = sid_arc.clone();
            let av_iv_arc = av_iv_arc.clone();
            let bv_iv_arc = bv_iv_arc.clone();
            let fut = {
                let chan = comms.private_channel(me, p).child(i as u64);
                let order_key_other = hash(&(i, p))?;

                async move {
                    // Use a deterministic but random comparison function to decide who
                    // is the sender and who is the receiver. This allows the batched
                    // multiplication operation to put even networking load between the
                    // participants.
                    if order_key_other.as_ref() < order_key_me.as_ref() {
                        multiplication_sender(
                            chan,
                            sid_arc[i].as_ref(),
                            &av_iv_arc[i],
                            &bv_iv_arc[i],
                            rng,
                        )
                        .await
                    } else {
                        multiplication_receiver(
                            chan,
                            sid_arc[i].as_ref(),
                            &av_iv_arc[i],
                            &bv_iv_arc[i],
                            rng,
                        )
                        .await
                    }
                }
            };
            tasks.push(fut);
        }
    }
    let mut outs = vec![];
    for i in 0..N {
        let av_i = &av_iv_arc.as_slice()[i];
        let bv_i = &bv_iv_arc.as_slice()[i];
        let out = *av_i * *bv_i;
        outs.push(out);
    }

    let mut results = futures::future::try_join_all(tasks)
        .await?
        .into_iter()
        .collect::<VecDeque<_>>();

    for oi in outs.iter_mut().take(N) {
        for _ in participants.others(me) {
            if let Some(result) = results.pop_front() {
                *oi += result;
            } else {
                return Err(ProtocolError::AssertionFailed(
                    "Received less values than expected".to_string(),
                ));
            }
        }
    }

    Ok(outs)
}

#[cfg(test)]
mod test {
    use k256::Scalar;
    use rand_core::OsRng;

    use crate::{
        crypto::hash::hash,
        ecdsa::ot_based_ecdsa::triples::multiplication::{multiplication, multiplication_many},
        participants::ParticipantList,
        protocol::internal::{make_protocol, Comms},
        test::{generate_participants, run_protocol, GenProtocol},
    };

    #[test]
    fn test_multiplication() {
        let participants = generate_participants(3);

        let prep: Vec<_> = participants
            .iter()
            .map(|p| {
                let a_i = Scalar::generate_biased(&mut OsRng);
                let b_i = Scalar::generate_biased(&mut OsRng);
                (p, a_i, b_i)
            })
            .collect();
        let a = prep.iter().fold(Scalar::ZERO, |acc, (_, a_i, _)| acc + a_i);
        let b = prep.iter().fold(Scalar::ZERO, |acc, (_, _, b_i)| acc + b_i);

        let mut protocols: GenProtocol<Scalar> = Vec::with_capacity(prep.len());

        let sid = hash(b"sid").unwrap();

        for (p, a_i, b_i) in prep {
            let ctx = Comms::new();
            let prot = make_protocol(
                ctx.clone(),
                multiplication(
                    ctx,
                    sid,
                    ParticipantList::new(&participants).unwrap(),
                    *p,
                    a_i,
                    b_i,
                    OsRng,
                ),
            );
            protocols.push((*p, Box::new(prot)));
        }

        let result = run_protocol(protocols).unwrap();
        let c = result
            .into_iter()
            .fold(Scalar::ZERO, |acc, (_, c_i)| acc + c_i);

        assert_eq!(a * b, c);
    }

    #[test]
    fn test_multiplication_many() {
        const N: usize = 4;
        let participants = generate_participants(3);

        let prep: Vec<_> = participants
            .iter()
            .map(|p| {
                let a_iv = (0..N)
                    .map(|_| Scalar::generate_biased(&mut OsRng))
                    .collect::<Vec<_>>();
                let b_iv = (0..N)
                    .map(|_| Scalar::generate_biased(&mut OsRng))
                    .collect::<Vec<_>>();
                (p, a_iv, b_iv)
            })
            .collect();

        let a_v = prep
            .iter()
            .fold(vec![Scalar::ZERO; N], |acc, (_, a_iv, _)| {
                acc.iter()
                    .zip(a_iv.iter())
                    .map(|(acc_i, a_i)| acc_i + a_i)
                    .collect()
            });
        let b_v = prep
            .iter()
            .fold(vec![Scalar::ZERO; N], |acc, (_, _, b_iv)| {
                acc.iter()
                    .zip(b_iv.iter())
                    .map(|(acc_i, b_i)| acc_i + b_i)
                    .collect()
            });

        let mut protocols: GenProtocol<Vec<Scalar>> = Vec::with_capacity(prep.len());

        let sids = (0..N)
            .map(|i| hash(&format!("sid{i}")))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        for (p, a_iv, b_iv) in prep {
            let ctx = Comms::new();

            let prot = make_protocol(
                ctx.clone(),
                multiplication_many::<N>(
                    ctx,
                    sids.clone(),
                    ParticipantList::new(&participants).unwrap(),
                    *p,
                    a_iv,
                    b_iv,
                    OsRng,
                ),
            );
            protocols.push((*p, Box::new(prot)));
        }

        let result = run_protocol(protocols).unwrap();
        let c_v: Vec<_> = result
            .into_iter()
            .fold(vec![Scalar::ZERO; N], |acc, (_, c_iv)| {
                acc.iter()
                    .zip(c_iv.iter())
                    .map(|(acc_i, c_i)| acc_i + c_i)
                    .collect()
            });

        for i in 0..N {
            assert_eq!(a_v[i] * b_v[i], c_v[i]);
        }
    }
}
