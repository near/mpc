use crate::errors::ProtocolError;
use crate::participants::Participant;
use crate::protocol::{Action, Protocol};
use crate::test_utils::{protocol_snapshot, Simulator};
use std::collections::HashMap;

use crate::participants::ParticipantList;
use crate::protocol::internal::{make_protocol, Comms};
use crate::test_utils::{GenProtocol, MockCryptoRng};
use rand::RngCore;
use rand_core::SeedableRng;

// +++++++++++++++++ Any Protocol +++++++++++++++++ //
/// Run a protocol to completion, synchronously.
///
/// This works by executing each participant in order.
///
/// The reason this function exists is as a convenient testing utility.
/// In practice each protocol participant is likely running on a different machine,
/// and so orchestrating the protocol would happen differently.
pub fn run_protocol<T>(
    ps: Vec<(Participant, Box<dyn Protocol<Output = T>>)>,
) -> Result<Vec<(Participant, T)>, ProtocolError> {
    run_protocol_common(ps, false).map(|(v, _)| v)
}

/// Like [`run_protocol()`], except that it snapshots all the communication.
pub fn run_protocol_and_take_snapshots<T>(
    ps: Vec<(Participant, Box<dyn Protocol<Output = T>>)>,
) -> Result<(Vec<(Participant, T)>, protocol_snapshot), ProtocolError> {
    run_protocol_common(ps, true).map(|(v, snapshot)| (v, snapshot.unwrap()))
}

/// Runs one real participant and one simulation representing the rest of participants
/// The simulation has an internal storage of what to send to the real participant
pub fn run_simulated_protocol<T>(
    real_participant: Participant,
    mut real_prot: Box<dyn Protocol<Output = T>>,
    simulator: Simulator,
) -> Result<T, ProtocolError> {
    if simulator.real_participant() != real_participant {
        return Err(ProtocolError::AssertionFailed(
            "The given real participant does not match the simulator's internal real participant"
                .to_string(),
        ));
    }

    // fill the real_participant's buffer with the recorded messages
    for (from, data) in simulator.get_recorded_messages() {
        real_prot.message(from, data)?;
    }

    let mut out = None;
    while out.is_none() {
        let action = real_prot.poke()?;
        if let Action::Return(output) = action {
            out = Some(output);
        }
    }
    out.ok_or_else(|| ProtocolError::Other("out is None".to_string()))
}

/// Like [`run_protocol()`], except for just two parties.
/// Currently only used for Cait-Sith
///
/// This is more useful for testing two party protocols with asymmetric results,
/// since the return types for the two protocols can be different.
pub fn run_two_party_protocol<T0: std::fmt::Debug, T1: std::fmt::Debug>(
    p0: Participant,
    p1: Participant,
    prot0: &mut dyn Protocol<Output = T0>,
    prot1: &mut dyn Protocol<Output = T1>,
) -> Result<(T0, T1), ProtocolError> {
    let mut active0 = true;

    let mut out0 = None;
    let mut out1 = None;

    while out0.is_none() || out1.is_none() {
        if active0 {
            let action = prot0.poke()?;
            match action {
                Action::Wait => active0 = false,
                Action::SendMany(m) => {
                    prot1.message(p0, m)?;
                }
                Action::SendPrivate(to, m) if to == p1 => {
                    prot1.message(p0, m)?;
                }
                Action::Return(out) => out0 = Some(out),
                // Ignore other actions, which means sending private messages to other people.
                Action::SendPrivate(..) => {}
            }
        } else {
            let action = prot1.poke()?;
            match action {
                Action::Wait => active0 = true,
                Action::SendMany(m) => {
                    prot0.message(p1, m)?;
                }
                Action::SendPrivate(to, m) if to == p0 => {
                    prot0.message(p1, m)?;
                }
                Action::Return(out) => out1 = Some(out),
                // Ignore other actions, which means sending private messages to other people.
                Action::SendPrivate(..) => {}
            }
        }
    }

    Ok((
        out0.ok_or_else(|| ProtocolError::Other("out0 is None".to_string()))?,
        out1.ok_or_else(|| ProtocolError::Other("out1 is None".to_string()))?,
    ))
}

#[allow(clippy::type_complexity)]
fn run_protocol_common<T>(
    mut ps: Vec<(Participant, Box<dyn Protocol<Output = T>>)>,
    take_snapshots: bool,
) -> Result<(Vec<(Participant, T)>, Option<protocol_snapshot>), ProtocolError> {
    let indices: HashMap<Participant, usize> =
        ps.iter().enumerate().map(|(i, (p, _))| (*p, i)).collect();

    let mut protocol_snapshots = {
        if take_snapshots {
            let participants: Vec<_> = ps.iter().map(|(p, _)| *p).collect();
            Some(protocol_snapshot::new_empty(participants))
        } else {
            None
        }
    };

    let size = ps.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            while {
                let action = ps[i].1.poke()?;
                match action {
                    Action::Wait => false,
                    Action::SendMany(m) => {
                        for j in 0..size {
                            if i == j {
                                continue;
                            }
                            let from = ps[i].0;
                            let to = ps[j].0;

                            if let Some(protocol_snapshots) = &mut protocol_snapshots {
                                // snapshot the message
                                protocol_snapshots
                                    .push_message(to, from, m.clone())
                                    .ok_or_else(|| {
                                        ProtocolError::Other(
                                            "Participant not found in snapshot".to_string(),
                                        )
                                    })?;
                            }

                            ps[j].1.message(from, m.clone())?;
                        }
                        true
                    }
                    Action::SendPrivate(to, m) => {
                        let from = ps[i].0;
                        if let Some(protocol_snapshots) = &mut protocol_snapshots {
                            // snapshot the message
                            protocol_snapshots
                                .push_message(to, from, m.clone())
                                .ok_or_else(|| {
                                    ProtocolError::Other(
                                        "Participant not found in snapshot".to_string(),
                                    )
                                })?;
                        }
                        ps[indices[&to]].1.message(from, m)?;
                        true
                    }
                    Action::Return(r) => {
                        out.push((ps[i].0, r));
                        false
                    }
                }
            } {}
        }
    }
    out.sort_by_key(|(p, _)| *p);
    Ok((out, protocol_snapshots))
}

/// Build protocols with unbounded `Comms` for buffer-capacity testing.
///
/// For each participant, creates a `Comms::with_buffer_capacity(usize::MAX)`,
/// a `ParticipantList`, and a per-participant RNG, then calls `make_future`
/// to obtain the protocol future. Returns the ready-to-run protocols and
/// a vec of `(Participant, Comms)` references for later assertions.
pub fn build_buffer_test<T: Send + 'static, Fut, F>(
    participants: &[Participant],
    rng: &mut MockCryptoRng,
    mut make_future: F,
) -> (GenProtocol<T>, Vec<(Participant, Comms)>)
where
    Fut: std::future::Future<Output = Result<T, ProtocolError>> + Send + 'static,
    F: FnMut(&Comms, ParticipantList, Participant, MockCryptoRng) -> Fut,
{
    let mut comms_refs = Vec::new();
    let mut protocols: GenProtocol<T> = Vec::new();

    for &p in participants {
        let comms = Comms::with_buffer_capacity(usize::MAX);
        let participant_list = ParticipantList::new(participants).unwrap();
        let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
        let fut = make_future(&comms, participant_list, p, rng_p);
        comms_refs.push((p, comms.clone()));
        let prot = make_protocol(comms, fut);
        protocols.push((p, Box::new(prot)));
    }

    (protocols, comms_refs)
}

/// Run protocols to completion and assert that each participant's
/// `Comms::buffer_len()` equals the value returned by `expected(participant)`.
pub fn run_and_assert_buffer_entries<T>(
    protocols: GenProtocol<T>,
    comms_refs: &[(Participant, Comms)],
    expected: impl Fn(Participant) -> usize,
) {
    let _ = run_protocol(protocols).unwrap();

    for (p, comms) in comms_refs {
        let exp = expected(*p);
        assert_eq!(
            comms.buffer_len(),
            exp,
            "Unexpected buffer entries for participant {p:?}"
        );
    }
}

/// Returns a closure that maps a participant to its expected buffer size
/// based on whether it is the coordinator or not.
pub fn expected_buffer_by_role(
    coordinator: Participant,
    coordinator_entries: usize,
    participant_entries: usize,
) -> impl Fn(Participant) -> usize {
    move |p| {
        if p == coordinator {
            coordinator_entries
        } else {
            participant_entries
        }
    }
}

/// One-call convenience: build protocols with unbounded buffers, run them,
/// and assert exact buffer entry counts.
pub fn assert_buffer_capacity<T: Send + 'static, Fut, F>(
    participants: &[Participant],
    rng: &mut MockCryptoRng,
    make_future: F,
    expected: impl Fn(Participant) -> usize,
) where
    Fut: std::future::Future<Output = Result<T, ProtocolError>> + Send + 'static,
    F: FnMut(&Comms, ParticipantList, Participant, MockCryptoRng) -> Fut,
{
    let (protocols, comms_refs) = build_buffer_test(participants, rng, make_future);
    run_and_assert_buffer_entries(protocols, &comms_refs, expected);
}
