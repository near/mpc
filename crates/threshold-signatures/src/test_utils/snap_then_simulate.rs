use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::cmp::Reverse;
use std::time::Instant;

use crate::participants::Participant;
use crate::protocol::{Action, MessageData, Protocol};

use super::simulator_bench::{LatencyModel, SimulationMetrics};

// ---------------------------------------------------------------------------
// Trace types
// ---------------------------------------------------------------------------

/// Action recorded during a drain (Send/Return only, not Wait).
#[derive(Debug, Clone)]
pub enum TracedAction {
    SendMany {
        data: MessageData,
        recipients: Vec<Participant>,
    },
    SendPrivate {
        to: Participant,
        data: MessageData,
    },
    Return,
}

/// The message that triggered a `drain_poke` invocation.
#[derive(Debug, Clone)]
pub struct TriggerMessage {
    pub from: Participant,
    pub data: MessageData,
}

/// One `drain_poke` invocation recorded during the snap phase.
#[derive(Debug, Clone)]
pub struct DrainEvent {
    pub participant: Participant,
    pub participant_idx: usize,
    pub trigger_message: Option<TriggerMessage>,
    pub actions: Vec<TracedAction>,
}

/// Complete execution trace from Phase 1.
#[derive(Debug, Clone)]
pub struct ExecutionTrace {
    pub participants: Vec<Participant>,
    pub drain_events: Vec<DrainEvent>,
    pub total_bytes_sent: u64,
    pub total_messages_sent: u64,
    pub bytes_sent_per_participant: HashMap<Participant, u64>,
}

/// Per-poke timing within a drain.
#[derive(Debug, Clone, Copy)]
pub struct PokeTiming {
    pub action_idx: usize,
    pub elapsed_ns: u64,
}

/// Per-participant timing data from Phase 2.
#[derive(Debug, Clone)]
pub struct ParticipantTimings {
    /// `(global_drain_event_index, per-poke timings for that drain)`
    pub drains: Vec<(usize, Vec<PokeTiming>)>,
}

/// Collected timings for all participants.
pub type AllTimings = HashMap<Participant, ParticipantTimings>;

// ---------------------------------------------------------------------------
// Private: priority-queue message for Phase 1.
// Same field order and derived Ord as PendingMessage in simulator_bench.rs
// so that the priority-queue ordering is identical.
// ---------------------------------------------------------------------------

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct SnapMessage {
    arrival_time: u64,
    from: Participant,
    to: Participant,
    data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Phase 1 — Record Trace
// ---------------------------------------------------------------------------

/// Run all protocols through a zero-latency simulation, recording the
/// execution trace without timing any computation.
///
/// Returns the protocol outputs and the trace.
pub fn record_trace<T>(
    mut protocols: Vec<(Participant, impl Protocol<Output = T>)>,
) -> (Vec<(Participant, T)>, ExecutionTrace) {
    let indices: HashMap<Participant, usize> = protocols
        .iter()
        .enumerate()
        .map(|(i, (p, _))| (*p, i))
        .collect();

    let size = protocols.len();
    let all_participants: Vec<Participant> = protocols.iter().map(|(p, _)| *p).collect();

    let mut finished = vec![false; size];
    let mut queue: BinaryHeap<Reverse<SnapMessage>> = BinaryHeap::new();
    let mut drain_events: Vec<DrainEvent> = Vec::new();
    let mut outputs: Vec<(Participant, T)> = Vec::with_capacity(size);

    let mut total_bytes_sent: u64 = 0;
    let mut total_messages_sent: u64 = 0;
    let mut bytes_sent_per_participant: HashMap<Participant, u64> =
        all_participants.iter().map(|p| (*p, 0)).collect();

    // Initial drains
    for i in 0..size {
        let event = record_drain_poke(
            i,
            &mut protocols,
            &mut finished,
            &all_participants,
            &mut queue,
            &mut outputs,
            &mut total_bytes_sent,
            &mut total_messages_sent,
            &mut bytes_sent_per_participant,
            None,
        );
        drain_events.push(event);
    }

    // Process message queue
    while let Some(Reverse(msg)) = queue.pop() {
        let receiver_idx = *indices
            .get(&msg.to)
            .unwrap_or_else(|| panic!("Unknown participant {:?}", msg.to));

        if finished[receiver_idx] {
            continue;
        }

        protocols[receiver_idx]
            .1
            .message(msg.from, msg.data.clone())
            .expect("Message delivery failed");

        let trigger = TriggerMessage {
            from: msg.from,
            data: msg.data,
        };

        let event = record_drain_poke(
            receiver_idx,
            &mut protocols,
            &mut finished,
            &all_participants,
            &mut queue,
            &mut outputs,
            &mut total_bytes_sent,
            &mut total_messages_sent,
            &mut bytes_sent_per_participant,
            Some(trigger),
        );
        drain_events.push(event);
    }

    outputs.sort_by_key(|(p, _)| *p);

    let trace = ExecutionTrace {
        participants: all_participants,
        drain_events,
        total_bytes_sent,
        total_messages_sent,
        bytes_sent_per_participant,
    };

    (outputs, trace)
}

#[allow(clippy::too_many_arguments)]
fn record_drain_poke<T>(
    idx: usize,
    protocols: &mut [(Participant, impl Protocol<Output = T>)],
    finished: &mut [bool],
    all_participants: &[Participant],
    queue: &mut BinaryHeap<Reverse<SnapMessage>>,
    outputs: &mut Vec<(Participant, T)>,
    total_bytes_sent: &mut u64,
    total_messages_sent: &mut u64,
    bytes_sent_per_participant: &mut HashMap<Participant, u64>,
    trigger_message: Option<TriggerMessage>,
) -> DrainEvent {
    let sender = protocols[idx].0;
    let mut actions = Vec::new();

    if !finished[idx] {
        loop {
            let action = protocols[idx].1.poke().expect("Protocol poke failed");

            match action {
                Action::Wait => break,
                Action::SendMany(data) => {
                    let mut recipients = Vec::with_capacity(all_participants.len() - 1);
                    for &recipient in all_participants {
                        if recipient == sender {
                            continue;
                        }
                        let data_len = data.len() as u64;
                        *total_bytes_sent += data_len;
                        *total_messages_sent += 1;
                        *bytes_sent_per_participant.entry(sender).or_insert(0) += data_len;

                        queue.push(Reverse(SnapMessage {
                            arrival_time: 0,
                            from: sender,
                            to: recipient,
                            data: data.clone(),
                        }));
                        recipients.push(recipient);
                    }
                    actions.push(TracedAction::SendMany { data, recipients });
                }
                Action::SendPrivate(recipient, data) => {
                    let data_len = data.len() as u64;
                    *total_bytes_sent += data_len;
                    *total_messages_sent += 1;
                    *bytes_sent_per_participant.entry(sender).or_insert(0) += data_len;

                    queue.push(Reverse(SnapMessage {
                        arrival_time: 0,
                        from: sender,
                        to: recipient,
                        data: data.clone(),
                    }));
                    actions.push(TracedAction::SendPrivate {
                        to: recipient,
                        data,
                    });
                }
                Action::Return(result) => {
                    finished[idx] = true;
                    outputs.push((sender, result));
                    actions.push(TracedAction::Return);
                    break;
                }
            }
        }
    }

    DrainEvent {
        participant: sender,
        participant_idx: idx,
        trigger_message,
        actions,
    }
}

// ---------------------------------------------------------------------------
// Phase 2 — Cache-Hot Per-Participant Timing
// ---------------------------------------------------------------------------

/// For each participant independently, replay their message sequence from the
/// trace and time each productive `poke()` call with [`Instant::now()`].
///
/// Wait pokes are NOT timed, matching `simulator_bench.rs` behaviour.
/// Each participant is processed sequentially so its working set stays
/// cache-hot throughout.
pub fn time_all_participants<T>(
    mut protocols: Vec<(Participant, impl Protocol<Output = T>)>,
    trace: &ExecutionTrace,
) -> AllTimings {
    let indices: HashMap<Participant, usize> = protocols
        .iter()
        .enumerate()
        .map(|(i, (p, _))| (*p, i))
        .collect();

    // Build per-participant drain lists: (global_drain_index, &DrainEvent)
    let mut per_participant: HashMap<Participant, Vec<(usize, &DrainEvent)>> = HashMap::new();
    for (global_idx, event) in trace.drain_events.iter().enumerate() {
        per_participant
            .entry(event.participant)
            .or_default()
            .push((global_idx, event));
    }

    // Process each participant fully before moving to the next (cache-hot).
    let mut all_timings = AllTimings::new();

    for &participant in &trace.participants {
        let Some(drains) = per_participant.get(&participant) else {
            continue;
        };
        let protocol_idx = indices[&participant];
        let protocol = &mut protocols[protocol_idx].1;

        let mut participant_drains: Vec<(usize, Vec<PokeTiming>)> =
            Vec::with_capacity(drains.len());

        for &(global_idx, event) in drains {
            // Deliver trigger message if present
            if let Some(trigger) = &event.trigger_message {
                protocol
                    .message(trigger.from, trigger.data.clone())
                    .expect("Message delivery failed during timing replay");
            }

            // Time each poke individually
            let poke_timings = time_drain_poke(protocol, &event.actions);
            participant_drains.push((global_idx, poke_timings));
        }

        all_timings.insert(
            participant,
            ParticipantTimings {
                drains: participant_drains,
            },
        );
    }

    all_timings
}

/// Time one `drain_poke` invocation, returning per-poke timings for productive
/// actions only (Send*/Return). Wait pokes terminate the loop without timing.
fn time_drain_poke<T>(
    protocol: &mut impl Protocol<Output = T>,
    expected_actions: &[TracedAction],
) -> Vec<PokeTiming> {
    let mut timings = Vec::with_capacity(expected_actions.len());
    let mut action_idx: usize = 0;

    loop {
        let start = Instant::now();
        let action = protocol.poke().expect("Protocol poke failed during timing");
        let elapsed_ns = start.elapsed().as_nanos() as u64;

        match action {
            Action::Wait => break,
            Action::SendMany(_) | Action::SendPrivate(_, _) => {
                debug_assert!(
                    action_idx < expected_actions.len(),
                    "More productive pokes than expected actions in trace"
                );
                timings.push(PokeTiming {
                    action_idx,
                    elapsed_ns,
                });
                action_idx += 1;
            }
            Action::Return(_) => {
                debug_assert!(
                    action_idx < expected_actions.len(),
                    "Return at unexpected position"
                );
                timings.push(PokeTiming {
                    action_idx,
                    elapsed_ns,
                });
                action_idx += 1;
                break;
            }
        }
    }

    debug_assert_eq!(
        action_idx,
        expected_actions.len(),
        "Replay produced different number of actions than trace"
    );

    timings
}

// ---------------------------------------------------------------------------
// Phase 3 — Virtual Timeline Reconstruction
// ---------------------------------------------------------------------------

/// Reconstruct a virtual timeline from the execution trace and per-participant
/// timings, producing the same [`SimulationMetrics`] as `run_simulation`.
///
/// The trace's global event order is replayed. For each drain:
///   1. If a trigger message exists, its virtual arrival time is looked up
///      and the participant's clock is advanced: `clock = max(clock, arrival)`.
///   2. For each productive poke, the clock advances by the measured time.
///   3. For each Send action, `arrival_time = clock + latency` is enqueued
///      for the recipient.
#[allow(clippy::cast_possible_truncation)]
pub fn reconstruct_timeline(
    trace: &ExecutionTrace,
    timings: &AllTimings,
    latency_model: &LatencyModel,
) -> SimulationMetrics {
    let all_participants = &trace.participants;

    let mut clocks: HashMap<Participant, u64> =
        all_participants.iter().map(|p| (*p, 0u64)).collect();
    let mut finished: HashMap<Participant, bool> =
        all_participants.iter().map(|p| (*p, false)).collect();

    // Per-(sender, receiver) FIFO queue of virtual arrival times.
    let mut arrival_queues: HashMap<(Participant, Participant), VecDeque<u64>> = HashMap::new();

    // Build a lookup: global_drain_index -> &[PokeTiming]
    let mut timing_lookup: HashMap<usize, &[PokeTiming]> = HashMap::new();
    for pt in timings.values() {
        for (global_idx, poke_timings) in &pt.drains {
            timing_lookup.insert(*global_idx, poke_timings.as_slice());
        }
    }

    let mut total_bytes_sent: u64 = 0;
    let mut total_bytes_received: u64 = 0;
    let mut total_messages_sent: u64 = 0;
    let mut total_messages_received: u64 = 0;
    let mut bytes_sent_per_participant: HashMap<Participant, u64> =
        all_participants.iter().map(|p| (*p, 0)).collect();
    let mut bytes_received_per_participant: HashMap<Participant, u64> =
        all_participants.iter().map(|p| (*p, 0)).collect();

    for (global_idx, event) in trace.drain_events.iter().enumerate() {
        let p = event.participant;
        if finished[&p] {
            continue;
        }

        // Step 1: apply trigger message virtual arrival time
        if let Some(trigger) = &event.trigger_message {
            let queue = arrival_queues
                .entry((trigger.from, p))
                .or_default();
            if let Some(arrival_time) = queue.pop_front() {
                let clock = clocks.get_mut(&p).expect("participant exists");
                if arrival_time > *clock {
                    *clock = arrival_time;
                }
            }

            let data_len = trigger.data.len() as u64;
            total_bytes_received += data_len;
            total_messages_received += 1;
            *bytes_received_per_participant.entry(p).or_insert(0) += data_len;
        }

        // Step 2: apply per-poke timings and compute send arrival times
        let poke_timings = timing_lookup
            .get(&global_idx)
            .copied()
            .unwrap_or_default();

        for pt in poke_timings {
            let clock = clocks.get_mut(&p).expect("participant exists");
            *clock += pt.elapsed_ns;

            let action = &event.actions[pt.action_idx];
            match action {
                TracedAction::SendMany { data, recipients } => {
                    for &recipient in recipients {
                        let latency = latency_model.sample();
                        let arrival = *clock + latency;
                        arrival_queues
                            .entry((p, recipient))
                            .or_default()
                            .push_back(arrival);

                        let data_len = data.len() as u64;
                        total_bytes_sent += data_len;
                        total_messages_sent += 1;
                        *bytes_sent_per_participant.entry(p).or_insert(0) += data_len;
                    }
                }
                TracedAction::SendPrivate { to, data } => {
                    let latency = latency_model.sample();
                    let arrival = *clocks.get(&p).expect("participant exists") + latency;
                    arrival_queues
                        .entry((p, *to))
                        .or_default()
                        .push_back(arrival);

                    let data_len = data.len() as u64;
                    total_bytes_sent += data_len;
                    total_messages_sent += 1;
                    *bytes_sent_per_participant.entry(p).or_insert(0) += data_len;
                }
                TracedAction::Return => {
                    finished.insert(p, true);
                }
            }
        }
    }

    let virtual_time_elapsed = clocks.values().copied().max().unwrap_or(0);

    SimulationMetrics {
        total_bytes_sent,
        total_bytes_received,
        total_messages_sent,
        total_messages_received,
        bytes_sent_per_participant,
        bytes_received_per_participant,
        virtual_time_elapsed,
    }
}

// ---------------------------------------------------------------------------
// Combined Entry Point
// ---------------------------------------------------------------------------

/// Three-phase snap-then-simulate benchmarking.
///
/// 1. **Snap** — run all protocols to completion, recording the execution
///    trace (message deliveries, poke actions) without timing.
/// 2. **Time** — for each participant independently (cache-hot), replay its
///    message sequence and time each productive `poke()`.
/// 3. **Reconstruct** — build a virtual timeline from the trace + timings +
///    latency model, producing [`SimulationMetrics`].
///
/// `make_protocols` is called **twice**: once for the snap phase and once for
/// the timing phase. It must produce deterministic protocol instances (e.g.
/// seeded with the same [`MockCryptoRng`]).
pub fn snap_then_simulate<T>(
    make_protocols: impl Fn() -> Vec<(Participant, Box<dyn Protocol<Output = T>>)>,
    latency_model: &LatencyModel,
) -> (Vec<(Participant, T)>, SimulationMetrics) {
    // Phase 1: record trace
    let (outputs, trace) = record_trace(make_protocols());

    // Phase 2: cache-hot timing
    let timings = time_all_participants(make_protocols(), &trace);

    // Phase 3: reconstruct virtual timeline
    let metrics = reconstruct_timeline(&trace, &timings, latency_model);

    (outputs, metrics)
}
