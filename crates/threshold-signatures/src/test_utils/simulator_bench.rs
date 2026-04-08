use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::env;
use std::time::{Duration, Instant};

use crate::participants::Participant;
use crate::protocol::{Action, Protocol};

// Discrete-event protocol simulator.
//
// All participants share a single global timeline starting at t=0.
// Each participant tracks its position on this timeline via a clock (in ns).
// The clock advances in two ways:
//   - Computation: wall-clock time of each poke() call is added.
//   - Waiting: on message receipt, clock = max(clock, arrival_time).
// Messages are delivered via a priority queue ordered by arrival_time,
// where arrival_time = sender_clock + latency at the time of sending.

/// Model for generating per-message network latency.
/// Extensible to statistical distributions (normal, log-normal, etc.).
pub enum LatencyModel {
    /// Fixed one-way latency in nanoseconds.
    Fixed(u64),
}

impl LatencyModel {
    pub fn sample(&self) -> u64 {
        match self {
            Self::Fixed(ns) => *ns,
        }
    }
}

struct PendingMessage {
    arrival_time: u64,
    from: Participant,
    to: Participant,
    data: Vec<u8>,
}

impl PartialEq for PendingMessage {
    fn eq(&self, other: &Self) -> bool {
        self.arrival_time == other.arrival_time && self.from == other.from && self.to == other.to
    }
}

impl Eq for PendingMessage {}

impl PartialOrd for PendingMessage {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PendingMessage {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.arrival_time
            .cmp(&other.arrival_time)
            .then_with(|| self.from.cmp(&other.from))
            .then_with(|| self.to.cmp(&other.to))
    }
}

struct ParticipantState {
    clock: u64,
    finished: bool,
}

#[derive(Debug, Clone)]
pub struct SimulationMetrics {
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub bytes_sent_per_participant: HashMap<Participant, u64>,
    pub bytes_received_per_participant: HashMap<Participant, u64>,
    pub wall_clock_elapsed: Duration,
    /// max(all participant clocks) in ns, includes network latency + computation time.
    pub virtual_time_elapsed: u64,
}

impl SimulationMetrics {
    #[allow(clippy::cast_precision_loss)]
    pub fn virtual_time_ms(&self) -> f64 {
        self.virtual_time_elapsed as f64 / 1_000_000.0
    }

    /// Assert that sent counts match between runs. Received counts are not
    /// checked because protocols using threshold-based echo-broadcast may
    /// consume a variable number of messages depending on delivery order.
    pub fn assert_deterministic(&self, other: &Self, label: &str) {
        assert_eq!(
            self.total_messages_sent, other.total_messages_sent,
            "{label}: total_messages_sent changed"
        );
        assert_eq!(
            self.total_bytes_sent, other.total_bytes_sent,
            "{label}: total_bytes_sent changed"
        );
    }
}

#[allow(clippy::cast_precision_loss)]
pub fn bench_simulation(name: &str, run: &dyn Fn() -> SimulationMetrics, samples: usize) {
    let mut times = Vec::with_capacity(samples);
    let mut first_metrics: Option<SimulationMetrics> = None;
    for _ in 0..samples {
        let metrics = run();
        times.push(metrics.virtual_time_ms());
        if let Some(first) = &first_metrics {
            metrics.assert_deterministic(first, name);
        } else {
            first_metrics = Some(metrics);
        }
    }
    let first_metrics = first_metrics.expect("samples > 0");

    let avg = times.iter().sum::<f64>() / samples as f64;
    let min = times.iter().copied().reduce(f64::min).expect("samples > 0");
    let max = times.iter().copied().reduce(f64::max).expect("samples > 0");

    println!("=== {name} ===");
    print!("{first_metrics}");
    println!("Virtual time: avg {avg:.3} ms, min {min:.3} ms, max {max:.3} ms");
}

pub struct BenchConfig {
    pub num_participants: usize,
    pub threshold: usize,
    pub latency: LatencyModel,
    pub samples: usize,
}

impl BenchConfig {
    pub fn from_env() -> Self {
        let num_participants = env::var("NUM_PARTICIPANTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(7);
        let threshold = env::var("THRESHOLD")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or((num_participants / 2) + 1);
        let latency_ms: u64 = env::var("LATENCY_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);
        let samples = env::var("SAMPLE_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(15);
        Self {
            num_participants,
            threshold,
            latency: LatencyModel::Fixed(latency_ms * 1_000_000),
            samples,
        }
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn latency_ms(&self) -> f64 {
        match self.latency {
            LatencyModel::Fixed(ns) => ns as f64 / 1_000_000.0,
        }
    }

    pub fn warmup(&self, run: &dyn Fn()) {
        let warmup = Duration::from_secs(WARMUP_SECS);
        eprint!("Warming up for {warmup:?}...");
        let start = Instant::now();
        while start.elapsed() < warmup {
            run();
        }
        eprintln!(" done\n");
    }
}

const WARMUP_SECS: u64 = 3;

impl std::fmt::Display for SimulationMetrics {
    #[allow(clippy::cast_precision_loss)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.bytes_sent_per_participant.len().max(1) as f64;
        writeln!(
            f,
            "Total messages: {} sent, {} received",
            self.total_messages_sent, self.total_messages_received
        )?;
        writeln!(
            f,
            "Avg messages/participant: {:.0} sent, {:.0} received",
            self.total_messages_sent as f64 / n,
            self.total_messages_received as f64 / n
        )?;
        writeln!(
            f,
            "Total bytes: {} sent, {} received",
            self.total_bytes_sent, self.total_bytes_received
        )?;
        writeln!(
            f,
            "Avg bytes/participant: {:.0} sent, {:.0} received",
            self.total_bytes_sent as f64 / n,
            self.total_bytes_received as f64 / n
        )?;
        Ok(())
    }
}

pub fn run_simulation<T>(
    mut protocols: Vec<(Participant, Box<dyn Protocol<Output = T>>)>,
    latency_model: &LatencyModel,
) -> (Vec<(Participant, T)>, SimulationMetrics) {
    let wall_start = Instant::now();

    let indices: HashMap<Participant, usize> = protocols
        .iter()
        .enumerate()
        .map(|(i, (p, _))| (*p, i))
        .collect();

    let size = protocols.len();
    let all_participants: Vec<Participant> = protocols.iter().map(|(p, _)| *p).collect();

    let mut states: Vec<ParticipantState> = (0..size)
        .map(|_| ParticipantState {
            clock: 0,
            finished: false,
        })
        .collect();

    let mut queue: BinaryHeap<Reverse<PendingMessage>> = BinaryHeap::new();

    let mut metrics = SimulationMetrics {
        total_bytes_sent: 0,
        total_bytes_received: 0,
        total_messages_sent: 0,
        total_messages_received: 0,
        bytes_sent_per_participant: all_participants.iter().map(|p| (*p, 0)).collect(),
        bytes_received_per_participant: all_participants.iter().map(|p| (*p, 0)).collect(),
        wall_clock_elapsed: Duration::ZERO,
        virtual_time_elapsed: 0,
    };

    let mut outputs: Vec<(Participant, T)> = Vec::with_capacity(size);

    for i in 0..size {
        drain_poke(
            i,
            &mut protocols,
            &mut states,
            &indices,
            &all_participants,
            &mut queue,
            &mut metrics,
            &mut outputs,
            latency_model,
        );
    }

    while let Some(Reverse(msg)) = queue.pop() {
        let receiver_idx = *indices
            .get(&msg.to)
            .unwrap_or_else(|| panic!("Unknown participant {:?}", msg.to));

        if states[receiver_idx].finished {
            continue;
        }

        let state = &mut states[receiver_idx];
        if msg.arrival_time > state.clock {
            state.clock = msg.arrival_time;
        }

        let data_len = msg.data.len() as u64;
        metrics.total_bytes_received += data_len;
        metrics.total_messages_received += 1;
        *metrics
            .bytes_received_per_participant
            .entry(msg.to)
            .or_insert(0) += data_len;

        protocols[receiver_idx]
            .1
            .message(msg.from, msg.data)
            .expect("Message delivery failed");

        drain_poke(
            receiver_idx,
            &mut protocols,
            &mut states,
            &indices,
            &all_participants,
            &mut queue,
            &mut metrics,
            &mut outputs,
            latency_model,
        );
    }

    metrics.wall_clock_elapsed = wall_start.elapsed();
    metrics.virtual_time_elapsed = states.iter().map(|s| s.clock).max().unwrap_or(0);

    outputs.sort_by_key(|(p, _)| *p);
    (outputs, metrics)
}

#[allow(clippy::too_many_arguments)]
fn drain_poke<T>(
    idx: usize,
    protocols: &mut [(Participant, Box<dyn Protocol<Output = T>>)],
    states: &mut [ParticipantState],
    indices: &HashMap<Participant, usize>,
    all_participants: &[Participant],
    queue: &mut BinaryHeap<Reverse<PendingMessage>>,
    metrics: &mut SimulationMetrics,
    outputs: &mut Vec<(Participant, T)>,
    latency_model: &LatencyModel,
) {
    if states[idx].finished {
        return;
    }

    let sender = protocols[idx].0;

    loop {
        let poke_start = Instant::now();
        let action = protocols[idx].1.poke().expect("Protocol poke failed");
        let poke_elapsed_ns = poke_start.elapsed().as_nanos() as u64;

        states[idx].clock += poke_elapsed_ns;

        match action {
            Action::Wait => break,
            Action::SendMany(data) => {
                for &recipient in all_participants {
                    if recipient == sender {
                        continue;
                    }
                    let data_len = data.len() as u64;
                    metrics.total_bytes_sent += data_len;
                    metrics.total_messages_sent += 1;
                    *metrics
                        .bytes_sent_per_participant
                        .entry(sender)
                        .or_insert(0) += data_len;

                    let latency = latency_model.sample();
                    queue.push(Reverse(PendingMessage {
                        arrival_time: states[idx].clock + latency,
                        from: sender,
                        to: recipient,
                        data: data.clone(),
                    }));
                }
            }
            Action::SendPrivate(recipient, data) => {
                if indices.contains_key(&recipient) {
                    let data_len = data.len() as u64;
                    metrics.total_bytes_sent += data_len;
                    metrics.total_messages_sent += 1;
                    *metrics
                        .bytes_sent_per_participant
                        .entry(sender)
                        .or_insert(0) += data_len;

                    let latency = latency_model.sample();
                    queue.push(Reverse(PendingMessage {
                        arrival_time: states[idx].clock + latency,
                        from: sender,
                        to: recipient,
                        data,
                    }));
                }
            }
            Action::Return(result) => {
                states[idx].finished = true;
                outputs.push((sender, result));
                break;
            }
        }
    }
}
