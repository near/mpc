use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::env;
use std::io::Write;
use std::time::{Duration, Instant};

use statrs::statistics::Statistics;

use crate::participants::Participant;
use crate::protocol::{Action, Protocol};

// Discrete-event protocol simulator.
//
// All participants share a single global timeline starting at t=0.
// Each participant tracks its position on this timeline via a clock (in ns).
// The clock advances in two ways:
//   - Computation: wall-clock time of each poke() call is added, including
//     pokes that end in Wait, which may have processed received messages.
//   - Waiting: on message receipt, clock = max(clock, arrival_time).
// Messages are delivered via a priority queue ordered by arrival_time,
// where arrival_time = sender_clock + latency at the time of sending.

pub fn run_simulation<T>(
    mut protocols: Vec<(Participant, impl Protocol<Output = T>)>,
    latency_model: &LatencyModel,
) -> (Vec<(Participant, T)>, SimulationMetrics) {
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
        compute_time_per_participant: all_participants
            .iter()
            .map(|p| (*p, Duration::ZERO))
            .collect(),
        max_burst_time: Duration::ZERO,
        max_message_bytes: 0,
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

        metrics.record_received(msg.to, &msg.data);
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

    metrics.virtual_time_elapsed = states.iter().map(|s| s.clock).max().unwrap_or(0);

    outputs.sort_by_key(|(p, _)| *p);
    (outputs, metrics)
}

pub fn bench_simulation(name: &str, run: &dyn Fn() -> SimulationMetrics, samples: usize) {
    let bar_width = 20;
    eprint!("{name}: ");
    let metrics: Vec<SimulationMetrics> = (0..samples)
        .map(|i| {
            let sample = run();
            let done = (i + 1) * bar_width / samples;
            eprint!(
                "\r{name}: [{}{}] {}/{}",
                "#".repeat(done),
                ".".repeat(bar_width - done),
                i + 1,
                samples
            );
            let _ = std::io::stderr().flush();
            sample
        })
        .collect();
    eprintln!();
    let first = metrics.first().expect("samples > 0");
    for sample in &metrics[1..] {
        sample.assert_deterministic(first, name);
    }

    println!("=== {name} ===");
    print!("{first}");
    print_spread(
        "Virtual time",
        metrics.iter().map(SimulationMetrics::virtual_time_ms),
    );
    print_spread(
        "Avg compute/participant",
        metrics.iter().map(SimulationMetrics::avg_compute_ms),
    );
    print_spread(
        "Max burst",
        metrics.iter().map(|m| m.max_burst_time.as_secs_f64() * 1e3),
    );
}

fn print_spread(label: &str, values_ms: impl Iterator<Item = f64>) {
    let values_ms: Vec<f64> = values_ms.collect();
    println!(
        "{label}: avg {:.3} ms, min {:.3} ms, max {:.3} ms",
        Statistics::mean(&values_ms),
        Statistics::min(&values_ms),
        Statistics::max(&values_ms)
    );
}

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

#[derive(Debug, Clone)]
pub struct SimulationMetrics {
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub bytes_sent_per_participant: HashMap<Participant, u64>,
    pub bytes_received_per_participant: HashMap<Participant, u64>,
    /// Wall-clock time each participant spent in [`Protocol::poke`], including pokes that return
    /// [`Action::Wait`].
    pub compute_time_per_participant: HashMap<Participant, Duration>,
    /// How long the node's protocol runner holds a runtime thread without yielding to other
    /// tasks, estimated from below by the longest run of consecutive [`Protocol::poke`] calls up
    /// to an [`Action::Wait`], [`Action::Yield`] or [`Action::Return`].
    pub max_burst_time: Duration,
    /// Largest single protocol message, in bytes.
    pub max_message_bytes: u64,
    /// max(all participant clocks) in ns, includes network latency + computation time.
    pub virtual_time_elapsed: u64,
}

impl SimulationMetrics {
    #[allow(clippy::cast_precision_loss)]
    pub fn virtual_time_ms(&self) -> f64 {
        self.virtual_time_elapsed as f64 / 1_000_000.0
    }

    fn avg_compute_ms(&self) -> f64 {
        self.compute_time_per_participant
            .values()
            .map(|time| time.as_secs_f64() * 1e3)
            .mean()
    }

    fn record_sent(&mut self, sender: Participant, data: &[u8]) {
        let data_len = u64::try_from(data.len()).expect("message length fits in u64");
        self.total_bytes_sent += data_len;
        self.total_messages_sent += 1;
        self.max_message_bytes = self.max_message_bytes.max(data_len);
        *self.bytes_sent_per_participant.entry(sender).or_insert(0) += data_len;
    }

    fn record_received(&mut self, receiver: Participant, data: &[u8]) {
        let data_len = u64::try_from(data.len()).expect("message length fits in u64");
        self.total_bytes_received += data_len;
        self.total_messages_received += 1;
        *self
            .bytes_received_per_participant
            .entry(receiver)
            .or_insert(0) += data_len;
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
        writeln!(f, "Max message: {} bytes", self.max_message_bytes)?;
        Ok(())
    }
}

/// - `NUM_PARTICIPANTS` (default: 7)
/// - `THRESHOLD` (default: n/2 + 1)
/// - `LATENCY_MS` (default: 50)
/// - `SAMPLE_SIZE` (default: 15)
pub struct BenchConfig {
    pub num_participants: usize,
    pub threshold: usize,
    pub latency: LatencyModel,
    pub samples: usize,
}

const WARMUP_SECS: u64 = 3;

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

// Field order matters: derived Ord compares fields top-to-bottom.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct PendingMessage {
    arrival_time: u64,
    from: Participant,
    to: Participant,
    data: Vec<u8>,
}

struct ParticipantState {
    clock: u64,
    finished: bool,
}

#[allow(clippy::too_many_arguments)]
fn drain_poke<T>(
    idx: usize,
    protocols: &mut [(Participant, impl Protocol<Output = T>)],
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
    let mut burst = Duration::ZERO;

    loop {
        let poke_start = Instant::now();
        let action = protocols[idx].1.poke().expect("Protocol poke failed");
        let poke_elapsed = poke_start.elapsed();
        states[idx].clock +=
            u64::try_from(poke_elapsed.as_nanos()).expect("a poke takes less than 584 years");
        *metrics
            .compute_time_per_participant
            .entry(sender)
            .or_default() += poke_elapsed;

        burst += poke_elapsed;
        if matches!(action, Action::Wait | Action::Yield | Action::Return(_)) {
            metrics.max_burst_time = metrics.max_burst_time.max(burst);
            burst = Duration::ZERO;
        }

        match action {
            Action::Wait => break,
            // Keep poking.
            Action::Yield => {}
            Action::SendMany(data) => {
                for &recipient in all_participants {
                    if recipient == sender {
                        continue;
                    }
                    metrics.record_sent(sender, &data);
                    queue.push(Reverse(PendingMessage {
                        arrival_time: states[idx].clock + latency_model.sample(),
                        from: sender,
                        to: recipient,
                        data: data.clone(),
                    }));
                }
            }
            Action::SendPrivate(recipient, data) => {
                if indices.contains_key(&recipient) {
                    metrics.record_sent(sender, &data);
                    queue.push(Reverse(PendingMessage {
                        arrival_time: states[idx].clock + latency_model.sample(),
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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::collections::VecDeque;
    use std::thread;
    use std::time::Duration;

    use rstest::rstest;

    use super::{LatencyModel, run_simulation};
    use crate::errors::{MessageError, ProtocolError};
    use crate::participants::Participant;
    use crate::protocol::{Action, MessageData, Protocol};

    const POKE_WORK: Duration = Duration::from_millis(5);

    struct BusyPokes {
        script: VecDeque<Action<()>>,
    }

    impl Protocol for BusyPokes {
        type Output = ();

        fn poke(&mut self) -> Result<Action<()>, ProtocolError> {
            let Some(action) = self.script.pop_front() else {
                return Ok(Action::Wait);
            };
            thread::sleep(POKE_WORK);
            Ok(action)
        }

        fn message(&mut self, _from: Participant, _data: MessageData) -> Result<(), MessageError> {
            Ok(())
        }
    }

    #[rstest]
    #[case::wait(Action::Wait)]
    #[case::yield_(Action::Yield)]
    #[case::send_many(Action::SendMany(vec![0]))]
    #[case::send_private(Action::SendPrivate(Participant::from(1_u32), vec![0]))]
    #[case::return_(Action::Return(()))]
    fn run_simulation__should_count_poke_time_whatever_the_action(#[case] action: Action<()>) {
        // Given
        let me = Participant::from(0_u32);
        let protocols = vec![(
            me,
            BusyPokes {
                script: [action].into(),
            },
        )];

        // When
        let (_, metrics) = run_simulation(protocols, &LatencyModel::Fixed(0));

        // Then
        assert!(Duration::from_nanos(metrics.virtual_time_elapsed) >= POKE_WORK);
        assert!(metrics.compute_time_per_participant[&me] >= POKE_WORK);
    }

    #[rstest]
    #[case::wait(Action::Wait)]
    #[case::yield_(Action::Yield)]
    #[case::return_(Action::Return(()))]
    fn run_simulation__should_extend_a_burst_over_sends_until_the_protocol_stops(
        #[case] stop: Action<()>,
    ) {
        // Given
        let protocols = vec![(
            Participant::from(0_u32),
            BusyPokes {
                script: [Action::SendMany(vec![0]), Action::SendMany(vec![0]), stop].into(),
            },
        )];

        // When
        let (_, metrics) = run_simulation(protocols, &LatencyModel::Fixed(0));

        // Then
        assert!(metrics.max_burst_time >= 3 * POKE_WORK);
    }

    #[test]
    fn run_simulation__should_end_a_burst_at_yield() {
        // Given
        let me = Participant::from(0_u32);
        let protocols = vec![(
            me,
            BusyPokes {
                script: [Action::Yield, Action::Return(())].into(),
            },
        )];

        // When
        let (_, metrics) = run_simulation(protocols, &LatencyModel::Fixed(0));

        // Then
        assert!(metrics.max_burst_time < metrics.compute_time_per_participant[&me]);
    }

    #[test]
    fn run_simulation__should_record_the_largest_message() {
        // Given
        let receiver = Participant::from(1_u32);
        let protocols = vec![
            (
                Participant::from(0_u32),
                BusyPokes {
                    script: [
                        Action::SendPrivate(receiver, vec![0; 3]),
                        Action::SendMany(vec![0; 10]),
                        Action::SendPrivate(receiver, vec![0; 5]),
                    ]
                    .into(),
                },
            ),
            (
                receiver,
                BusyPokes {
                    script: VecDeque::new(),
                },
            ),
        ];

        // When
        let (_, metrics) = run_simulation(protocols, &LatencyModel::Fixed(0));

        // Then
        assert_eq!(metrics.max_message_bytes, 10);
    }
}
