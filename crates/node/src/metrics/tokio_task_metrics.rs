use prometheus::{register_counter_vec, register_int_counter_vec, CounterVec, IntCounterVec};
use std::sync::LazyLock;
use tokio_metrics::TaskMonitor;

use crate::metrics::MONITOR_SAMPLE_DURATION;

const TOKIO_TASK_LABELS: &[&str] = &["protocol_scheme", "task", "role"];

const ECDSA_PROTOCOL_SCHEME_LABEL: &str = "ecdsa";
const EDDSA_PROTOCOL_SCHEME_LABEL: &str = "eddsa";
const ROBUST_ECDSA_PROTOCOL_SCHEME_LABEL: &str = "robust_ecdsa";

const MAKE_SIGNATURE_TASK_LABEL: &str = "make_signature";
const TRIPLE_GENERATION_TASK_LABEL: &str = "triple_generation";
const PRESIGNATURE_GENERATION_TASK_LABEL: &str = "presignature_generation";

const LEADER_ROLE_LABEL: &str = "leader";
const FOLLOWER_ROLE_LABEL: &str = "follower";

static TOKIO_TASK_DROPPED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "mpc_tokio_task_dropped_total",
        "The number of tasks dropped.",
        TOKIO_TASK_LABELS,
    )
    .unwrap()
});

static TOKIO_TASK_INSTRUMENTED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "mpc_tokio_task_instrumented_total",
        "The number of tasks instrumented.",
        TOKIO_TASK_LABELS,
    )
    .unwrap()
});

static TOKIO_TASK_SLOW_POLL_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "mpc_tokio_task_slow_poll_total",
        "Total number of times that polling tasks completed slowly.",
        TOKIO_TASK_LABELS,
    )
    .unwrap()
});

static TOKIO_TASK_FAST_POLL_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "mpc_tokio_task_fast_poll_total",
        "Total number of times that polling tasks completed fast.",
        TOKIO_TASK_LABELS,
    )
    .unwrap()
});

static TOKIO_TASK_SLOW_POLL_DURATION_SECONDS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "mpc_tokio_task_slow_poll_duration_seconds_total",
        "The total duration of slow polls.",
        TOKIO_TASK_LABELS,
    )
    .unwrap()
});

static TOKIO_TASK_FAST_POLL_DURATION_SECONDS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "mpc_tokio_task_fast_poll_duration_seconds_total",
        "The total duration of fast polls.",
        TOKIO_TASK_LABELS,
    )
    .unwrap()
});

static TOKIO_TASK_SHORT_SCHEDULE_DELAY_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "mpc_tokio_task_short_schedule_delay_total",
        "The total count of tasks with short scheduling delays.",
        TOKIO_TASK_LABELS,
    )
    .unwrap()
});

static TOKIO_TASK_LONG_SCHEDULE_DELAY_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "mpc_tokio_task_long_schedule_delay_total",
        "The total count of tasks with long scheduling delays.",
        TOKIO_TASK_LABELS,
    )
    .unwrap()
});

static TOKIO_TASK_SHORT_SCHEDULE_DELAY_DURATION_SECONDS_TOTAL: LazyLock<CounterVec> =
    LazyLock::new(|| {
        register_counter_vec!(
            "mpc_tokio_task_short_schedule_delay_duration_seconds_total",
            "The total duration of tasks with short scheduling delays.",
            TOKIO_TASK_LABELS,
        )
        .unwrap()
    });

static TOKIO_TASK_LONG_SCHEDULE_DELAY_DURATION_SECONDS_TOTAL: LazyLock<CounterVec> =
    LazyLock::new(|| {
        register_counter_vec!(
            "mpc_tokio_task_long_schedule_delay_duration_seconds_total",
            "The total duration of tasks with long scheduling delays.",
            TOKIO_TASK_LABELS,
        )
        .unwrap()
    });

pub(crate) static ECDSA_TASK_MONITORS: LazyLock<EcdsaTaskMonitors> =
    LazyLock::new(EcdsaTaskMonitors::default);

pub(crate) static ROBUST_ECDSA_TASK_MONITORS: LazyLock<RobustEcdsaTaskMonitors> =
    LazyLock::new(RobustEcdsaTaskMonitors::default);

pub(crate) static EDDSA_TASK_MONITORS: LazyLock<EddsaTaskMonitors> =
    LazyLock::new(EddsaTaskMonitors::default);

#[derive(Default)]
pub(crate) struct EcdsaTaskMonitors {
    pub(crate) make_signature: TaskMonitor,
    pub(crate) make_signature_follower: TaskMonitor,

    pub(crate) triple_generation: TaskMonitor,
    pub(crate) triple_generation_follower: TaskMonitor,

    pub(crate) presignature_generation_leader: TaskMonitor,
    pub(crate) presignature_generation_follower: TaskMonitor,
}

#[derive(Default)]
pub(crate) struct RobustEcdsaTaskMonitors {
    pub(crate) make_signature: TaskMonitor,
    pub(crate) make_signature_follower: TaskMonitor,

    pub(crate) presignature_generation_leader: TaskMonitor,
    pub(crate) presignature_generation_follower: TaskMonitor,
}

#[derive(Default)]
pub(crate) struct EddsaTaskMonitors {
    pub(crate) make_signature: TaskMonitor,
    pub(crate) make_signature_follower: TaskMonitor,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TaskLabels {
    pub(crate) protocol_scheme: &'static str,
    pub(crate) task: &'static str,
    pub(crate) role: &'static str,
}

impl TaskLabels {
    pub(crate) const fn new(
        protocol_scheme: &'static str,
        task: &'static str,
        role: &'static str,
    ) -> Self {
        Self {
            protocol_scheme,
            task,
            role,
        }
    }

    pub(crate) const fn labels(&self) -> [&'static str; 3] {
        [self.protocol_scheme, self.task, self.role]
    }
}

trait TaskMonitorProvider {
    fn get_monitors(&self) -> Vec<(TaskMonitor, TaskLabels)>;
}

impl TaskMonitorProvider for EcdsaTaskMonitors {
    fn get_monitors(&self) -> Vec<(TaskMonitor, TaskLabels)> {
        vec![
            (
                self.make_signature.clone(),
                TaskLabels::new(
                    ECDSA_PROTOCOL_SCHEME_LABEL,
                    MAKE_SIGNATURE_TASK_LABEL,
                    LEADER_ROLE_LABEL,
                ),
            ),
            (
                self.make_signature_follower.clone(),
                TaskLabels::new(
                    ECDSA_PROTOCOL_SCHEME_LABEL,
                    MAKE_SIGNATURE_TASK_LABEL,
                    FOLLOWER_ROLE_LABEL,
                ),
            ),
            (
                self.triple_generation.clone(),
                TaskLabels::new(
                    ECDSA_PROTOCOL_SCHEME_LABEL,
                    TRIPLE_GENERATION_TASK_LABEL,
                    LEADER_ROLE_LABEL,
                ),
            ),
            (
                self.triple_generation_follower.clone(),
                TaskLabels::new(
                    ECDSA_PROTOCOL_SCHEME_LABEL,
                    TRIPLE_GENERATION_TASK_LABEL,
                    FOLLOWER_ROLE_LABEL,
                ),
            ),
            (
                self.presignature_generation_leader.clone(),
                TaskLabels::new(
                    ECDSA_PROTOCOL_SCHEME_LABEL,
                    PRESIGNATURE_GENERATION_TASK_LABEL,
                    LEADER_ROLE_LABEL,
                ),
            ),
            (
                self.presignature_generation_follower.clone(),
                TaskLabels::new(
                    ECDSA_PROTOCOL_SCHEME_LABEL,
                    PRESIGNATURE_GENERATION_TASK_LABEL,
                    FOLLOWER_ROLE_LABEL,
                ),
            ),
        ]
    }
}

impl TaskMonitorProvider for RobustEcdsaTaskMonitors {
    fn get_monitors(&self) -> Vec<(TaskMonitor, TaskLabels)> {
        vec![
            (
                self.make_signature.clone(),
                TaskLabels::new(
                    ROBUST_ECDSA_PROTOCOL_SCHEME_LABEL,
                    MAKE_SIGNATURE_TASK_LABEL,
                    LEADER_ROLE_LABEL,
                ),
            ),
            (
                self.make_signature_follower.clone(),
                TaskLabels::new(
                    ROBUST_ECDSA_PROTOCOL_SCHEME_LABEL,
                    MAKE_SIGNATURE_TASK_LABEL,
                    FOLLOWER_ROLE_LABEL,
                ),
            ),
            (
                self.presignature_generation_leader.clone(),
                TaskLabels::new(
                    ROBUST_ECDSA_PROTOCOL_SCHEME_LABEL,
                    PRESIGNATURE_GENERATION_TASK_LABEL,
                    LEADER_ROLE_LABEL,
                ),
            ),
            (
                self.presignature_generation_follower.clone(),
                TaskLabels::new(
                    ROBUST_ECDSA_PROTOCOL_SCHEME_LABEL,
                    PRESIGNATURE_GENERATION_TASK_LABEL,
                    FOLLOWER_ROLE_LABEL,
                ),
            ),
        ]
    }
}

impl TaskMonitorProvider for EddsaTaskMonitors {
    fn get_monitors(&self) -> Vec<(TaskMonitor, TaskLabels)> {
        vec![
            (
                self.make_signature.clone(),
                TaskLabels::new(
                    EDDSA_PROTOCOL_SCHEME_LABEL,
                    MAKE_SIGNATURE_TASK_LABEL,
                    LEADER_ROLE_LABEL,
                ),
            ),
            (
                self.make_signature_follower.clone(),
                TaskLabels::new(
                    EDDSA_PROTOCOL_SCHEME_LABEL,
                    MAKE_SIGNATURE_TASK_LABEL,
                    FOLLOWER_ROLE_LABEL,
                ),
            ),
        ]
    }
}

pub(crate) async fn run_monitor_loop() {
    let task_monitor_providers: [&dyn TaskMonitorProvider; 3] = [
        &*ECDSA_TASK_MONITORS,
        &*ROBUST_ECDSA_TASK_MONITORS,
        &*EDDSA_TASK_MONITORS,
    ];

    let mut task_monitors: Vec<_> = task_monitor_providers
        .into_iter()
        .flat_map(TaskMonitorProvider::get_monitors)
        // TODO(#1841): `TaskMonitorProvider` should return intervals directly
        .map(|(task_monitor, labels)| (task_monitor.intervals(), labels))
        .collect();

    let mut ticker = tokio::time::interval(MONITOR_SAMPLE_DURATION);

    loop {
        ticker.tick().await;

        for (task_interval, task_labels) in task_monitors.iter_mut() {
            let Some(metrics) = task_interval.next() else {
                tracing::error!(
                    protocol_scheme = task_labels.protocol_scheme,
                    task = task_labels.task,
                    role = task_labels.role,
                    "interval iterator is unending, but failed to produce next task metric"
                );
                return;
            };

            TOKIO_TASK_DROPPED_TOTAL
                .with_label_values(&task_labels.labels())
                .inc_by(metrics.dropped_count);

            TOKIO_TASK_INSTRUMENTED_TOTAL
                .with_label_values(&task_labels.labels())
                .inc_by(metrics.instrumented_count);

            TOKIO_TASK_SLOW_POLL_TOTAL
                .with_label_values(&task_labels.labels())
                .inc_by(metrics.total_slow_poll_count);

            TOKIO_TASK_FAST_POLL_TOTAL
                .with_label_values(&task_labels.labels())
                .inc_by(metrics.total_fast_poll_count);

            TOKIO_TASK_FAST_POLL_DURATION_SECONDS_TOTAL
                .with_label_values(&task_labels.labels())
                .inc_by(metrics.total_fast_poll_duration.as_secs_f64());

            TOKIO_TASK_SLOW_POLL_DURATION_SECONDS_TOTAL
                .with_label_values(&task_labels.labels())
                .inc_by(metrics.total_slow_poll_duration.as_secs_f64());

            TOKIO_TASK_SHORT_SCHEDULE_DELAY_TOTAL
                .with_label_values(&task_labels.labels())
                .inc_by(metrics.total_short_delay_count);

            TOKIO_TASK_LONG_SCHEDULE_DELAY_TOTAL
                .with_label_values(&task_labels.labels())
                .inc_by(metrics.total_long_delay_count);

            TOKIO_TASK_SHORT_SCHEDULE_DELAY_DURATION_SECONDS_TOTAL
                .with_label_values(&task_labels.labels())
                .inc_by(metrics.total_short_delay_duration.as_secs_f64());

            TOKIO_TASK_LONG_SCHEDULE_DELAY_DURATION_SECONDS_TOTAL
                .with_label_values(&task_labels.labels())
                .inc_by(metrics.total_long_delay_duration.as_secs_f64());
        }
    }
}
