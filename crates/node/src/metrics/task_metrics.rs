use prometheus::{register_int_counter_vec, IntCounterVec};
use std::{sync::LazyLock, time::Duration};
use tokio_metrics::TaskMonitor;

const TOKIO_TASK_LABELS: &[&str] = &["protocol_scheme", "task", "role"];

static TOKIO_TASK_DROPPED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "mpc_tokio_task_dropped_total",
        "TThe number of tasks dropped.",
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

static TOKIO_TASK_SLOW_POLL_DURATION_SECS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "mpc_tokio_task_slow_poll_duration_secs_total",
        "Total number of times that polling tasks completed slowly.",
        TOKIO_TASK_LABELS,
    )
    .unwrap()
});

static TOKIO_TASK_FAST_POLL_DURATION_SECS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "mpc_tokio_task_fast_poll_duration_secs_total",
        "Total number of times that polling tasks completed fast.",
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

static TOKIO_TASK_SHORT_SCHEDULE_DELAY_DURATION_SECS_TOTAL: LazyLock<IntCounterVec> =
    LazyLock::new(|| {
        register_int_counter_vec!(
            "mpc_tokio_task_short_schedule_delay_duration_secs_total",
            "The total duration of tasks with short scheduling delays.",
            TOKIO_TASK_LABELS,
        )
        .unwrap()
    });

static TOKIO_TASK_LONG_SCHEDULE_DELAY_DURATION_SECS_TOTAL: LazyLock<IntCounterVec> =
    LazyLock::new(|| {
        register_int_counter_vec!(
            "mpc_tokio_task_long_schedule_delay_duration_secs_total",
            "The total duration of tasks with long scheduling delays.",
            TOKIO_TASK_LABELS,
        )
        .unwrap()
    });

const TASK_MONITOR_SAMPLE_DURATION: Duration = Duration::from_secs(10);

pub(crate) const ECDSA_TASK_MONITORS: LazyLock<EcdsaTaskMonitors> =
    LazyLock::new(|| EcdsaTaskMonitors::default());

pub(crate) const ROBUST_ECDSA_TASK_MONITORS: LazyLock<RobustEcdsaTaskMonitors> =
    LazyLock::new(|| RobustEcdsaTaskMonitors::default());

pub(crate) const EDDSA_TASK_MONITORS: LazyLock<EddsaTaskMonitors> =
    LazyLock::new(|| EddsaTaskMonitors::default());

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
                TaskLabels::new("ecdsa", "make_signature", "leader"),
            ),
            (
                self.make_signature_follower.clone(),
                TaskLabels::new("ecdsa", "make_signature", "follower"),
            ),
            (
                self.triple_generation.clone(),
                TaskLabels::new("ecdsa", "triple_generation", "leader"),
            ),
            (
                self.triple_generation_follower.clone(),
                TaskLabels::new("ecdsa", "triple_generation", "follower"),
            ),
            (
                self.presignature_generation_leader.clone(),
                TaskLabels::new("ecdsa", "presignature_generation", "leader"),
            ),
            (
                self.presignature_generation_follower.clone(),
                TaskLabels::new("ecdsa", "presignature_generation", "follower"),
            ),
        ]
    }
}

impl TaskMonitorProvider for RobustEcdsaTaskMonitors {
    fn get_monitors(&self) -> Vec<(TaskMonitor, TaskLabels)> {
        vec![
            (
                self.make_signature.clone(),
                TaskLabels::new("robust_ecdsa", "make_signature", "leader"),
            ),
            (
                self.make_signature_follower.clone(),
                TaskLabels::new("robust_ecdsa", "make_signature", "follower"),
            ),
            (
                self.presignature_generation_leader.clone(),
                TaskLabels::new("robust_ecdsa", "presignature_generation", "leader"),
            ),
            (
                self.presignature_generation_follower.clone(),
                TaskLabels::new("robust_ecdsa", "presignature_generation", "follower"),
            ),
        ]
    }
}

impl TaskMonitorProvider for EddsaTaskMonitors {
    fn get_monitors(&self) -> Vec<(TaskMonitor, TaskLabels)> {
        vec![
            (
                self.make_signature.clone(),
                TaskLabels::new("eddsa", "make_signature", "leader"),
            ),
            (
                self.make_signature_follower.clone(),
                TaskLabels::new("eddsa", "make_signature", "follower"),
            ),
        ]
    }
}

pub(crate) async fn monitor_runtime_metrics() {
    let task_monitor_providers: [&dyn TaskMonitorProvider; 3] = [
        &*ECDSA_TASK_MONITORS,
        &*ROBUST_ECDSA_TASK_MONITORS,
        &*EDDSA_TASK_MONITORS,
    ];

    // Collect once; monitors are Clone, and label parts are &'static str.
    let task_monitors: Vec<(TaskMonitor, TaskLabels)> = task_monitor_providers
        .into_iter()
        .flat_map(TaskMonitorProvider::get_monitors)
        .collect();

    let mut ticker = tokio::time::interval(TASK_MONITOR_SAMPLE_DURATION);

    'outer: loop {
        ticker.tick().await;

        for (task_monitor, id) in task_monitors.iter() {
            let Some(metrics) = task_monitor.intervals().next() else {
                tracing::error!(
                    subsystem = id.protocol_scheme,
                    task = id.task,
                    variant = id.role,
                    "interval iterator is unended, but failed to produce next task metric"
                );
                break 'outer;
            };

            TOKIO_TASK_DROPPED_TOTAL
                .with_label_values(&id.labels())
                .inc_by(metrics.dropped_count);

            TOKIO_TASK_INSTRUMENTED_TOTAL
                .with_label_values(&id.labels())
                .inc_by(metrics.instrumented_count);

            TOKIO_TASK_SLOW_POLL_TOTAL
                .with_label_values(&id.labels())
                .inc_by(metrics.total_slow_poll_count);

            TOKIO_TASK_FAST_POLL_TOTAL
                .with_label_values(&id.labels())
                .inc_by(metrics.total_fast_poll_count);

            TOKIO_TASK_FAST_POLL_DURATION_SECS_TOTAL
                .with_label_values(&id.labels())
                .inc_by(metrics.total_fast_poll_duration.as_secs());

            TOKIO_TASK_SLOW_POLL_DURATION_SECS_TOTAL
                .with_label_values(&id.labels())
                .inc_by(metrics.total_slow_poll_duration.as_secs());

            TOKIO_TASK_SHORT_SCHEDULE_DELAY_TOTAL
                .with_label_values(&id.labels())
                .inc_by(metrics.total_short_delay_count);

            TOKIO_TASK_LONG_SCHEDULE_DELAY_TOTAL
                .with_label_values(&id.labels())
                .inc_by(metrics.total_long_delay_count);

            TOKIO_TASK_SHORT_SCHEDULE_DELAY_DURATION_SECS_TOTAL
                .with_label_values(&id.labels())
                .inc_by(metrics.total_short_delay_duration.as_secs());

            TOKIO_TASK_LONG_SCHEDULE_DELAY_DURATION_SECS_TOTAL
                .with_label_values(&id.labels())
                .inc_by(metrics.total_long_delay_duration.as_secs());
        }
    }
}
