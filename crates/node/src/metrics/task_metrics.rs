use prometheus::{register_int_counter_vec, IntCounterVec};
use std::{sync::LazyLock, time::Duration};
use tokio_metrics::TaskMonitor;

static TOKIO_TASK_SLOW_POLL_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "mpc_tokio_task_slow_poll_total",
        "Total number of times that polling tasks completed slowly.",
        &["subsystem", "task", "variant"],
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

/// Stable, low-cardinality labels for all instrumented tasks.
///
/// Use `variant = "na"` when there is no meaningful variant.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TaskId {
    pub(crate) subsystem: &'static str,
    pub(crate) task: &'static str,
    pub(crate) variant: &'static str,
}

impl TaskId {
    pub(crate) const fn new(
        subsystem: &'static str,
        task: &'static str,
        variant: &'static str,
    ) -> Self {
        Self {
            subsystem,
            task,
            variant,
        }
    }

    pub(crate) const fn labels(&self) -> [&'static str; 3] {
        [self.subsystem, self.task, self.variant]
    }
}

trait TaskMonitorProvider {
    fn get_monitors(&self) -> Vec<(TaskMonitor, TaskId)>;
}

impl TaskMonitorProvider for EcdsaTaskMonitors {
    fn get_monitors(&self) -> Vec<(TaskMonitor, TaskId)> {
        vec![
            (
                self.make_signature.clone(),
                TaskId::new("ecdsa", "make_signature", "leader"),
            ),
            (
                self.make_signature_follower.clone(),
                TaskId::new("ecdsa", "make_signature", "follower"),
            ),
            (
                self.triple_generation.clone(),
                TaskId::new("ecdsa", "triple_generation", "leader"),
            ),
            (
                self.triple_generation_follower.clone(),
                TaskId::new("ecdsa", "triple_generation", "follower"),
            ),
            (
                self.presignature_generation_leader.clone(),
                TaskId::new("ecdsa", "presignature_generation", "leader"),
            ),
            (
                self.presignature_generation_follower.clone(),
                TaskId::new("ecdsa", "presignature_generation", "follower"),
            ),
        ]
    }
}

impl TaskMonitorProvider for RobustEcdsaTaskMonitors {
    fn get_monitors(&self) -> Vec<(TaskMonitor, TaskId)> {
        vec![
            (
                self.make_signature.clone(),
                TaskId::new("robust_ecdsa", "make_signature", "leader"),
            ),
            (
                self.make_signature_follower.clone(),
                TaskId::new("robust_ecdsa", "make_signature", "follower"),
            ),
            (
                self.presignature_generation_leader.clone(),
                TaskId::new("robust_ecdsa", "presignature_generation", "leader"),
            ),
            (
                self.presignature_generation_follower.clone(),
                TaskId::new("robust_ecdsa", "presignature_generation", "follower"),
            ),
        ]
    }
}

impl TaskMonitorProvider for EddsaTaskMonitors {
    fn get_monitors(&self) -> Vec<(TaskMonitor, TaskId)> {
        vec![
            (
                self.make_signature.clone(),
                TaskId::new("eddsa", "make_signature", "leader"),
            ),
            (
                self.make_signature_follower.clone(),
                TaskId::new("eddsa", "make_signature", "follower"),
            ),
        ]
    }
}

/// Example of a monitor that *doesn't* have leader/follower semantics:
#[allow(dead_code)]
pub(crate) fn network_example_task_id() -> TaskId {
    TaskId::new("network", "peer_gossip", "na")
}

pub(crate) async fn monitor_runtime_metrics() {
    let task_monitor_providers: [&dyn TaskMonitorProvider; 3] = [
        &*ECDSA_TASK_MONITORS,
        &*ROBUST_ECDSA_TASK_MONITORS,
        &*EDDSA_TASK_MONITORS,
    ];

    // Collect once; monitors are Clone, and label parts are &'static str.
    let task_monitors: Vec<(TaskMonitor, TaskId)> = task_monitor_providers
        .into_iter()
        .flat_map(TaskMonitorProvider::get_monitors)
        .collect();

    let mut ticker = tokio::time::interval(TASK_MONITOR_SAMPLE_DURATION);

    'outer: loop {
        ticker.tick().await;

        for (task_monitor, id) in task_monitors.iter() {
            let Some(metrics) = task_monitor.intervals().next() else {
                tracing::error!(
                    subsystem = id.subsystem,
                    task = id.task,
                    variant = id.variant,
                    "interval iterator is unended, but failed to produce next task metric"
                );
                break 'outer;
            };

            TOKIO_TASK_SLOW_POLL_TOTAL
                .with_label_values(&id.labels())
                .inc_by(metrics.total_slow_poll_count);
        }
    }
}
