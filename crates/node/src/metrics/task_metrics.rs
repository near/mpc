use prometheus::{register_int_counter_vec, IntCounterVec};
use std::{sync::LazyLock, time::Duration};
use tokio_metrics::TaskMonitor;

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

static TOKIO_TASK_SLOW_POLL_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "mpc_tokio_task_slow_poll_total",
        "The total number of times that polling tasks completed slowly.",
        &["task"],
    )
    .unwrap()
});

pub(crate) async fn monitor_runtime_metrics() {
    // Collect all intervals into a Vec or Map to iterate over them
    let mut intervals = vec![
        (
            ECDSA_TASK_MONITORS.make_signature.intervals(),
            "ecdsa_make_signature",
        ),
        (
            ECDSA_TASK_MONITORS.make_signature_follower.intervals(),
            "ecdsa_make_signature_follower",
        ),
        // Add others here...
    ];

    let mut interval_timer = tokio::time::interval(TASK_MONITOR_SAMPLE_DURATION);

    loop {
        interval_timer.tick().await;

        for (ref mut interval_iter, label) in &mut intervals {
            if let Some(metrics) = interval_iter.next() {
                TOKIO_TASK_SLOW_POLL_TOTAL
                    .with_label_values(&[label])
                    .inc_by(metrics.total_slow_poll_count);

                // You can also capture other useful metrics here:
                // metrics.mean_poll_duration(), metrics.total_idled_time, etc.
            }
        }
    }
}
