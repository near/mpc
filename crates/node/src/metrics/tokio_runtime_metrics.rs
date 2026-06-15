use prometheus::{CounterVec, IntGaugeVec, register_counter_vec, register_int_gauge_vec};
use std::sync::LazyLock;
use tokio_metrics::RuntimeMonitor;

use crate::metrics::MONITOR_SAMPLE_DURATION;

/// Distinguishes the runtimes that each run their own monitor loop (e.g. the
/// main MPC runtime vs. the lower-priority asset-generation runtime).
const RUNTIME_LABEL: &str = "runtime";

static TOKIO_RUNTIME_BUSY_DURATION_SECONDS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "tokio_runtime_busy_duration_seconds_total",
        "Total time worker threads were busy since runtime start (seconds).",
        &[RUNTIME_LABEL]
    )
    .unwrap()
});

static TOKIO_RUNTIME_TIME_ELAPSED_SECONDS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "tokio_runtime_time_elapsed_seconds_total",
        "Total amount of time elapsed since observing runtime metrics (seconds).",
        &[RUNTIME_LABEL]
    )
    .unwrap()
});

static TOKIO_RUNTIME_GLOBAL_QUEUE_DEPTH: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "tokio_runtime_global_queue_depth",
        "Current tasks in global queue.",
        &[RUNTIME_LABEL]
    )
    .unwrap()
});

static TOKIO_RUNTIME_LIVE_TASKS_COUNT: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "tokio_runtime_live_tasks_count",
        "Current number of alive tasks.",
        &[RUNTIME_LABEL]
    )
    .unwrap()
});

/// Samples `runtime_monitor` forever, publishing its metrics under the given
/// `runtime` label so multiple runtimes don't conflate into one series.
pub(crate) async fn run_monitor_loop(runtime: &'static str, runtime_monitor: RuntimeMonitor) {
    let mut ticker = tokio::time::interval(MONITOR_SAMPLE_DURATION);

    let busy_duration = TOKIO_RUNTIME_BUSY_DURATION_SECONDS_TOTAL.with_label_values(&[runtime]);
    let time_elapsed = TOKIO_RUNTIME_TIME_ELAPSED_SECONDS_TOTAL.with_label_values(&[runtime]);
    let global_queue_depth = TOKIO_RUNTIME_GLOBAL_QUEUE_DEPTH.with_label_values(&[runtime]);
    let live_tasks_count = TOKIO_RUNTIME_LIVE_TASKS_COUNT.with_label_values(&[runtime]);

    for runtime_metrics in runtime_monitor.intervals() {
        busy_duration.inc_by(runtime_metrics.total_busy_duration.as_secs_f64());
        time_elapsed.inc_by(runtime_metrics.elapsed.as_secs_f64());

        global_queue_depth.set(runtime_metrics.global_queue_depth as i64);
        live_tasks_count.set(runtime_metrics.live_tasks_count as i64);

        ticker.tick().await;
    }
}
