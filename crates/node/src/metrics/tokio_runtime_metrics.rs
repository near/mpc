use prometheus::{register_counter, register_int_gauge, Counter, IntGauge};
use std::sync::LazyLock;
use tokio_metrics::RuntimeMonitor;

use crate::metrics::MONITOR_SAMPLE_DURATION;

static TOKIO_RUNTIME_BUSY_DURATION_SECONDS_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "tokio_runtime_busy_duration_seconds_total",
        "Total time worker threads were busy since runtime start (seconds)."
    )
    .unwrap()
});

static TOKIO_RUNTIME_TIME_ELAPSED_SECONDS_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "tokio_runtime_time_elapsed_seconds_total",
        "Total amount of time elapsed since observing runtime metrics (seconds)."
    )
    .unwrap()
});

static TOKIO_RUNTIME_GLOBAL_QUEUE_DEPTH: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "tokio_runtime_global_queue_depth",
        "Current tasks in global queue."
    )
    .unwrap()
});

static TOKIO_RUNTIME_LIVE_TASKS_COUNT: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "tokio_runtime_live_tasks_count",
        "Current number of alive tasks."
    )
    .unwrap()
});

pub(crate) async fn run_monitor_loop(runtime_monitor: RuntimeMonitor) {
    let mut ticker = tokio::time::interval(MONITOR_SAMPLE_DURATION);

    for runtime_metrics in runtime_monitor.intervals() {
        TOKIO_RUNTIME_BUSY_DURATION_SECONDS_TOTAL
            .inc_by(runtime_metrics.total_busy_duration.as_secs_f64());
        TOKIO_RUNTIME_TIME_ELAPSED_SECONDS_TOTAL.inc_by(runtime_metrics.elapsed.as_secs_f64());

        TOKIO_RUNTIME_GLOBAL_QUEUE_DEPTH.set(runtime_metrics.global_queue_depth as i64);
        TOKIO_RUNTIME_LIVE_TASKS_COUNT.set(runtime_metrics.live_tasks_count as i64);

        ticker.tick().await;
    }
}
