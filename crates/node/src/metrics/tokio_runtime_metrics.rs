use prometheus::{register_counter, register_int_gauge, Counter, IntGauge};
use std::sync::LazyLock;
use tokio_metrics::RuntimeMonitor;

use crate::metrics::MONITOR_SAMPLE_DURATION;

static TOKIO_RUNTIME_TOTAL_BUSY_DURATION_SECONDS: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "tokio_runtime_total_busy_duration_seconds",
        "Total time worker threads were busy since runtime start (seconds)."
    )
    .unwrap()
});

static TOKIO_RUNTIME_TOTAL_TIME_ELAPSED_SECONDS: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "tokio_runtime_total_time_elapsed_seconds",
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
    for runtime_metrics in runtime_monitor.intervals() {
        TOKIO_RUNTIME_TOTAL_BUSY_DURATION_SECONDS
            .inc_by(runtime_metrics.total_busy_duration.as_secs_f64());
        TOKIO_RUNTIME_TOTAL_TIME_ELAPSED_SECONDS.inc_by(runtime_metrics.elapsed.as_secs_f64());

        TOKIO_RUNTIME_GLOBAL_QUEUE_DEPTH.set(runtime_metrics.global_queue_depth as i64);
        TOKIO_RUNTIME_LIVE_TASKS_COUNT.set(runtime_metrics.live_tasks_count as i64);

        tokio::time::sleep(MONITOR_SAMPLE_DURATION).await;
    }
}
