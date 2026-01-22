use prometheus::{register_gauge, register_int_gauge, Gauge, IntGauge};
use std::{sync::LazyLock, time::Duration};
use tokio_metrics::RuntimeMonitor;

const RUNTIME_METRIC_INTERVAL: Duration = Duration::from_secs(1);

// --- STABLE METRICS ---
static TOKIO_RUNTIME_TOTAL_BUSY_DURATION_SECONDS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "tokio_runtime_total_busy_duration_seconds",
        "Total time worker threads were busy since runtime start (seconds)."
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

static TOKIO_RUNTIME_BUSY_RATIO: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(
        "tokio_runtime_busy_ratio",
        "Ratio of worker busy time to elapsed time."
    )
    .unwrap()
});

static TOKIO_RUNTIME_MEAN_POLL_DURATION_SECONDS: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(
        "tokio_runtime_mean_poll_duration_seconds",
        "Average time a task takes per poll. High values indicate blocking code."
    )
    .unwrap()
});

static TOKIO_RUNTIME_TOTAL_STEAL_COUNT: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "tokio_runtime_total_steal_count",
        "Number of tasks stolen by one worker from another. Indicates load imbalance."
    )
    .unwrap()
});

static TOKIO_RUNTIME_FORCED_YIELD_COUNT: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "tokio_runtime_budget_forced_yield_count",
        "Number of times tasks were forced to yield by the budget. Indicates compute-heavy tasks."
    )
    .unwrap()
});

static TOKIO_RUNTIME_BLOCKING_QUEUE_DEPTH: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "tokio_runtime_blocking_queue_depth",
        "Number of tasks waiting in the spawn_blocking pool."
    )
    .unwrap()
});

pub(crate) async fn monitor_runtime_metrics(runtime_monitor: RuntimeMonitor) {
    for runtime_metrics in runtime_monitor.intervals() {
        TOKIO_RUNTIME_TOTAL_BUSY_DURATION_SECONDS
            .set(runtime_metrics.total_busy_duration.as_secs() as i64);
        TOKIO_RUNTIME_GLOBAL_QUEUE_DEPTH.set(runtime_metrics.global_queue_depth as i64);
        TOKIO_RUNTIME_LIVE_TASKS_COUNT.set(runtime_metrics.live_tasks_count as i64);
        TOKIO_RUNTIME_BUSY_RATIO.set(runtime_metrics.busy_ratio());

        #[cfg(tokio_unstable)]
        {
            TOKIO_RUNTIME_MEAN_POLL_DURATION_SECONDS
                .set(runtime_metrics.mean_poll_duration.as_secs_f64());
            TOKIO_RUNTIME_TOTAL_STEAL_COUNT.set(runtime_metrics.total_steal_count as i64);
            TOKIO_RUNTIME_FORCED_YIELD_COUNT.set(runtime_metrics.budget_forced_yield_count as i64);
            TOKIO_RUNTIME_BLOCKING_QUEUE_DEPTH.set(runtime_metrics.blocking_queue_depth as i64);
        }

        tokio::time::sleep(RUNTIME_METRIC_INTERVAL).await;
    }
}
