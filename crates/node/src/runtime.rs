use std::ops::Deref;

use thread_priority::{ThreadPriority, set_current_thread_priority};

/// Builds a multi-threaded runtime whose worker threads run at the lowest OS
/// scheduling priority, so the OS preempts them whenever a normal-priority
/// thread is ready. Used to keep CPU-heavy asset generation from starving
/// signing.
pub fn build_lower_priority_runtime(
    worker_threads: usize,
    thread_name: &str,
) -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads.max(1))
        .thread_name(thread_name)
        .on_thread_start(|| {
            // Best-effort: on platforms/permissions where lowering priority is
            // unavailable we still want the runtime to come up.
            let _ = set_current_thread_priority(ThreadPriority::Min);
        })
        .enable_all()
        .build()
}

/// Tokio Runtime cannot be dropped in an asynchronous context (for good reason).
/// However, we need to be able to drop it in two scenarios:
///  - Integration tests, where we want to start up and shut down the CLI
///    multiple times.
///  - When the contract transitions in and out of the Running state (such as
///    for key resharing), we need to tear down the existing tasks (including
///    network) and restart with a new configuration. We need to ensure that
///    all existing tasks have terminated before starting the new configuration.
///    The only way to do that reliably is by dropping the runtime. If we cannot
///    drop the runtime in an async context, we'd have to rely on std::thread,
///    but that itself is difficult to deal with (mostly that we cannot easily
///    abort it and would have to rely on additional notifications).
///
/// Yes, this is an ugly workaround. But in our use case, the async task that
/// would be dropping a runtime is always on a thread that blocks on that task
/// and that task only.
pub struct AsyncDroppableRuntime(Option<tokio::runtime::Runtime>);

impl AsyncDroppableRuntime {
    pub fn new(runtime: tokio::runtime::Runtime) -> Self {
        Self(Some(runtime))
    }
}

impl Deref for AsyncDroppableRuntime {
    type Target = tokio::runtime::Runtime;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

impl Drop for AsyncDroppableRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            std::thread::scope(|s| {
                s.spawn(|| drop(runtime));
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use thread_priority::get_current_thread_priority;

    // Synchronous so the runtime is dropped outside an async context (dropping a
    // runtime inside one panics).
    #[cfg(target_os = "linux")]
    #[test]
    #[expect(non_snake_case)]
    fn build_lower_priority_runtime__should_start_worker_threads_at_min_priority() {
        // Given a runtime built by the lower-priority builder,
        let runtime = build_lower_priority_runtime(1, "test-lowprio").unwrap();

        // When we read the OS priority of one of its worker threads,
        let worker = runtime.spawn(async { get_current_thread_priority() });
        let worker_priority = runtime.block_on(worker).unwrap().unwrap();

        // ...and compare it to a thread explicitly lowered to the minimum,
        set_current_thread_priority(ThreadPriority::Min).unwrap();
        let min_priority = get_current_thread_priority().unwrap();

        // Then the worker thread runs at that same minimum priority.
        assert_eq!(worker_priority, min_priority);
    }
}
