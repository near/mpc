use std::ops::Deref;

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
