use futures::FutureExt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

pub enum MaybeReady<'a, T> {
    Ready(T),
    Future(Pin<Box<dyn Future<Output = T> + 'a>>),
}

/// Runs the future once, without allowing it to await for anything.
/// Returns either the result, or a future representing the remaining work.
pub fn run_future_once<'a, T>(future: impl Future<Output = T> + 'a) -> MaybeReady<'a, T> {
    let mut pinned = Box::pin(future);
    match pinned.poll_unpin(&mut Context::from_waker(futures::task::noop_waker_ref())) {
        Poll::Ready(output) => MaybeReady::Ready(output),
        Poll::Pending => MaybeReady::Future(pinned),
    }
}
