use std::future::Future;
use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder};
use tokio::sync::watch;

const MIN_BACKOFF_DURATION: Duration = Duration::from_secs(1);
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);

/// Retries `fetch` with exponential backoff until it succeeds, logging each failure.
pub(crate) async fn fetch_with_retry<T, Fetch, FetchFuture>(fetch: Fetch, error_context: &str) -> T
where
    Fetch: Fn() -> FetchFuture,
    FetchFuture: Future<Output = anyhow::Result<T>>,
{
    let mut backoff = ExponentialBuilder::default()
        .with_min_delay(MIN_BACKOFF_DURATION)
        .with_max_delay(MAX_BACKOFF_DURATION)
        .without_max_times()
        .with_jitter()
        .build();

    loop {
        match fetch().await {
            Ok(value) => return value,
            Err(e) => {
                log_fetch_error(error_context, &e);
                let backoff_duration = backoff.next().unwrap_or(MAX_BACKOFF_DURATION);
                tokio::time::sleep(backoff_duration).await;
            }
        }
    }
}

/// The deployed contract may predate the queried method; `MethodNotFound` is expected then.
fn log_fetch_error(error_context: &str, e: &anyhow::Error) {
    let error_msg = format!("{:?}", e);
    if error_msg.contains("wasm execution failed with error: MethodResolveError(MethodNotFound)") {
        tracing::info!(target: "mpc", "method not found in contract: {error_msg}");
    } else {
        tracing::error!(target: "mpc", "{error_context}: {error_msg}");
    }
}

pub(crate) fn publish_if_changed<T: PartialEq>(sender: &watch::Sender<T>, value: T) -> bool {
    sender.send_if_modified(|previous| {
        if *previous == value {
            false
        } else {
            *previous = value;
            true
        }
    })
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[tokio::test(start_paused = true)]
    async fn fetch_with_retry__should_keep_retrying_until_fetch_succeeds() {
        // Given: a fetch that fails twice before succeeding.
        let attempts = Cell::new(0);
        let fetch = || {
            let attempt = attempts.get() + 1;
            attempts.set(attempt);
            async move {
                if attempt < 3 {
                    anyhow::bail!("rpc unavailable");
                }
                Ok(attempt)
            }
        };

        // When
        let value = fetch_with_retry(fetch, "test").await;

        // Then
        assert_eq!(value, 3);
    }

    #[test]
    fn publish_if_changed__should_publish_a_changed_value() {
        // Given
        let (sender, receiver) = watch::channel(0);

        // When
        let published = publish_if_changed(&sender, 1);

        // Then
        assert!(published);
        assert_eq!(*receiver.borrow(), 1);
    }

    #[test]
    fn publish_if_changed__should_not_publish_an_unchanged_value() {
        // Given
        let (sender, mut receiver) = watch::channel(1);
        receiver.mark_unchanged();

        // When
        let published = publish_if_changed(&sender, 1);

        // Then
        assert!(!published);
        assert!(!receiver.has_changed().unwrap());
    }
}
