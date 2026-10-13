use std::error::Error;
use std::marker::PhantomData;
use std::time::Duration;

use near_account_id::AccountId;
use near_kit::rpc::{BlockReference, Finality, RpcError, TxExecutionStatus};
use near_kit::transaction::WaitLevel;

use crate::{
    CallContract, FunctionCallArgs, HasPollInterval, ObservedState, PollInterval,
    SerializedObservation, ViewArgs, ViewContract,
};

/// [`near_kit::Near`] as a call and view backend. `T` is the wait level a call blocks on
/// before returning, which decides its [`CallContract::Output`] and the finality views read
/// at; `poll_interval` paces subscriptions and `read_timeout` bounds each view.
#[derive(Clone)]
pub struct NearKitCaller<T> {
    inner: near_kit::Near,
    poll_interval: PollInterval,
    read_timeout: Duration,
    _wait_level: PhantomData<fn() -> T>,
}

impl<T> NearKitCaller<T> {
    pub fn new(near: near_kit::Near, poll_interval: PollInterval, read_timeout: Duration) -> Self {
        Self {
            inner: near,
            poll_interval,
            read_timeout,
            _wait_level: PhantomData,
        }
    }

    pub fn with_wait_level<U: WaitLevel>(self) -> NearKitCaller<U> {
        NearKitCaller {
            inner: self.inner,
            poll_interval: self.poll_interval,
            read_timeout: self.read_timeout,
            _wait_level: PhantomData,
        }
    }
}

impl<T> HasPollInterval for NearKitCaller<T> {
    fn poll_interval(&self) -> PollInterval {
        self.poll_interval
    }
}

impl<T: WaitLevel> CallContract for NearKitCaller<T> {
    type Output = T::Response;
    type Error = NearKitCallError;

    async fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> Result<Self::Output, Self::Error> {
        self.inner
            .call(contract_id, &call_args.method_name)
            .args_raw(call_args.args)
            .gas(call_args.gas)
            .deposit(call_args.deposit)
            .finish()
            .wait_until::<T>()
            .await
            .map_err(Into::into)
    }
}

impl<T: WaitLevel> ViewContract for NearKitCaller<T> {
    type Error = NearKitViewError;

    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<SerializedObservation, Self::Error> {
        let view = self.inner.rpc().view_function(
            contract_id,
            &view_args.method_name,
            &view_args.args,
            BlockReference::Finality(view_finality::<T>()),
        );
        let result = tokio::time::timeout(self.read_timeout, view)
            .await
            .map_err(|_elapsed| NearKitViewError::Timeout(self.read_timeout))??;
        Ok(ObservedState {
            observed_at: result.block_height.into(),
            value: result.result,
        })
    }
}

/// Below [`TxExecutionStatus::Final`], a call returns before the blocks holding its effects
/// are final, so only an optimistic view is guaranteed to observe them.
fn view_finality<T: WaitLevel>() -> Finality {
    match T::STATUS {
        TxExecutionStatus::Final => Finality::Final,
        // Deliberately exhaustive. If near-kit adds a wait level, decide where it should read.
        TxExecutionStatus::None
        | TxExecutionStatus::Included
        | TxExecutionStatus::ExecutedOptimistic
        | TxExecutionStatus::IncludedFinal
        | TxExecutionStatus::Executed => Finality::Optimistic,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct NearKitCallError(String);

impl From<near_kit::Error> for NearKitCallError {
    fn from(err: near_kit::Error) -> Self {
        match err {
            near_kit::Error::Rpc(rpc) => Self(describe(&rpc)),
            other => Self(other.to_string()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NearKitViewError {
    /// [`RpcError`] is neither [`Clone`] nor [`PartialEq`], so only its rendering is kept.
    #[error("{0}")]
    Rpc(String),
    #[error("view did not finish within {0:?}")]
    Timeout(Duration),
}

impl From<RpcError> for NearKitViewError {
    fn from(err: RpcError) -> Self {
        Self::Rpc(describe(&err))
    }
}

/// `reqwest` writes the request url, which is where an api key lives, into both the
/// [`Display`](std::fmt::Display) and the [`Debug`] of its errors, so its own text is dropped
/// in favour of the causes below it, which do not know the url. Every other variant carries
/// text `near_kit` authored itself.
fn describe(err: &RpcError) -> String {
    match err {
        RpcError::Http(_) => match Error::source(err).and_then(Error::source) {
            Some(cause) => format!("http transport error: {cause:?}"),
            None => "http transport error".to_owned(),
        },
        _ => err.to_string(),
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::time::Duration;

    use near_kit::Near;
    use near_kit::signer::{InMemorySigner, SecretKey};
    use near_kit::transaction::Final;
    use rstest::rstest;
    use tokio::net::TcpListener;

    use crate::{CallContract, FunctionCallArgs, NearGas, PollInterval, ViewArgs, ViewContract};

    use super::{NearKitCaller, NearKitViewError};

    const API_KEY: &str = "d0n0tl0gme";
    const READ_TIMEOUT: Duration = Duration::from_millis(100);

    enum Operation {
        View,
        Call,
    }

    async fn must_make_caller_into_hung_up_keyed_endpoint() -> NearKitCaller<Final> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        let signer =
            InMemorySigner::from_secret_key("alice.near", SecretKey::ed25519_from_bytes([7u8; 32]))
                .unwrap();
        let near = Near::custom(
            format!("http://127.0.0.1:{port}/?apikey={API_KEY}"),
            "mainnet",
        )
        .signer(signer)
        .build();
        NearKitCaller::new(
            near,
            PollInterval::new(Duration::from_secs(1)).unwrap(),
            READ_TIMEOUT,
        )
    }

    #[rstest]
    #[case::view(Operation::View)]
    #[case::call(Operation::Call)]
    #[tokio::test]
    async fn near_kit_caller__should_not_report_the_api_key_of_a_failing_endpoint(
        #[case] operation: Operation,
    ) {
        // Given
        let caller = must_make_caller_into_hung_up_keyed_endpoint().await;
        let contract_id = "v1.signer".parse().unwrap();

        // When
        let (display, debug) = match operation {
            Operation::View => {
                let err = caller
                    .view_contract(&contract_id, ViewArgs::no_args("state"))
                    .await
                    .expect_err("a hung up endpoint should fail the view");
                (format!("{err}"), format!("{err:?}"))
            }
            Operation::Call => {
                let err = caller
                    .call_contract(
                        &contract_id,
                        FunctionCallArgs::no_deposit(
                            "state",
                            b"{}".to_vec(),
                            NearGas::from_tgas(1),
                        ),
                    )
                    .await
                    .expect_err("a hung up endpoint should fail the call");
                (format!("{err}"), format!("{err:?}"))
            }
        };

        // Then
        assert!(
            display.starts_with("http transport error"),
            "the failure should be the scrubbed http error: {display}"
        );
        assert!(
            !display.contains(API_KEY),
            "api key must not be rendered: {display}"
        );
        assert!(
            !debug.contains(API_KEY),
            "api key must not be rendered: {debug}"
        );
    }

    #[tokio::test]
    async fn view_contract__should_time_out_when_the_endpoint_never_answers() {
        // Given
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held_open = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held_open.push(stream);
            }
        });
        let caller = NearKitCaller::<Final>::new(
            Near::custom(format!("http://127.0.0.1:{port}"), "mainnet").build(),
            PollInterval::new(Duration::from_secs(1)).unwrap(),
            READ_TIMEOUT,
        );

        // When
        let err = caller
            .view_contract(&"v1.signer".parse().unwrap(), ViewArgs::no_args("state"))
            .await
            .expect_err("a silent endpoint should time out");

        // Then
        assert_eq!(err, NearKitViewError::Timeout(READ_TIMEOUT));
    }
}
