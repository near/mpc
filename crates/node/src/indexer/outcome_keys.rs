use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder};
use near_contract_transport::ViewContract;
use near_mpc_contract_interface::client::MpcContractHandle;
use near_mpc_contract_interface::types as dtos;
use tokio::sync::watch;

use super::foreign_chain::send_if_changed;

const OUTCOME_KEYS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const MIN_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY: Duration = Duration::from_mins(1);

/// Reads the outcome keys once, then keeps them updated in the background. A failed read keeps
/// the previous keys. A failed first read starts with no keys instead of waiting, so a contract
/// that predates outcome keys does not delay the node's start.
pub async fn monitor_outcome_keys<V: ViewContract + Clone + Send + Sync + 'static>(
    contract: MpcContractHandle<V>,
) -> watch::Receiver<dtos::OutcomeKeys> {
    let first_read = read_outcome_keys(&contract, false).await;
    let mut previous_read_failed = first_read.is_none();
    let (sender, receiver) = watch::channel(first_read.unwrap_or_default());
    tokio::spawn(async move {
        let mut delay = OUTCOME_KEYS_REFRESH_INTERVAL;
        let mut retry_delays = retry_backoff().build();
        loop {
            tokio::time::sleep(delay).await;
            let read = read_outcome_keys(&contract, previous_read_failed).await;
            previous_read_failed = read.is_none();
            delay = match read {
                Some(latest) => {
                    send_if_changed(&sender, latest);
                    retry_delays = retry_backoff().build();
                    OUTCOME_KEYS_REFRESH_INTERVAL
                }
                None => retry_delays.next().unwrap_or(MAX_RETRY_DELAY),
            };
        }
    });
    receiver
}

fn retry_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(MIN_RETRY_DELAY)
        .with_max_delay(MAX_RETRY_DELAY)
        .without_max_times()
}

/// Logs a failure at debug level while the previous read failed too.
async fn read_outcome_keys<V: ViewContract + Clone + Send + 'static>(
    contract: &MpcContractHandle<V>,
    previous_read_failed: bool,
) -> Option<dtos::OutcomeKeys> {
    match contract.outcome_keys().await {
        Ok(observed) => Some(observed.value),
        Err(error) if previous_read_failed => {
            tracing::debug!(target: "mpc", ?error, "failed to read the outcome keys from the contract again");
            None
        }
        Err(error) => {
            tracing::warn!(target: "mpc", ?error, "failed to read the outcome keys from the contract");
            None
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::collections::BTreeMap;

    use near_contract_transport::mock::{MockViewContract, MockViewError};
    use near_contract_transport::{ObservedState, SerializedObservation};

    use super::*;

    fn observed(value: &impl serde::Serialize) -> Result<SerializedObservation, MockViewError> {
        Ok(ObservedState {
            observed_at: 0.into(),
            value: serde_json::to_vec(value).unwrap(),
        })
    }

    fn contract(viewer: &MockViewContract) -> MpcContractHandle<MockViewContract> {
        MpcContractHandle::new(viewer.clone(), "mpc.near".parse().unwrap())
    }

    fn outcome_keys(seed: u8) -> dtos::OutcomeKeys {
        BTreeMap::from([(
            "node.near".parse().unwrap(),
            dtos::Ed25519PublicKey::from([seed; 32]),
        )])
        .into()
    }

    #[tokio::test]
    async fn monitor_outcome_keys__should_publish_the_keys_the_contract_returns() {
        // Given
        let viewer = MockViewContract::new(observed(&outcome_keys(1)));

        // When
        let keys = monitor_outcome_keys(contract(&viewer)).await;

        // Then
        assert_eq!(*keys.borrow(), outcome_keys(1));
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_outcome_keys__should_start_without_keys_when_the_contract_has_none_to_read() {
        // Given
        let viewer = MockViewContract::new(Err(MockViewError("method not found")));

        // When
        let keys = monitor_outcome_keys(contract(&viewer)).await;

        // Then
        assert_eq!(*keys.borrow(), dtos::OutcomeKeys::default());
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_outcome_keys__should_publish_changed_keys() {
        // Given
        let viewer = MockViewContract::new(observed(&outcome_keys(1)));
        let mut keys = monitor_outcome_keys(contract(&viewer)).await;
        keys.mark_unchanged();

        // When
        viewer.set_response(observed(&outcome_keys(2)));
        tokio::time::timeout(Duration::from_mins(1), keys.changed())
            .await
            .unwrap()
            .unwrap();

        // Then
        assert_eq!(*keys.borrow(), outcome_keys(2));
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_outcome_keys__should_publish_the_keys_once_the_contract_can_be_read() {
        // Given
        let viewer = MockViewContract::new(Err(MockViewError("method not found")));
        let mut keys = monitor_outcome_keys(contract(&viewer)).await;

        // When
        viewer.set_response(observed(&outcome_keys(1)));
        tokio::time::timeout(MAX_RETRY_DELAY * 2, keys.changed())
            .await
            .unwrap()
            .unwrap();

        // Then
        assert_eq!(*keys.borrow(), outcome_keys(1));
    }
}
