use crate::errors::ChainGatewayError;
use crate::near_internals_wrapper::BlockHeight;
use crate::near_internals_wrapper::ViewOutput;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use std::sync::Arc;

#[async_trait]
pub trait ContractStateStream<Res> {
    /// Returns the last value observed on chain and the block height at which it last changed.
    fn latest(&mut self) -> Result<ObservedState<Res>, ChainGatewayError>;
    /// Waits until the observed value changes.
    async fn changed(&mut self) -> Result<(), ChainGatewayError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedState<Res> {
    pub last_changed: BlockHeight,
    pub value: Res,
}

pub type ObservedChainState = ObservedState<Vec<u8>>;

impl ObservedState<Vec<u8>> {
    pub fn deserialize<Res: DeserializeOwned>(
        self,
    ) -> Result<ObservedState<Res>, ChainGatewayError> {
        let value = serde_json::from_slice::<Res>(&self.value).map_err(|err| {
            ChainGatewayError::Deserialization {
                source: Arc::new(err),
            }
        })?;
        Ok(ObservedState {
            last_changed: self.last_changed,
            value,
        })
    }
}

impl From<ViewOutput> for ObservedChainState {
    fn from(value: ViewOutput) -> Self {
        Self {
            last_changed: value.observed_at,
            value: value.value,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use crate::{
        errors::ChainGatewayError,
        near_internals_wrapper::ViewOutput,
        state_viewer::subscription_trait::{ObservedChainState, ObservedState},
    };

    #[test]
    fn test_from_viewoutput_to_observed_chain_state() {
        let vo = ViewOutput {
            observed_at: 42.into(),
            value: vec![1, 2, 3, 4],
        };

        let observed: ObservedChainState = vo.into();

        assert_eq!(observed.last_changed, 42.into());
        assert_eq!(observed.value, vec![1, 2, 3, 4]);
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct T {
        a: u32,
    }

    #[test]
    fn test_deserialize_ok() {
        let observed = ObservedChainState {
            last_changed: 7.into(),
            value: br#"{"a":1}"#.to_vec(),
        };

        let typed: ObservedState<T> = observed.deserialize().unwrap();

        assert_eq!(typed.last_changed, 7.into());
        assert_eq!(typed.value, T { a: 1 });
    }

    #[test]
    fn test_deserialize_err() {
        let observed = ObservedChainState {
            last_changed: 7.into(),
            value: b"not json".to_vec(),
        };

        let err = observed.deserialize::<T>().unwrap_err();

        assert!(matches!(err, ChainGatewayError::Deserialization { .. }));
    }
}
