use std::sync::Arc;

use derive_more::{From, Into};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::errors::ChainGatewayError;

#[derive(
    Into, From, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug,
)]
pub struct BlockHeight(u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedState<T = Vec<u8>> {
    pub observed_at: BlockHeight,
    pub value: T,
}

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
            observed_at: self.observed_at,
            value,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use crate::{errors::ChainGatewayError, types::ObservedState};

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct T {
        a: u32,
    }

    #[test]
    fn test_deserialize_ok() {
        let observed = ObservedState {
            observed_at: 7.into(),
            value: br#"{"a":1}"#.to_vec(),
        };

        let typed: ObservedState<T> = observed.deserialize().unwrap();

        assert_eq!(typed.observed_at, 7.into());
        assert_eq!(typed.value, T { a: 1 });
    }

    #[test]
    fn test_deserialize_err() {
        let observed = ObservedState {
            observed_at: 7.into(),
            value: b"not json".to_vec(),
        };

        let err = observed.deserialize::<T>().unwrap_err();

        assert!(matches!(err, ChainGatewayError::Deserialization { .. }));
    }
}
