use derive_more::{From, Into};
use near_indexer_primitives::CryptoHash;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::errors::ChainGatewayError;

/// An empty argument struct for contract view calls that take no arguments.
#[derive(Serialize)]
pub struct NoArgs {}

#[derive(
    Into, From, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug,
)]
pub struct BlockHeight(u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedState<T = Vec<u8>> {
    pub observed_at: BlockHeight,
    pub value: T,
}

/// block height and block hash
pub type LatestFinalBlockInfo = ObservedState<CryptoHash>;

impl ObservedState<Vec<u8>> {
    pub fn deserialize<Res: DeserializeOwned>(
        self,
    ) -> Result<ObservedState<Res>, ChainGatewayError> {
        let value = serde_json::from_slice::<Res>(&self.value).map_err(|err| {
            ChainGatewayError::Deserialization {
                message: err.to_string(),
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
    use assert_matches::assert_matches;
    use serde::Deserialize;

    use crate::{
        errors::ChainGatewayError,
        types::{NoArgs, ObservedState},
    };

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Num {
        a: u32,
    }

    #[test]
    fn test_deserialize_ok() {
        let observed = ObservedState {
            observed_at: 7.into(),
            value: br#"{"a":1}"#.to_vec(),
        };

        let typed: ObservedState<Num> = observed.deserialize().unwrap();

        assert_eq!(typed.observed_at, 7.into());
        assert_eq!(typed.value, Num { a: 1 });
    }

    #[test]
    fn test_deserialize_err() {
        let observed = ObservedState {
            observed_at: 7.into(),
            value: b"not json".to_vec(),
        };

        let err = observed.deserialize::<Num>().unwrap_err();
        assert_matches!(err, ChainGatewayError::Deserialization { .. });
    }

    #[test]
    fn test_no_args_serializes_to_empty_json_object() {
        let json = serde_json::to_string(&NoArgs {}).unwrap();
        assert_eq!(json, "{}");
    }
}
