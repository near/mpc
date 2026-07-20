use derive_more::{Display, From, Into};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub use near_gas::NearGas;
pub use near_token::NearToken;

#[derive(Debug, Clone)]
pub struct FunctionCallArgs {
    pub method_name: String,
    pub args: Vec<u8>,
    pub gas: NearGas,
    pub deposit: NearToken,
}

#[derive(Debug, Clone)]
pub struct ViewArgs {
    pub method_name: String,
    pub args: Vec<u8>,
}

impl ViewArgs {
    pub fn new(method_name: impl Into<String>, args: Vec<u8>) -> Self {
        Self {
            method_name: method_name.into(),
            args,
        }
    }

    /// A view call taking no arguments (an empty JSON object).
    pub fn no_args(method_name: impl Into<String>) -> Self {
        Self::new(method_name, b"{}".to_vec())
    }
}

#[derive(
    Into, From, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Display,
)]
pub struct BlockHeight(u64);

impl BlockHeight {
    pub fn saturating_add(self, delta: u64) -> Self {
        BlockHeight(self.0.saturating_add(delta))
    }
    pub fn saturating_sub(self, delta: u64) -> Self {
        BlockHeight(self.0.saturating_sub(delta))
    }
    /// Block distance from `earlier` to `self`. Saturates to `0` if `earlier > self`.
    pub fn blocks_since(self, earlier: BlockHeight) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// A value read from a contract together with the height it was observed at.
/// `H` is the backend's height witness: [`BlockHeight`] where the backend
/// reports one, `()` where it cannot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedState<T = Vec<u8>, H = BlockHeight> {
    pub observed_at: H,
    pub value: T,
}

impl<H> ObservedState<Vec<u8>, H> {
    pub fn deserialize<Res: DeserializeOwned>(
        self,
    ) -> Result<ObservedState<Res, H>, serde_json::Error> {
        Ok(ObservedState {
            observed_at: self.observed_at,
            value: serde_json::from_slice(&self.value)?,
        })
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{ObservedState, ViewArgs};
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Num {
        a: u32,
    }

    #[test]
    fn no_args__should_encode_an_empty_json_object() {
        assert_eq!(ViewArgs::no_args("m").args, b"{}");
    }

    #[test]
    fn observed_state__should_deserialize_json_values() {
        let observed: ObservedState = ObservedState {
            observed_at: 7.into(),
            value: br#"{"a":1}"#.to_vec(),
        };

        let typed: ObservedState<Num> = observed.deserialize().unwrap();

        assert_eq!(typed.observed_at, 7.into());
        assert_eq!(typed.value, Num { a: 1 });
    }

    #[test]
    fn observed_state__should_fail_on_invalid_json() {
        let observed: ObservedState = ObservedState {
            observed_at: 7.into(),
            value: b"not json".to_vec(),
        };

        observed.deserialize::<Num>().unwrap_err();
    }
}
