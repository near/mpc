use derive_more::{Display, From, Into};
use serde::{Deserialize, Serialize};

pub use near_gas::NearGas;
pub use near_token::NearToken;

#[derive(Debug, Clone)]
pub struct FunctionCallArgs {
    pub method_name: String,
    pub args: Vec<u8>,
    pub gas: NearGas,
    pub deposit: NearToken,
}

impl FunctionCallArgs {
    pub fn new(
        method_name: impl Into<String>,
        args: Vec<u8>,
        gas: NearGas,
        deposit: NearToken,
    ) -> Self {
        Self {
            method_name: method_name.into(),
            args,
            gas,
            deposit,
        }
    }

    pub fn no_deposit(method_name: impl Into<String>, args: Vec<u8>, gas: NearGas) -> Self {
        Self::new(method_name, args, gas, NearToken::from_yoctonear(0))
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
