//! The payload of a NEAR function call, shared across the MPC stack.

pub use near_gas::NearGas;
pub use near_token::NearToken;

/// A NEAR `FunctionCallAction` payload: method name, encoded args, gas, and deposit.
#[derive(Debug, Clone)]
pub struct FunctionCallArgs {
    pub method_name: String,
    pub args: Vec<u8>,
    pub gas: NearGas,
    pub deposit: NearToken,
}
