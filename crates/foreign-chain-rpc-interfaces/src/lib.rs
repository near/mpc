use jsonrpsee::core::traits::ToRpcParams;
use serde::Serialize;

pub mod aptos;
pub mod bitcoin;
pub mod evm;
pub mod starknet;
pub mod sui;

// Helper macro to implement ToRpcParams for types that implement serde::Serialize.
macro_rules! to_rpc_params_impl {
    () => {
        fn to_rpc_params(
            self,
        ) -> Result<Option<Box<serde_json::value::RawValue>>, serde_json::Error> {
            let json = serde_json::value::to_raw_value(&self)?;
            Ok(Some(json))
        }
    };
}

pub(crate) use to_rpc_params_impl;

/// Argument list for RPC methods that take no arguments, e.g. `eth_chainId`.
///
/// Serializes to an explicit `[]` rather than omitting `params` altogether — some providers
/// reject a request without the field.
pub struct NoParams;

impl Serialize for NoParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let no_parameters: [(); 0] = [];
        no_parameters.serialize(serializer)
    }
}

impl ToRpcParams for &NoParams {
    to_rpc_params_impl!();
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn serialize_no_params__should_produce_an_empty_array() {
        // Given / When
        let serialized = serde_json::to_value(NoParams).unwrap();

        // Then
        assert_eq!(serialized, serde_json::json!([]));
    }
}
