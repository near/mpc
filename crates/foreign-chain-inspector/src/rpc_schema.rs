pub(crate) mod bitcoin;
pub(crate) mod ethereum;

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
