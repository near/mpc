use crate::args::TeraGas;

pub const DEFAULT_VALUE: &str = "hello from test";

/* Method names */
// public view method
pub const VIEW_VALUE: &str = "view_value";
// public set method
pub const SET_VALUE: &str = "set_value";
// private method for setting value
pub const PRIVATE_SET: &str = "private_set";
// spawn a promise to set the value
pub const SET_VALUE_IN_PROMISE: &str = "set_value_in_promise";
// spawns a promise to set the value and spawns a callback promise to set the value
pub const SPAWN_PROMISE_WITH_CALLBACK: &str = "spawn_promise_with_callback";

/* Gas constants */
// teragas as u64. We don't use near_sdk::Gas on purpose, such that the near indexer can re-use
// these constants without depending on near_sdk.
pub const FIVE_TGAS: TeraGas = TeraGas(5);
pub const SET_VALUE_GAS: TeraGas = FIVE_TGAS;
pub const PRIVATE_SET_ARGS_GAS: TeraGas = SET_VALUE_GAS;
pub const SET_VALUE_IN_PROMISE_GAS: TeraGas = SET_VALUE_GAS.const_add(FIVE_TGAS);
pub const SPAWN_PROMISE_WITH_CALLBACK_GAS: TeraGas = SET_VALUE_IN_PROMISE_GAS
    .const_add(SET_VALUE_GAS)
    .const_add(FIVE_TGAS);
