use near_contract_transport::NearGas;

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
pub const SET_VALUE_GAS: NearGas = NearGas::from_tgas(5);
pub const PRIVATE_SET_ARGS_GAS: NearGas = NearGas::from_tgas(5);
pub const SET_VALUE_IN_PROMISE_GAS: NearGas = NearGas::from_tgas(10);
pub const SPAWN_PROMISE_WITH_CALLBACK_GAS: NearGas = NearGas::from_tgas(20);
