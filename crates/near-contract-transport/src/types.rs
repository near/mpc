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
