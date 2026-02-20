use near_account_id::AccountId;
use std::fmt;

#[derive(Debug, Clone)]
pub(crate) struct ViewFunctionCall {
    pub(crate) account_id: AccountId,
    pub(crate) method_name: String,
    pub(crate) args: Vec<u8>,
}

// for dispaly, we only print the argument length, not the actual vector
impl fmt::Display for ViewFunctionCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "view function call {}.{} (args_len={})",
            self.account_id,
            self.method_name,
            self.args.len()
        )
    }
}

impl From<&ViewFunctionCall> for near_indexer_primitives::views::QueryRequest {
    fn from(value: &ViewFunctionCall) -> Self {
        near_indexer_primitives::views::QueryRequest::CallFunction {
            account_id: value.account_id.clone(),
            method_name: value.method_name.to_string(),
            args: value.args.clone().into(),
        }
    }
}
