use near_account_id::AccountId;

#[derive(Debug, Clone)]
pub(crate) struct ViewFunctionCall {
    pub(crate) account_id: AccountId,
    pub(crate) method_name: String,
    pub(crate) args: Vec<u8>,
}
