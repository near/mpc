use near_jsonrpc_client::methods::tx::RpcTransactionResponse;
use std::fmt::Debug;

pub trait IntoReturnValueExt {
    /// Converts the RPC call result to a return value, or error if the result is anything else.
    fn into_return_value(self) -> anyhow::Result<Vec<u8>>;
}

impl<E: Debug> IntoReturnValueExt for Result<RpcTransactionResponse, E> {
    fn into_return_value(self) -> anyhow::Result<Vec<u8>> {
        match self {
            Ok(tx_response) => {
                let Some(outcome) = tx_response.final_execution_outcome else {
                    return Err(anyhow::anyhow!("Final execution outcome not found"));
                };
                let outcome = outcome.into_outcome();
                match outcome.status {
                    near_primitives::views::FinalExecutionStatus::Failure(tx_execution_error) => {
                        Err(anyhow::anyhow!(
                            "Transaction failed: {tx_execution_error:?}"
                        ))
                    }
                    near_primitives::views::FinalExecutionStatus::SuccessValue(value) => Ok(value),
                    _ => Err(anyhow::anyhow!("Transaction failed: {:?}", outcome.status)),
                }
            }
            Err(e) => Err(anyhow::anyhow!("Transaction failed: {e:?}")),
        }
    }
}
