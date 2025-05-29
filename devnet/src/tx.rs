use near_jsonrpc_client::methods::{self, tx::RpcTransactionResponse};
use near_primitives::{transaction::SignedTransaction, views::TxExecutionStatus};
use std::{fmt::Debug, sync::Arc};

use crate::rpc::NearRpcClients;

pub async fn submit_tx_to_client(
    client: Arc<NearRpcClients>,
    signed_transaction: SignedTransaction,
    wait_until: TxExecutionStatus,
) -> anyhow::Result<RpcTransactionResponse> {
    let request = methods::send_tx::RpcSendTransactionRequest {
        signed_transaction,
        wait_until,
    };
    Ok(client.submit(request).await?)
}

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
                            "Transaction failed: {:?}",
                            tx_execution_error
                        ))
                    }
                    near_primitives::views::FinalExecutionStatus::SuccessValue(value) => Ok(value),
                    _ => Err(anyhow::anyhow!("Transaction failed: {:?}", outcome.status)),
                }
            }
            Err(e) => Err(anyhow::anyhow!("Transaction failed: {:?}", e)),
        }
    }
}
