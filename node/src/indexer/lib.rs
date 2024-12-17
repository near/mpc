use actix::Addr;
use anyhow::bail;
use mpc_contract::ProtocolContractState;
use near_client::ClientActor;
use near_client::Status;
use near_indexer_primitives::types;
use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::types::TransactionOrReceiptId;
use near_indexer_primitives::views::ExecutionStatusView::SuccessReceiptId;
use near_indexer_primitives::views::ExecutionStatusView::SuccessValue;
use near_indexer_primitives::views::QueryRequest;
use near_indexer_primitives::views::QueryResponseKind::CallResult;
use near_indexer_primitives::CryptoHash;
use near_o11y::WithSpanContextExt;
use std::time::Duration;
use tokio::time;

const INTERVAL: Duration = Duration::from_millis(500);

pub(crate) async fn wait_for_full_sync(client: &Addr<ClientActor>) {
    loop {
        time::sleep(INTERVAL).await;

        let Ok(Ok(status)) = client
            .send(
                Status {
                    is_health_check: false,
                    detailed: false,
                }
                .with_span_context(),
            )
            .await
        else {
            continue;
        };

        if !status.sync_info.syncing {
            return;
        }
    }
}

pub(crate) async fn get_mpc_contract_state(
    mpc_contract_id: AccountId,
    client: &actix::Addr<near_client::ViewClientActor>,
) -> anyhow::Result<ProtocolContractState> {
    let request = QueryRequest::CallFunction {
        account_id: mpc_contract_id,
        method_name: "state".to_string(),
        args: vec![].into(),
    };
    let query = near_client::Query {
        block_reference: types::BlockReference::Finality(types::Finality::Final),
        request,
    };
    let response = client.send(query.with_span_context()).await??;

    match response.kind {
        CallResult(result) => Ok(serde_json::from_slice(&result.result)?),
        _ => {
            bail!("got unexpected response querying mpc contract state")
        }
    }
}

pub(crate) async fn wait_for_contract_code(
    contract_id: AccountId,
    client: &actix::Addr<near_client::ViewClientActor>,
) {
    loop {
        time::sleep(INTERVAL).await;
        if get_mpc_contract_state(contract_id.clone(), client)
            .await
            .is_ok()
        {
            return;
        }
    }
}

/* When a sign function call is made, the immediate execution outcome for the
 * receipt is another receipt id. To understand whether the signature has been
 * completed we have to descend into the receipts and look for a SuccessValue.
 * TODO(#100): Avoid making multiple queries to the view client here.
 */
pub(crate) async fn has_success_value(
    mut receipt_id: CryptoHash,
    receiver_id: AccountId,
    client: &actix::Addr<near_client::ViewClientActor>,
) -> anyhow::Result<bool> {
    loop {
        let query = near_client::GetExecutionOutcome {
            id: TransactionOrReceiptId::Receipt {
                receipt_id,
                receiver_id: receiver_id.clone(),
            },
        };
        // The client should respond
        let response = client.send(query.with_span_context()).await?;
        // But there may not be an execution outcome yet
        let Ok(execution_outcome) = response else {
            return Ok(false);
        };
        match execution_outcome.outcome_proof.outcome.status {
            SuccessReceiptId(id) => {
                receipt_id = id;
            }
            SuccessValue(_) => return Ok(true),
            _ => return Ok(false),
        }
    }
}
