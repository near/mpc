use actix::Addr;
use anyhow::bail;
use mpc_contract::state::ProtocolContractState;
use near_client::ClientActor;
use near_client::Status;
use near_indexer_primitives::types;
use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::views::QueryRequest;
use near_indexer_primitives::views::QueryResponseKind::CallResult;
use near_o11y::WithSpanContextExt;
use std::time::Duration;
use std::time::Instant;
use tokio::time;

const INTERVAL: Duration = Duration::from_millis(500);
const LOG_INTERVAL: Duration = Duration::from_secs(5);

pub(crate) async fn wait_for_full_sync(client: &Addr<ClientActor>) {
    let mut last_log_instant = Instant::now();
    let sync_start_time = Instant::now();
    loop {
        let now = Instant::now();
        let duration_since_last_log = now.duration_since(last_log_instant);

        if duration_since_last_log > LOG_INTERVAL {
            let syncing_wait_time = now.duration_since(sync_start_time);
            tracing::info!(
                "MPC INDEXER HAS BEEN WAITING FOR SYNC FOR: {:?}",
                syncing_wait_time
            );
            last_log_instant = Instant::now();
        }

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
) -> anyhow::Result<(u64, ProtocolContractState)> {
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
        CallResult(result) => Ok((
            response.block_height,
            serde_json::from_slice(&result.result)?,
        )),
        _ => {
            bail!("got unexpected response querying mpc contract state")
        }
    }
}
