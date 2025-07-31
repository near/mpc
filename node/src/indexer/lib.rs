use actix::Addr;
use anyhow::bail;
use mpc_contract::state::ProtocolContractState;
use near_client::ClientActor;
use near_client::Status;
use near_indexer_primitives::types;
use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::views::QueryRequest;
use near_indexer_primitives::views::QueryResponseKind::{CallResult, ViewAccount};
use near_o11y::WithSpanContextExt;
use serde::Deserialize;
use std::time::Duration;
use tokio::time;

#[cfg(feature = "tee")]
use mpc_contract::tee::proposal::AllowedDockerImageHashes;

const INTERVAL: Duration = Duration::from_millis(500);
#[cfg(feature = "tee")]
const ALLOWED_IMAGE_HASHES_ENDPOINT: &str = "allowed_docker_image_hashes";
const CONTRACT_STATE_ENDPOINT: &str = "state";

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

pub(crate) async fn get_mpc_state<State>(
    mpc_contract_id: AccountId,
    client: &actix::Addr<near_client::ViewClientActor>,
    endpoint: &str,
) -> anyhow::Result<(u64, State)>
where
    State: for<'de> Deserialize<'de>,
{
    let request = QueryRequest::CallFunction {
        account_id: mpc_contract_id,
        method_name: endpoint.to_string(),
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

pub(crate) async fn get_mpc_contract_state(
    mpc_contract_id: AccountId,
    client: &actix::Addr<near_client::ViewClientActor>,
) -> anyhow::Result<(u64, ProtocolContractState)> {
    get_mpc_state(mpc_contract_id, client, CONTRACT_STATE_ENDPOINT).await
}

#[cfg(feature = "tee")]
pub(crate) async fn get_mpc_allowed_image_hashes(
    mpc_contract_id: AccountId,
    client: &actix::Addr<near_client::ViewClientActor>,
) -> anyhow::Result<(u64, AllowedDockerImageHashes)> {
    get_mpc_state(mpc_contract_id, client, ALLOWED_IMAGE_HASHES_ENDPOINT).await
}

pub(crate) async fn get_account_balance(
    account_id: AccountId,
    client: &actix::Addr<near_client::ViewClientActor>,
) -> anyhow::Result<(u64, f64)> {
    tracing::info!("fetching account balance for {}", account_id);
    let request = QueryRequest::ViewAccount { account_id };
    let query = near_client::Query {
        block_reference: types::BlockReference::Finality(types::Finality::Final),
        request,
    };
    let response = client.send(query.with_span_context()).await??;
    match response.kind {
        ViewAccount(result) => {
            const YOCTO_PER_NEAR: u128 = 10u128.pow(24);
            let whole = (result.amount / YOCTO_PER_NEAR) as f64;
            let fraction = (result.amount % YOCTO_PER_NEAR) as f64 / YOCTO_PER_NEAR as f64;
            let balance = whole + fraction;
            Ok((response.block_height, balance))
        }
        _ => {
            tracing::warn!("got unexpected response querying account balance");
            anyhow::bail!("got unexpected response querying account balance")
        }
    }
}
