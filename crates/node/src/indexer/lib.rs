use actix::Addr;
use anyhow::bail;
use mpc_contract::state::ProtocolContractState;
use mpc_contract::tee::proposal::LauncherDockerComposeHash;
use mpc_contract::tee::proposal::MpcDockerImageHash;
use mpc_contract::tee::tee_state::NodeId;
use near_client::ClientActor;
use near_client::Status;
use near_indexer_primitives::types;
use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::views::QueryRequest;
use near_indexer_primitives::views::QueryResponseKind::CallResult;
use near_o11y::WithSpanContextExt;
use serde::Deserialize;
use std::time::Duration;
use tokio::time;

use super::migrations::ContractMigrationInfo;

const INTERVAL: Duration = Duration::from_millis(500);
const ALLOWED_IMAGE_HASHES_ENDPOINT: &str = "allowed_docker_image_hashes";
const ALLOWED_LAUNCHER_COMPOSE_HASHES_ENDPOINT: &str = "allowed_launcher_compose_hashes";
const TEE_ACCOUNTS_ENDPOINT: &str = "get_tee_accounts";
pub const MIGRATION_INFO_ENDPOINT: &str = "migration_info";
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

pub(crate) async fn get_mpc_allowed_image_hashes(
    mpc_contract_id: AccountId,
    client: actix::Addr<near_client::ViewClientActor>,
) -> anyhow::Result<(u64, Vec<MpcDockerImageHash>)> {
    get_mpc_state(mpc_contract_id, &client, ALLOWED_IMAGE_HASHES_ENDPOINT).await
}

pub(crate) async fn get_mpc_allowed_launcher_compose_hashes(
    mpc_contract_id: AccountId,
    client: actix::Addr<near_client::ViewClientActor>,
) -> anyhow::Result<(u64, Vec<LauncherDockerComposeHash>)> {
    get_mpc_state(
        mpc_contract_id,
        &client,
        ALLOWED_LAUNCHER_COMPOSE_HASHES_ENDPOINT,
    )
    .await
}

pub(crate) async fn get_mpc_tee_accounts(
    mpc_contract_id: AccountId,
    client: &actix::Addr<near_client::ViewClientActor>,
) -> anyhow::Result<(u64, Vec<NodeId>)> {
    get_mpc_state(mpc_contract_id, client, TEE_ACCOUNTS_ENDPOINT).await
}

pub(crate) async fn get_mpc_migration_info(
    mpc_contract_id: AccountId,
    client: &actix::Addr<near_client::ViewClientActor>,
) -> anyhow::Result<(u64, ContractMigrationInfo)> {
    get_mpc_state(mpc_contract_id, client, MIGRATION_INFO_ENDPOINT).await
}
