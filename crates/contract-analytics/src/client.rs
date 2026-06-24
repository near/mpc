use anyhow::{Context, Result, bail};
use near_jsonrpc_client::{JsonRpcClient, methods::query::RpcQueryRequest};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::{
    types::{AccountId, BlockReference, Finality, FunctionArgs},
    views::QueryRequest,
};

pub struct Client {
    rpc: JsonRpcClient,
    contract_id: AccountId,
}

impl Client {
    pub fn new(rpc_url: &str, contract_id: AccountId) -> Self {
        Self {
            rpc: JsonRpcClient::connect(rpc_url),
            contract_id,
        }
    }

    pub fn contract_id(&self) -> &AccountId {
        &self.contract_id
    }

    pub async fn view_call(&self, method_name: &str, args: Vec<u8>) -> Result<Vec<u8>> {
        let request = RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::CallFunction {
                account_id: self.contract_id.clone(),
                method_name: method_name.to_string(),
                args: FunctionArgs::from(args),
            },
        };
        let response = self
            .rpc
            .call(request)
            .await
            .with_context(|| format!("RPC call to `{method_name}` failed"))?;
        match response.kind {
            QueryResponseKind::CallResult(r) => Ok(r.result),
            other => bail!("unexpected response kind from `{method_name}`: {other:?}"),
        }
    }
}
