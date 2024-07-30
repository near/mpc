mod actions;
mod cases;

use crate::actions::wait_for;

use anyhow::anyhow;
use futures::future::BoxFuture;
use integration_tests_chain_signatures::containers::DockerClient;
use integration_tests_chain_signatures::utils::{vote_join, vote_leave};
use integration_tests_chain_signatures::{run, utils, MultichainConfig, Nodes};
use near_jsonrpc_client::JsonRpcClient;

use near_workspaces::types::SecretKey;
use near_workspaces::{Account, AccountId};

use integration_tests_chain_signatures::local::NodeConfig;
use std::str::FromStr;

pub struct MultichainTestContext<'a> {
    nodes: Nodes<'a>,
    rpc_client: near_fetch::Client,
    jsonrpc_client: JsonRpcClient,
    http_client: reqwest::Client,
    cfg: MultichainConfig,
}

impl MultichainTestContext<'_> {
    pub async fn participant_accounts(&self) -> anyhow::Result<Vec<Account>> {
        let node_accounts: Vec<Account> = self.nodes.near_accounts();
        let state = wait_for::running_mpc(self, None).await?;
        let participant_ids = state.participants.keys().collect::<Vec<_>>();
        let participant_accounts: Vec<Account> = participant_ids
            .iter()
            .map(|id| near_workspaces::types::AccountId::from_str(id.as_ref()).unwrap())
            .map(|id| {
                node_accounts
                    .iter()
                    .find(|a| a.id() == &id)
                    .unwrap()
                    .clone()
            })
            .collect();
        Ok(participant_accounts)
    }

    pub async fn add_participant(
        &mut self,
        existing_node: Option<NodeConfig>,
    ) -> anyhow::Result<()> {
        let state = wait_for::running_mpc(self, None).await?;
        let account_id: AccountId;
        let sk: SecretKey;
        let new_node_account: Account;

        if let Some(node_cfg) = existing_node {
            account_id = node_cfg.account_id;
            sk = node_cfg.account_sk;
            tracing::info!("Adding an existing participant: {}", account_id);
        } else {
            new_node_account = self.nodes.ctx().worker.dev_create_account().await?;
            account_id = new_node_account.id().clone();
            sk = new_node_account.secret_key().clone();
            tracing::info!("Adding a new participant: {}", account_id);
        }

        self.nodes.start_node(&account_id, &sk, &self.cfg).await?;

        // Wait for new node to add itself as a candidate
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // T number of participants should vote
        let participants = self.participant_accounts().await?;
        let voting_participants = participants
            .iter()
            .take(state.threshold)
            .cloned()
            .collect::<Vec<_>>();
        assert!(vote_join(
            voting_participants,
            self.nodes.ctx().mpc_contract.id(),
            &account_id,
        )
        .await
        .is_ok());

        let new_state = wait_for::running_mpc(self, Some(state.epoch + 1)).await?;
        assert_eq!(new_state.participants.len(), state.participants.len() + 1);
        assert_eq!(
            state.public_key, new_state.public_key,
            "public key must stay the same"
        );

        Ok(())
    }

    pub async fn remove_participant(
        &mut self,
        leaving_account_id: Option<&AccountId>,
    ) -> anyhow::Result<NodeConfig> {
        let state = wait_for::running_mpc(self, None).await?;
        let participant_accounts = self.participant_accounts().await?;
        let leaving_account_id =
            leaving_account_id.unwrap_or_else(|| participant_accounts.last().unwrap().id());
        tracing::info!("Removing participant: {}", leaving_account_id);

        let voting_accounts = participant_accounts
            .iter()
            .filter(|account| account.id() != leaving_account_id)
            .take(state.threshold)
            .cloned()
            .collect::<Vec<Account>>();

        tracing::info!("Removing vote from: {:?}", voting_accounts);
        let results = vote_leave(
            voting_accounts.clone(),
            self.nodes.ctx().mpc_contract.id(),
            leaving_account_id,
        )
        .await;
        // Check if any result has failures, and return early with an error if so
        if results
            .iter()
            .any(|result| !result.as_ref().unwrap().failures().is_empty())
        {
            tracing::error!("Failed vote from: {:?}", voting_accounts);
            return Err(anyhow!("Failed to vote_leave"));
        }

        let new_state = wait_for::running_mpc(self, Some(state.epoch + 1)).await?;
        tracing::info!(
            "Getting new state, old {} {:?}, new {} {:?}",
            state.participants.len(),
            state.public_key,
            new_state.participants.len(),
            new_state.public_key
        );

        assert_eq!(state.participants.len(), new_state.participants.len() + 1);

        assert_eq!(
            state.public_key, new_state.public_key,
            "public key must stay the same"
        );

        Ok(self.nodes.kill_node(leaving_account_id).await.unwrap())
    }
}

pub async fn with_multichain_nodes<F>(cfg: MultichainConfig, f: F) -> anyhow::Result<()>
where
    F: for<'a> FnOnce(MultichainTestContext<'a>) -> BoxFuture<'a, anyhow::Result<()>>,
{
    let docker_client = DockerClient::default();
    let nodes = run(cfg.clone(), &docker_client).await?;

    let sk_local_path = nodes.ctx().storage_options.sk_share_local_path.clone();

    let connector = JsonRpcClient::new_client();
    let jsonrpc_client = connector.connect(&nodes.ctx().lake_indexer.rpc_host_address);
    let rpc_client = near_fetch::Client::from_client(jsonrpc_client.clone());
    let result = f(MultichainTestContext {
        nodes,
        rpc_client,
        jsonrpc_client,
        http_client: reqwest::Client::default(),
        cfg,
    })
    .await;
    utils::clear_local_sk_shares(sk_local_path).await?;

    result
}
