use ed25519_dalek::SigningKey;
use std::time::Duration;

use near_contract_transport::{
    CallContract, FunctionCallArgs, NearGas, NearKitCaller, PollInterval,
};
use near_kit::SigningNear;
use near_kit::protocol::Action;
use near_kit::rpc::{FinalExecutionOutcome, Finality};
use near_kit::transaction::{ExecutedOptimistic, Final};

use crate::conversions::ToNearKey;

const MAX_GAS: NearGas = NearGas::from_tgas(1000);
const VIEW_POLL_INTERVAL: Duration = Duration::from_millis(500);
const VIEW_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// RPC client for any NEAR network (sandbox or testnet).
///
/// Wraps a [`near_kit::SigningNear`] client signed as the root/funder account.
/// Whether the RPC URL points to a local Docker sandbox or NEAR testnet,
/// the code path is identical.
pub struct NearBlockchain {
    root_client: SigningNear,
    rpc_url: String,
}

impl NearBlockchain {
    pub fn new(
        rpc_url: &str,
        chain_id: &str,
        root_account: &str,
        root_secret_key: near_kit::signer::SecretKey,
    ) -> anyhow::Result<Self> {
        let signer =
            near_kit::signer::InMemorySigner::new(parse_account_id(root_account)?, root_secret_key);
        let client = near_kit::Near::custom(rpc_url, chain_id)
            .build()
            .with_signer(signer);
        Ok(Self {
            root_client: client,
            rpc_url: rpc_url.to_string(),
        })
    }

    pub async fn create_account_with_keys(
        &self,
        name: &str,
        balance_near: u128,
        keys: &[SigningKey],
    ) -> anyhow::Result<()> {
        let mut tx = self
            .root_client
            .transaction(parse_account_id(name)?)
            .add_action(Action::create_account())
            .add_action(Action::transfer(near_kit::NearToken::from_near(
                balance_near,
            )));

        for key in keys {
            tx = tx.add_action(Action::add_full_access_key(key.to_near_public_key()));
        }

        tx.await
            .and_then(|outcome| Ok(outcome.result()?))
            .map_err(|e| anyhow::anyhow!("failed to create account {name}: {e}"))?;
        Ok(())
    }

    pub async fn create_account_and_deploy(
        &self,
        name: &str,
        balance_near: u128,
        key: &SigningKey,
        wasm: &[u8],
    ) -> anyhow::Result<DeployedContract> {
        self.root_client
            .transaction(parse_account_id(name)?)
            .add_action(Action::create_account())
            .add_action(Action::transfer(near_kit::NearToken::from_near(
                balance_near,
            )))
            .add_action(Action::add_full_access_key(key.to_near_public_key()))
            .add_action(Action::deploy_contract(wasm))
            .await
            .and_then(|outcome| Ok(outcome.result()?))
            .map_err(|e| anyhow::anyhow!("failed to create account and deploy to {name}: {e}"))?;

        let client = self.make_client(name, key)?;
        Ok(DeployedContract {
            client,
            contract_id: name.parse().unwrap(),
        })
    }

    pub async fn delete_access_key(
        &self,
        account_id: &str,
        signer_key: &SigningKey,
        key_to_delete: near_kit::signer::PublicKey,
    ) -> anyhow::Result<()> {
        let client = self
            .make_client(account_id, signer_key)?
            .wait_until::<Final>();
        let outcome = client
            .transaction(parse_account_id(account_id)?)
            .add_action(Action::delete_key(key_to_delete))
            .await
            .map_err(|e| anyhow::anyhow!("failed to delete access key on {account_id}: {e}"))?;
        anyhow::ensure!(
            !outcome.is_failure(),
            "deleting an access key on {account_id} failed"
        );
        Ok(())
    }

    pub fn client_for(
        &self,
        account_id: &str,
        key: &SigningKey,
    ) -> anyhow::Result<NearKitCaller<SigningNear<ExecutedOptimistic>>> {
        let poll_interval = PollInterval::new(VIEW_POLL_INTERVAL).expect("non-zero");
        Ok(NearKitCaller::new(
            self.make_client(account_id, key)?,
            poll_interval,
            VIEW_READ_TIMEOUT,
        ))
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    fn make_client(
        &self,
        account_id: &str,
        key: &SigningKey,
    ) -> anyhow::Result<SigningNear<ExecutedOptimistic>> {
        let signer = near_kit::signer::InMemorySigner::new(
            parse_account_id(account_id)?,
            key.to_near_secret_key(),
        );
        Ok(self
            .root_client
            .with_signer(signer)
            .wait_until::<ExecutedOptimistic>())
    }
}

fn parse_account_id(account_id: &str) -> anyhow::Result<near_kit::AccountId> {
    account_id
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid account id {account_id}: {e}"))
}

/// Handle to a deployed MPC signer contract.
pub struct DeployedContract {
    client: SigningNear<ExecutedOptimistic>,
    contract_id: near_account_id::AccountId,
}

impl DeployedContract {
    pub fn account_id(&self) -> &near_account_id::AccountId {
        &self.contract_id
    }

    pub fn client(&self) -> NearKitCaller<SigningNear<ExecutedOptimistic>> {
        let poll_interval = PollInterval::new(VIEW_POLL_INTERVAL).expect("non-zero");
        NearKitCaller::new(self.client.clone(), poll_interval, VIEW_READ_TIMEOUT)
    }

    pub async fn call(
        &self,
        method: &str,
        args: serde_json::Value,
    ) -> anyhow::Result<FinalExecutionOutcome> {
        let call_args = FunctionCallArgs::no_deposit(method, serde_json::to_vec(&args)?, MAX_GAS);
        self.client()
            .call_contract(&self.contract_id, call_args)
            .await
            .map_err(|e| anyhow::anyhow!("contract call `{method}` failed: {e}"))
    }

    /// SHA-256 hash of the contract code currently deployed at this account.
    pub async fn code_hash(&self) -> anyhow::Result<near_kit::CryptoHash> {
        let view = self
            .client
            .near()
            .rpc()
            .view_account(&self.contract_id, Finality::Final)
            .await
            .map_err(|e| anyhow::anyhow!("view_account for `{}` failed: {e}", self.contract_id))?;
        Ok(view.code_hash)
    }
}
