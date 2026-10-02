use ed25519_dalek::SigningKey;
use std::time::Duration;

use near_contract_transport::{
    CallContract, FunctionCallArgs, NearGas, NearKitCaller, NearToken, PollInterval,
};
use near_kit::rpc::FinalExecutionOutcome;
use near_kit::transaction::{ExecutedOptimistic, Final, WaitLevel};
use near_mpc_contract_interface::client::MpcContractHandle;
use near_mpc_contract_interface::types::ProtocolContractState;

use crate::conversions::ToNearKey;

const MAX_GAS: NearGas = NearGas::from_tgas(1000);
const VIEW_POLL_INTERVAL: Duration = Duration::from_millis(500);
const VIEW_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// RPC client for any NEAR network (sandbox or testnet).
///
/// Wraps [`near_kit::Near`] client signed as the root/funder account.
/// Whether the RPC URL points to a local Docker sandbox or NEAR testnet,
/// the code path is identical.
pub struct NearBlockchain {
    root_client: near_kit::Near,
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
            near_kit::signer::InMemorySigner::from_secret_key(root_account, root_secret_key)
                .map_err(|e| anyhow::anyhow!("failed to create root signer: {e}"))?;
        let client = near_kit::Near::custom(rpc_url, chain_id)
            .signer(signer)
            .build();
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
            .transaction(name)
            .create_account()
            .transfer(near_kit::NearToken::from_near(balance_near));

        for key in keys {
            tx = tx.add_full_access_key(key.to_near_public_key());
        }

        tx.wait_until::<Final>()
            .await
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
            .transaction(name)
            .create_account()
            .transfer(near_kit::NearToken::from_near(balance_near))
            .add_full_access_key(key.to_near_public_key())
            .deploy(wasm.to_vec())
            .wait_until::<Final>()
            .await
            .map_err(|e| anyhow::anyhow!("failed to create account and deploy to {name}: {e}"))?;

        let client = self.make_client(name, key)?;
        Ok(DeployedContract {
            client,
            contract_id: name.parse().unwrap(),
        })
    }

    pub fn client_for(
        &self,
        account_id: &str,
        key: &SigningKey,
    ) -> anyhow::Result<NearKitCaller<ExecutedOptimistic>> {
        Ok(near_kit_caller(self.make_client(account_id, key)?))
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    fn make_client(&self, account_id: &str, key: &SigningKey) -> anyhow::Result<near_kit::Near> {
        let sk = key.to_near_secret_key();
        let signer = near_kit::signer::InMemorySigner::from_secret_key(account_id, sk)
            .map_err(|e| anyhow::anyhow!("failed to create signer for {account_id}: {e}"))?;
        Ok(self.root_client.with_signer(signer))
    }
}

/// Handle to a deployed MPC signer contract.
pub struct DeployedContract {
    client: near_kit::Near,
    contract_id: near_account_id::AccountId,
}

impl DeployedContract {
    pub fn account_id(&self) -> &near_account_id::AccountId {
        &self.contract_id
    }

    pub fn client(&self) -> NearKitCaller<ExecutedOptimistic> {
        near_kit_caller(self.client.clone())
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

    pub async fn call_from_with_deposit<T: WaitLevel>(
        &self,
        client: &NearKitCaller<T>,
        method: &str,
        args: serde_json::Value,
        gas: NearGas,
        deposit: NearToken,
    ) -> anyhow::Result<T::Response> {
        let call_args = FunctionCallArgs::new(method, serde_json::to_vec(&args)?, gas, deposit);
        client
            .call_contract(&self.contract_id, call_args)
            .await
            .map_err(|e| anyhow::anyhow!("contract call `{method}` (with deposit) failed: {e}"))
    }

    pub fn view_mpc(&self) -> MpcContractHandle<NearKitCaller<ExecutedOptimistic>> {
        MpcContractHandle::new(self.client(), self.contract_id.clone())
    }

    pub async fn state(&self) -> anyhow::Result<ProtocolContractState> {
        Ok(self.view_mpc().state().await?.value)
    }

    /// SHA-256 hash of the contract code currently deployed at this account.
    pub async fn code_hash(&self) -> anyhow::Result<near_kit::CryptoHash> {
        let view = self
            .client
            .account(self.contract_id.as_str())
            .await
            .map_err(|e| anyhow::anyhow!("view_account for `{}` failed: {e}", self.contract_id))?;
        Ok(view.code_hash)
    }
}

fn near_kit_caller(near: near_kit::Near) -> NearKitCaller<ExecutedOptimistic> {
    let poll_interval = PollInterval::new(VIEW_POLL_INTERVAL).expect("non-zero");
    NearKitCaller::new(near, poll_interval, VIEW_READ_TIMEOUT)
}
