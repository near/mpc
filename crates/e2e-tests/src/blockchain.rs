use anyhow::Context;
use ed25519_dalek::SigningKey;
use near_kit::FinalExecutionOutcome;
use near_mpc_contract_interface::types::ProtocolContractState;
use serde::de::DeserializeOwned;

/// RPC client for any NEAR network (sandbox or testnet).
///
/// Wraps a `near_kit::Near` client signed as the root/funder account.
/// Whether the RPC URL points to a local Docker sandbox or NEAR testnet,
/// the code path is identical.
pub struct NearBlockchain {
    root_client: near_kit::Near,
    rpc_url: String,
}

pub struct ClientHandle {
    inner: near_kit::Near,
}

impl NearBlockchain {
    pub fn new(rpc_url: &str, root_account: &str, root_secret_key: &str) -> anyhow::Result<Self> {
        let sk: near_kit::SecretKey = root_secret_key.parse().context("invalid root secret key")?;
        let signer = near_kit::InMemorySigner::from_secret_key(root_account, sk)
            .map_err(|e| anyhow::anyhow!("failed to create root signer: {e}"))?;
        let client = near_kit::Near::custom(rpc_url).signer(signer).build();
        Ok(Self {
            root_client: client,
            rpc_url: rpc_url.to_string(),
        })
    }

    pub async fn create_account(
        &self,
        name: &str,
        balance_near: u64,
        key: &SigningKey,
    ) -> anyhow::Result<()> {
        let pubkey = dalek_to_near_pubkey(key)?;
        self.root_client
            .transaction(name)
            .create_account()
            .transfer(near_kit::NearToken::from_near(balance_near as u128))
            .add_full_access_key(pubkey)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("failed to create account {name}: {e}"))?;
        Ok(())
    }

    pub async fn create_account_and_deploy(
        &self,
        name: &str,
        balance_near: u64,
        key: &SigningKey,
        wasm: &[u8],
    ) -> anyhow::Result<DeployedContract> {
        let pubkey = dalek_to_near_pubkey(key)?;
        self.root_client
            .transaction(name)
            .create_account()
            .transfer(near_kit::NearToken::from_near(balance_near as u128))
            .add_full_access_key(pubkey)
            .deploy(wasm.to_vec())
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("failed to create account and deploy to {name}: {e}"))?;

        let client = self.make_client(name, key)?;
        Ok(DeployedContract {
            client,
            contract_id: name.to_string(),
        })
    }

    pub fn client_for(&self, account_id: &str, key: &SigningKey) -> anyhow::Result<ClientHandle> {
        Ok(ClientHandle {
            inner: self.make_client(account_id, key)?,
        })
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    fn make_client(&self, account_id: &str, key: &SigningKey) -> anyhow::Result<near_kit::Near> {
        let sk = dalek_to_near_secret_key(key)?;
        let signer = near_kit::InMemorySigner::from_secret_key(account_id, sk)
            .map_err(|e| anyhow::anyhow!("failed to create signer for {account_id}: {e}"))?;
        Ok(self.root_client.with_signer(signer))
    }
}

/// Handle to a deployed MPC signer contract.
pub struct DeployedContract {
    client: near_kit::Near,
    contract_id: String,
}

impl DeployedContract {
    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    pub async fn call(&self, method: &str, args: serde_json::Value) -> anyhow::Result<()> {
        self.client
            .call(&self.contract_id, method)
            .args(args)
            .gas(near_kit::Gas::from_tgas(300))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("contract call `{method}` failed: {e}"))?;
        Ok(())
    }

    pub async fn call_from(
        &self,
        client: &ClientHandle,
        method: &str,
        args: serde_json::Value,
    ) -> anyhow::Result<()> {
        client
            .inner
            .call(&self.contract_id, method)
            .args(args)
            .gas(near_kit::Gas::from_tgas(300))
            .send()
            .await
            .map_err(|e| {
                anyhow::anyhow!("contract call `{method}` (external signer) failed: {e}")
            })?;
        Ok(())
    }

    pub async fn call_from_with_deposit(
        &self,
        client: &ClientHandle,
        method: &str,
        args: serde_json::Value,
        gas: near_kit::Gas,
        deposit: near_kit::NearToken,
    ) -> anyhow::Result<FinalExecutionOutcome> {
        client
            .inner
            .call(&self.contract_id, method)
            .args(args)
            .gas(gas)
            .deposit(deposit)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("contract call `{method}` (with deposit) failed: {e}"))
    }

    pub async fn view<T: DeserializeOwned + Send + 'static>(
        &self,
        method: &str,
    ) -> anyhow::Result<T> {
        self.client
            .view::<T>(&self.contract_id, method)
            .await
            .map_err(|e| anyhow::anyhow!("contract view `{method}` failed: {e}"))
    }

    pub async fn state(&self) -> anyhow::Result<ProtocolContractState> {
        self.view("state").await
    }
}

fn dalek_to_near_pubkey(key: &SigningKey) -> anyhow::Result<near_kit::PublicKey> {
    let s = format!(
        "ed25519:{}",
        bs58::encode(key.verifying_key().to_bytes()).into_string()
    );
    s.parse().context("failed to parse NEAR public key")
}

fn dalek_to_near_secret_key(key: &SigningKey) -> anyhow::Result<near_kit::SecretKey> {
    let s = format!(
        "ed25519:{}",
        bs58::encode(key.to_keypair_bytes()).into_string()
    );
    s.parse().context("failed to parse NEAR secret key")
}
