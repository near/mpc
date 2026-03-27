use ed25519_dalek::SigningKey;
use near_mpc_contract_interface::types::ProtocolContractState;
use serde::de::DeserializeOwned;

pub struct NearBlockchain {
    _rpc_url: String,
}

pub struct ClientHandle {
    _private: (),
}

impl NearBlockchain {
    pub fn new(
        _rpc_url: &str,
        _root_account: &str,
        _root_secret_key: &str,
    ) -> anyhow::Result<Self> {
        unimplemented!("NEAR RPC client implementation — see Change 2")
    }

    pub async fn create_account(
        &self,
        _name: &str,
        _balance_near: u64,
        _key: &SigningKey,
    ) -> anyhow::Result<()> {
        unimplemented!()
    }

    pub async fn create_account_and_deploy(
        &self,
        _name: &str,
        _balance_near: u64,
        _key: &SigningKey,
        _wasm: &[u8],
    ) -> anyhow::Result<DeployedContract> {
        unimplemented!()
    }

    pub fn client_for(&self, _account_id: &str, _key: &SigningKey) -> anyhow::Result<ClientHandle> {
        unimplemented!()
    }

    pub fn rpc_url(&self) -> &str {
        unimplemented!()
    }
}

pub struct DeployedContract {
    contract_id: String,
}

impl DeployedContract {
    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    pub async fn call(&self, _method: &str, _args: serde_json::Value) -> anyhow::Result<()> {
        unimplemented!()
    }

    pub async fn call_from(
        &self,
        _client: &ClientHandle,
        _method: &str,
        _args: serde_json::Value,
    ) -> anyhow::Result<()> {
        unimplemented!()
    }

    pub async fn view<T: DeserializeOwned + Send + 'static>(
        &self,
        _method: &str,
    ) -> anyhow::Result<T> {
        unimplemented!()
    }

    pub async fn state(&self) -> anyhow::Result<ProtocolContractState> {
        self.view("state").await
    }
}
