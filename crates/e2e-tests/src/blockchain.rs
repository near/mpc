use std::time::Duration;

use ed25519_dalek::SigningKey;
use near_contract_transport::{CallContract, FunctionCallArgs};
use near_kit::{CryptoHash, ExecutedOptimistic, Final, FinalExecutionOutcome, Included};
use near_mpc_contract_interface::client::MpcContractHandle;
use near_mpc_contract_interface::types::ProtocolContractState;
use serde::de::DeserializeOwned;
use tokio::time::Instant;

use crate::conversions::ToNearKey;

const MAX_GAS: near_kit::Gas = near_kit::Gas::from_tgas(1000);
const TX_STATUS_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// RPC client for any NEAR network (sandbox or testnet).
///
/// Wraps `near_kit::Near` client signed as the root/funder account.
/// Whether the RPC URL points to a local Docker sandbox or NEAR testnet,
/// the code path is identical.
pub struct NearBlockchain {
    root_client: near_kit::Near,
    rpc_url: String,
}

/// A `near_kit::Near` client bound to a specific account: the e2e
/// [`CallContract`] backend.
///
/// By default a call waits exactly as long as near-kit does: nearcore's RPC polling
/// window, across near-kit's retries. A request that outlives that window — a `sign`
/// whose yield is still open — reports [`CallError::Deadline`] while remaining alive on
/// chain. Use [`WithTimeout::with_timeout`] to keep observing it instead.
pub struct NearKitCaller {
    inner: near_kit::Near,
    account_id: String,
    timeout: Option<Duration>,
}

impl NearKitCaller {
    /// Observe the outcome for up to `timeout` instead of for as long as the RPC waits.
    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self {
            timeout: Some(timeout),
            ..self
        }
    }
}

/// Wait a caller-chosen duration for a call's on-chain outcome.
pub trait WithTimeout: Sized {
    fn with_timeout(self, timeout: Duration) -> Self;
}

impl WithTimeout for MpcContractHandle<NearKitCaller> {
    fn with_timeout(self, timeout: Duration) -> Self {
        self.map_caller(|caller| caller.with_timeout(timeout))
    }
}

/// Failure of a call made through [`NearKitCaller`].
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error(transparent)]
    Rpc(near_kit::Error),

    /// The transaction is on chain but its outcome was still unresolved when we stopped
    /// waiting — typically a `sign` whose yield has not been answered. The call itself
    /// did not fail; widen the window with [`WithTimeout::with_timeout`].
    #[error("request still pending on chain after {after:?} (tx {tx:?})")]
    Deadline {
        tx: Option<CryptoHash>,
        after: Duration,
    },
}

impl CallContract for NearKitCaller {
    type Output = FinalExecutionOutcome;
    type Error = CallError;

    async fn call_contract(
        &self,
        contract_id: &near_kit::AccountId,
        call_args: FunctionCallArgs,
    ) -> Result<Self::Output, Self::Error> {
        let call = self
            .inner
            .call(contract_id, &call_args.method_name)
            .args_raw(call_args.args)
            .gas(call_args.gas)
            .deposit(call_args.deposit);

        let Some(timeout) = self.timeout else {
            let started = Instant::now();
            return call.send().await.map_err(|e| {
                if timed_out_waiting(&e) {
                    CallError::Deadline {
                        tx: None,
                        after: started.elapsed(),
                    }
                } else {
                    CallError::Rpc(e)
                }
            });
        };

        // Inclusion first, so the transaction is known to the RPC and the poll below
        // cannot race a not-yet-seen hash.
        let tx = call
            .wait_until::<Included>()
            .await
            .map_err(CallError::Rpc)?
            .transaction_hash;

        let poll = async {
            loop {
                match self
                    .inner
                    .tx_status(&tx, self.account_id.as_str())
                    .wait_until::<ExecutedOptimistic>()
                    .await
                {
                    Ok(outcome) => return Ok(outcome),
                    Err(e) if !is_retryable(&e) => return Err(CallError::Rpc(e)),
                    Err(_) => tokio::time::sleep(TX_STATUS_POLL_INTERVAL).await,
                }
            }
        };

        tokio::time::timeout(timeout, poll)
            .await
            .unwrap_or_else(|_| {
                Err(CallError::Deadline {
                    tx: Some(tx),
                    after: timeout,
                })
            })
    }
}

/// Transient RPC failures worth polling through. Retrying anything else would spin until
/// the deadline and then report its cause as a timeout.
fn is_retryable(error: &near_kit::Error) -> bool {
    matches!(error, near_kit::Error::Rpc(rpc) if rpc.is_retryable())
}

/// Distinguishes "the RPC stopped waiting" from "the call failed".
fn timed_out_waiting(error: &near_kit::Error) -> bool {
    match error {
        near_kit::Error::Rpc(rpc) => matches!(
            **rpc,
            near_kit::RpcError::Timeout(_) | near_kit::RpcError::RequestTimeout { .. }
        ),
        _ => false,
    }
}

impl NearBlockchain {
    pub fn new(
        rpc_url: &str,
        chain_id: &str,
        root_account: &str,
        root_secret_key: near_kit::SecretKey,
    ) -> anyhow::Result<Self> {
        let signer = near_kit::InMemorySigner::from_secret_key(root_account, root_secret_key)
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

    pub fn client_for(&self, account_id: &str, key: &SigningKey) -> anyhow::Result<NearKitCaller> {
        Ok(NearKitCaller {
            inner: self.make_client(account_id, key)?,
            account_id: account_id.to_string(),
            timeout: None,
        })
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    fn make_client(&self, account_id: &str, key: &SigningKey) -> anyhow::Result<near_kit::Near> {
        let sk = key.to_near_secret_key();
        let signer = near_kit::InMemorySigner::from_secret_key(account_id, sk)
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
    pub fn contract_id(&self) -> String {
        self.contract_id.to_string()
    }

    pub fn handle_for(&self, caller: NearKitCaller) -> MpcContractHandle<NearKitCaller> {
        MpcContractHandle::new(caller, self.contract_id.clone())
    }

    pub async fn call(
        &self,
        method: &str,
        args: serde_json::Value,
    ) -> anyhow::Result<FinalExecutionOutcome> {
        self.client
            .call(&self.contract_id, method)
            .args(args)
            .gas(MAX_GAS)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("contract call `{method}` failed: {e}"))
    }

    pub async fn call_from(
        &self,
        client: &NearKitCaller,
        method: &str,
        args: serde_json::Value,
    ) -> anyhow::Result<FinalExecutionOutcome> {
        client
            .inner
            .call(&self.contract_id, method)
            .args(args)
            .gas(MAX_GAS)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("contract call `{method}` (external signer) failed: {e}"))
    }

    pub async fn call_from_with_deposit(
        &self,
        client: &NearKitCaller,
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

    /// Like [`Self::call_from`], but with an attached `deposit`.
    pub async fn call_from_deposit(
        &self,
        client: &NearKitCaller,
        method: &str,
        args: serde_json::Value,
        deposit: near_kit::NearToken,
    ) -> anyhow::Result<FinalExecutionOutcome> {
        self.call_from_with_deposit(client, method, args, MAX_GAS, deposit)
            .await
    }

    /// Call a method whose arguments are borsh-serialized (e.g. `propose_update`).
    pub async fn call_from_borsh_with_deposit<A: borsh::BorshSerialize>(
        &self,
        client: &NearKitCaller,
        method: &str,
        args: A,
        gas: near_kit::Gas,
        deposit: near_kit::NearToken,
    ) -> anyhow::Result<FinalExecutionOutcome> {
        client
            .inner
            .call(&self.contract_id, method)
            .args_borsh(args)
            .gas(gas)
            .deposit(deposit)
            .send()
            .await
            .map_err(|e| {
                anyhow::anyhow!("contract call `{method}` (borsh args, with deposit) failed: {e}")
            })
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

    pub async fn view_borsh<T: borsh::BorshDeserialize + Send + 'static>(
        &self,
        method: &str,
    ) -> anyhow::Result<T> {
        self.client
            .view::<T>(&self.contract_id, method)
            .borsh()
            .await
            .map_err(|e| anyhow::anyhow!("contract view `{method}` failed: {e}"))
    }

    pub async fn state(&self) -> anyhow::Result<ProtocolContractState> {
        self.view("state").await
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
