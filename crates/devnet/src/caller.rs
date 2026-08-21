use std::marker::PhantomData;
use std::sync::Arc;

use crate::account::{OperatingAccessKey, OperatingAccount};
use crate::tx::SubmittedTx;
use near_contract_transport::{CallContract, FunctionCallArgs};
use near_jsonrpc_client::methods::tx::RpcTransactionResponse;
use near_mpc_contract_interface::client::MpcContractHandle;
use near_primitives::hash::CryptoHash;
use near_primitives::types::AccountId;
use near_primitives::views::TxExecutionStatus;
use tokio::sync::Mutex;

/// The status a submitted transaction is awaited to, and the response type that
/// status can produce. `send_tx` returns no execution outcome before
/// [`TxExecutionStatus::Executed`], so early levels surface the locally derived
/// transaction hash instead.
pub trait WaitLevel {
    type Response;

    const STATUS: TxExecutionStatus;

    fn response(
        tx_hash: CryptoHash,
        sender_id: &AccountId,
        response: RpcTransactionResponse,
    ) -> Self::Response;
}

pub struct Included;

impl WaitLevel for Included {
    type Response = SubmittedTx;

    const STATUS: TxExecutionStatus = TxExecutionStatus::Included;

    fn response(
        tx_hash: CryptoHash,
        sender_id: &AccountId,
        _response: RpcTransactionResponse,
    ) -> Self::Response {
        SubmittedTx {
            tx_hash,
            sender_id: sender_id.clone(),
        }
    }
}

pub struct Final;

impl WaitLevel for Final {
    type Response = RpcTransactionResponse;

    const STATUS: TxExecutionStatus = TxExecutionStatus::Final;

    fn response(
        _tx_hash: CryptoHash,
        _sender_id: &AccountId,
        response: RpcTransactionResponse,
    ) -> Self::Response {
        response
    }
}

pub(crate) trait CallMpcContract {
    fn call_mpc(&self, contract_id: &AccountId) -> MpcContractHandle<DevnetCaller<Final>>;
}

impl CallMpcContract for OperatingAccount {
    /// The returned handle logs each call and waits for transaction to be final
    fn call_mpc(&self, contract_id: &AccountId) -> MpcContractHandle<DevnetCaller<Final>> {
        MpcContractHandle::new(
            DevnetCaller::awaiting_final(self.any_access_key_handle(), Verbosity::Verbose),
            contract_id.clone(),
        )
    }
}

pub struct DevnetCaller<W> {
    key: Arc<Mutex<OperatingAccessKey>>,
    verbosity: Verbosity,
    _wait_level: PhantomData<fn() -> W>,
}

pub enum Verbosity {
    Verbose,
    Quiet,
}

impl DevnetCaller<Final> {
    pub(crate) fn awaiting_final(
        key: Arc<Mutex<OperatingAccessKey>>,
        verbosity: Verbosity,
    ) -> Self {
        Self {
            key,
            verbosity,
            _wait_level: PhantomData,
        }
    }
}

impl DevnetCaller<Included> {
    pub(crate) fn awaiting_inclusion(
        key: Arc<Mutex<OperatingAccessKey>>,
        verbosity: Verbosity,
    ) -> Self {
        Self {
            key,
            verbosity,
            _wait_level: PhantomData,
        }
    }
}

impl<W> DevnetCaller<W> {
    pub(crate) fn with_verbosity(self, verbosity: Verbosity) -> Self {
        Self { verbosity, ..self }
    }
}

pub trait WithVerbosity {
    fn with_verbosity(self, verbosity: Verbosity) -> Self;
}

impl<W> WithVerbosity for MpcContractHandle<DevnetCaller<W>> {
    fn with_verbosity(self, verbosity: Verbosity) -> Self {
        self.map_caller(|caller| caller.with_verbosity(verbosity))
    }
}

impl<W: WaitLevel> CallContract for DevnetCaller<W> {
    type Output = W::Response;
    type Error = anyhow::Error;

    async fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> Result<Self::Output, Self::Error> {
        self.key
            .lock()
            .await
            .submit_tx_to_call_function::<W>(
                contract_id,
                &call_args.method_name,
                &call_args.args,
                call_args.gas.as_tgas(),
                call_args.deposit.as_yoctonear(),
                matches!(self.verbosity, Verbosity::Verbose),
            )
            .await
    }
}
