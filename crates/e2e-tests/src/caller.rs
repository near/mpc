use std::time::Duration;

use near_contract_transport::watch::Observed;
use near_kit::protocol::Action;
use near_kit::rpc::{BlockReference, Finality, RpcError, ViewFunctionResult};
use near_kit::transaction::ExecutedOptimistic;
use near_kit::{AccountId, Contract as _, ContractError, MaybeSend, SigningNear, TxSender, Viewer};
use near_mpc_contract_interface::contract::{MpcContract, MpcContractClient};
use tokio::sync::watch;

/// How often the tests poll contract views.
pub const VIEW_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// A client signed as one of the test's accounts.
pub type E2eClient = OptimisticReads<SigningNear<ExecutedOptimistic>>;

/// A polled contract view, see [`near_contract_transport::watch::Subscribe`].
pub type Watched<T> = watch::Receiver<Observed<T, ContractError<RpcError>>>;

/// Forwards to `C`, but every view reads at optimistic finality: a call returns once it has
/// executed optimistically, before the blocks holding its effects are final, so only an
/// optimistic view is guaranteed to observe them.
#[derive(Clone)]
pub struct OptimisticReads<C>(pub C);

impl<C: Viewer> Viewer for OptimisticReads<C> {
    type ViewError = C::ViewError;

    fn view_function(
        &self,
        contract_id: &AccountId,
        method: &str,
        args: &[u8],
        _block: BlockReference,
    ) -> impl Future<Output = Result<ViewFunctionResult, Self::ViewError>> + MaybeSend {
        self.0
            .view_function(contract_id, method, args, Finality::Optimistic.into())
    }
}

impl<C: TxSender> TxSender for OptimisticReads<C> {
    type Output = C::Output;
    type SendError = C::SendError;

    fn account_id(&self) -> &AccountId {
        self.0.account_id()
    }

    fn send(
        &self,
        receiver_id: AccountId,
        actions: Vec<Action>,
    ) -> impl Future<Output = Result<Self::Output, Self::SendError>> + MaybeSend {
        self.0.send(receiver_id, actions)
    }
}

pub trait CallMpc: Sized {
    fn call_mpc(self, contract_id: &AccountId) -> MpcContractClient<Self>;
}

impl CallMpc for E2eClient {
    fn call_mpc(self, contract_id: &AccountId) -> MpcContractClient<Self> {
        MpcContract::client(self, contract_id.clone())
    }
}
