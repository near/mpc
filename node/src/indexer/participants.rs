use crate::indexer::lib::{get_mpc_contract_state, wait_for_contract_code, wait_for_full_sync};
use mpc_contract::{primitives::Participants, ProtocolContractState};
use near_indexer_primitives::types::AccountId;
use tokio::sync::mpsc;

pub(crate) async fn read_participants_from_chain(
    mpc_contract_id: AccountId,
    view_client: actix::Addr<near_client::ViewClientActor>,
    client: actix::Addr<near_client::ClientActor>,
    sender: mpsc::Sender<Participants>,
) {
    // Currently we assume the set of participants is static.
    // We wait first to catch up to the chain to avoid reading
    // the participants from an outdated state.
    wait_for_full_sync(&client).await;

    // In tests it is possible to catch up to the chain before the
    // contract is even deployed.
    wait_for_contract_code(mpc_contract_id.clone(), &view_client).await;

    let state = match get_mpc_contract_state(mpc_contract_id.clone(), &view_client).await {
        Ok(state) => state,
        Err(err) => {
            tracing::warn!(target: "mpc", %err, "error getting mpc contract state from account {:?}", mpc_contract_id);
            return;
        }
    };

    let ProtocolContractState::Running(state) = state else {
        tracing::warn!(target: "mpc", "mpc contract is not in a Running state");
        return;
    };

    let _ = sender.send(state.participants).await;
}
