pub(super) mod accounts;
pub(super) mod localnet;
pub(super) mod node;

use chain_gateway::ChainGateway;
use chain_gateway::transaction_sender::{GatewaySender, SentTransaction};
use near_kit_primitives::TxSender;
use near_kit_primitives::signer::InMemorySigner;
use near_kit_primitives::transaction::FunctionCall;

/// Sends `call` to `receiver_id` from `signer`'s account through `gateway`.
pub(super) async fn send(
    gateway: &ChainGateway,
    signer: &InMemorySigner,
    receiver_id: near_account_id::AccountId,
    call: FunctionCall,
) -> SentTransaction {
    GatewaySender::new(gateway.clone(), signer.clone())
        .send(receiver_id, vec![call.into_action().unwrap()])
        .await
        .unwrap()
}
