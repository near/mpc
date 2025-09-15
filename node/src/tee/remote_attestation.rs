use anyhow::Context;
use attestation::attestation::Attestation;

use crate::indexer::{
    tx_sender::TransactionSender,
    types::{ChainSendTransactionRequest, SubmitParticipantInfoArgs},
};

pub async fn submit_remote_attestation(
    tx_sender: impl TransactionSender,
    attestation: Attestation,
    tls_public_key: near_sdk::PublicKey,
) -> anyhow::Result<()> {
    let propose_join_args = SubmitParticipantInfoArgs {
        proposed_participant_attestation: attestation,
        tls_public_key,
    };

    tx_sender
        .send(ChainSendTransactionRequest::SubmitParticipantInfo(
            Box::new(propose_join_args),
        ))
        .await
        .context("Failed to send remote attestation transaction. Channel is closed.")
}
