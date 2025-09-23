use anyhow::Context;
use attestation::attestation::Attestation;
use ed25519_dalek::VerifyingKey;

use crate::{
    indexer::{
        tx_sender::TransactionSender,
        types::{ChainSendTransactionRequest, SubmitParticipantInfoArgs},
    },
    trait_extensions::convert_to_contract_dto::IntoDtoType,
};

pub async fn submit_remote_attestation(
    tx_sender: impl TransactionSender,
    attestation: Attestation,
    tls_public_key: VerifyingKey,
) -> anyhow::Result<()> {
    let propose_join_args = SubmitParticipantInfoArgs {
        proposed_participant_attestation: attestation.into_dto_type(),
        tls_public_key: tls_public_key.into_dto_type(),
    };

    tx_sender
        .send(ChainSendTransactionRequest::SubmitParticipantInfo(
            Box::new(propose_join_args),
        ))
        .await
        .context("Failed to send remote attestation transaction. Channel is closed.")
}
