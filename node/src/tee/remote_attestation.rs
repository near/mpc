use anyhow::Context;
use attestation::attestation::Attestation;
use ed25519_dalek::VerifyingKey;
use tokio::sync::mpsc;

use crate::{
    indexer::types::{ChainSendTransactionRequest, SubmitParticipantInfoArgs},
    providers::PublicKeyConversion,
};

pub async fn submit_remote_attestation(
    tx_sender: mpsc::Sender<ChainSendTransactionRequest>,
    report_data_contract: Attestation,
    account_public_key: VerifyingKey,
) -> anyhow::Result<()> {
    let near_sdk_public_key = account_public_key.to_near_sdk_public_key()?;

    let propose_join_args = SubmitParticipantInfoArgs {
        proposed_tee_participant: report_data_contract,
        sign_pk: near_sdk_public_key,
    };

    tx_sender
        .send(ChainSendTransactionRequest::SubmitParticipantInfo(
            Box::new(propose_join_args),
        ))
        .await
        .context("Failed to send remote attestation transaction. Channel is closed.")
}
