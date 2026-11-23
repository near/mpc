use near_mpc_contract_interface::{
    call_args::SubmitParticipantInfoArgs,
    types::{Attestation, Ed25519PublicKey},
};
use tee_context::SubmitAttestation;

use crate::indexer::{tx_sender::TransactionSender, types::ChainSendTransactionRequest};

#[derive(Clone)]
pub(crate) struct SubmitParticipantInfo<T>(pub T);

impl<T: TransactionSender> SubmitAttestation for SubmitParticipantInfo<T> {
    async fn submit(
        &self,
        attestation: Attestation,
        tls_public_key: Ed25519PublicKey,
    ) -> anyhow::Result<()> {
        let args = Box::new(SubmitParticipantInfoArgs::new(attestation, tls_public_key));
        Ok(self
            .0
            .send(ChainSendTransactionRequest::SubmitParticipantInfo(args))
            .await?)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::tests::common::MockTransactionSender;
    use near_mpc_contract_interface::types::MockAttestation;
    use std::assert_matches;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn submit_participant_info__should_send_the_attestation_as_participant_info() {
        // Given
        let (transaction_sender, mut sent_transactions) = mpsc::channel(1);
        let submitter = SubmitParticipantInfo(MockTransactionSender { transaction_sender });
        let attestation = Attestation::Mock(MockAttestation::Valid);
        let tls_public_key = Ed25519PublicKey([1; 32]);

        // When
        submitter
            .submit(attestation.clone(), tls_public_key.clone())
            .await
            .unwrap();

        // Then
        assert_matches!(
            sent_transactions.recv().await,
            Some(ChainSendTransactionRequest::SubmitParticipantInfo(args))
                if *args == SubmitParticipantInfoArgs::new(attestation, tls_public_key)
        );
    }
}
