use tokio::sync::mpsc;

use crate::indexer::{
    tx_sender::{TransactionProcessorError, TransactionSender, TransactionStatus},
    types::ChainSendTransactionRequest,
};

#[derive(Debug, Clone)]
pub struct MockTransactionSender {
    pub transaction_sender: mpsc::Sender<ChainSendTransactionRequest>,
}

impl TransactionSender for MockTransactionSender {
    async fn send(
        &self,
        transaction: ChainSendTransactionRequest,
    ) -> Result<(), TransactionProcessorError> {
        self.transaction_sender
            .send(transaction)
            .await
            .map_err(|_| TransactionProcessorError::ProcessorIsClosed)
    }

    async fn send_and_wait(
        &self,
        transaction: ChainSendTransactionRequest,
    ) -> Result<TransactionStatus, TransactionProcessorError> {
        // Forward to `send` so the test still observes the transaction on the
        // `transaction_sender` channel, then report it as `Executed`. This is
        // enough for callers like `submit_remote_attestation` that gate on
        // `Executed` vs `NotExecuted` rather than the actual on-chain effect.
        self.send(transaction).await?;
        Ok(TransactionStatus::Executed)
    }
}
