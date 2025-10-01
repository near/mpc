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
        _transaction: ChainSendTransactionRequest,
    ) -> Result<TransactionStatus, TransactionProcessorError> {
        unimplemented!()
    }
}
