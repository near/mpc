use mpc_primitives::domain::DomainId;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainPurpose, Protocol, ReconstructionThreshold,
};
use tokio::sync::mpsc;

use crate::indexer::{
    tx_sender::{TransactionProcessorError, TransactionSender, TransactionStatus},
    types::ChainSendTransactionRequest,
};

/// Builds a signing `DomainConfig` for `protocol` with reconstruction threshold `t`.
pub fn sign_domain(id: u64, protocol: Protocol, t: u64) -> DomainConfig {
    DomainConfig {
        id: DomainId(id),
        protocol,
        reconstruction_threshold: ReconstructionThreshold::new(t),
        purpose: DomainPurpose::Sign,
    }
}

/// Builds a `ConfidentialKeyDerivation` (CKD) `DomainConfig` with reconstruction threshold `t`.
pub fn ckd_domain(id: u64, t: u64) -> DomainConfig {
    DomainConfig {
        id: DomainId(id),
        protocol: Protocol::ConfidentialKeyDerivation,
        reconstruction_threshold: ReconstructionThreshold::new(t),
        purpose: DomainPurpose::CKD,
    }
}

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
