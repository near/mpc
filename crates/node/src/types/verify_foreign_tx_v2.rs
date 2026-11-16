use chain_gateway::event_subscriber::block_events::BlockContext;
use mpc_primitives::domain::DomainId;
use near_contract_transport::BlockHeight;
use near_indexer_primitives::CryptoHash;
use near_mpc_contract_interface::types as dtos;

use crate::indexer::handler::VerifyForeignTxRequestV2FromChain;
use crate::types::{FromChain, Request, RequestId, RequestType, VerifyForeignTxId};

/// A V2 foreign transaction request, as the node queues and answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyForeignTxRequestV2 {
    /// The receipt id of the request's yield callback.
    pub id: VerifyForeignTxId,
    /// The receipt that made the request.
    pub receipt_id: CryptoHash,
    pub yield_id: dtos::YieldId,
    /// The height of the block the contract stored with the request.
    pub request_block_height: BlockHeight,
    pub request: dtos::ForeignChainRpcRequest,
    pub domain_id: DomainId,
    /// The hash of the caller's expected values. The node never holds the values.
    pub expected_values_hash: dtos::Hash256,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
}

impl VerifyForeignTxRequestV2 {
    /// The payload that answers this request with `outcome`.
    pub fn sign_payload(
        &self,
        outcome: dtos::ForeignTxVerificationOutcome,
    ) -> dtos::ForeignTxSignPayload {
        dtos::ForeignTxSignPayload::V2(dtos::ForeignTxSignPayloadV2 {
            request: self.request.clone(),
            expected_values_hash: self.expected_values_hash.clone(),
            request_block_height: self.request_block_height,
            yield_id: self.yield_id,
            outcome,
        })
    }
}

impl FromChain<VerifyForeignTxRequestV2FromChain> for VerifyForeignTxRequestV2 {
    fn from_chain(chain_value: VerifyForeignTxRequestV2FromChain, block: &BlockContext) -> Self {
        let VerifyForeignTxRequestV2FromChain {
            verify_foreign_tx_id,
            receipt_id,
            yield_id,
            request_block_height,
            request,
            domain_id,
            expected_values_hash,
        } = chain_value;
        Self {
            id: verify_foreign_tx_id,
            receipt_id,
            yield_id,
            request_block_height,
            request,
            domain_id,
            expected_values_hash,
            entropy: block.entropy.clone().into(),
            timestamp_nanosec: block.timestamp_nanosec,
        }
    }
}

impl Request for VerifyForeignTxRequestV2 {
    fn get_id(&self) -> RequestId {
        self.id
    }

    fn get_receipt_id(&self) -> CryptoHash {
        self.receipt_id
    }

    fn get_entropy(&self) -> [u8; 32] {
        self.entropy
    }

    fn get_timestamp_nanosec(&self) -> u64 {
        self.timestamp_nanosec
    }

    fn get_domain_id(&self) -> DomainId {
        self.domain_id
    }

    fn get_foreign_chain(&self) -> Option<dtos::ForeignChain> {
        Some(self.request.chain())
    }

    fn get_type() -> RequestType {
        RequestType::VerifyForeignTxV2
    }
}
