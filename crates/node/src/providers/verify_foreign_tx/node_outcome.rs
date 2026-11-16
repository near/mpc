use borsh::{BorshDeserialize, BorshSerialize};
use foreign_chain_inspector::{ForeignChainInspectionError, Verdict};
use near_mpc_contract_interface::types::{self as dtos, ForeignTxVerificationNegativeVerdict};

use crate::providers::verify_foreign_tx::inspection::Inspection;

/// What one node concludes about a V2 foreign transaction request. Only the network concludes
/// [`dtos::ForeignTxVerificationOutcome::Inconclusive`], so a node outcome cannot express it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub(crate) enum NodeOutcome {
    Verdict(NodeVerdict),
    NoVerdict(NoVerdictReason),
}

/// The outcome a V2 signing round signs. Its Borsh encoding is part of the P2P wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum RoundOutcome {
    Verdict(NodeVerdict),
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum NodeVerdict {
    /// The hash of the extracted values equals the expected values hash.
    Verified,
    Negative(ForeignTxVerificationNegativeVerdict),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub(crate) enum NoVerdictReason {
    /// Covers every provider error except an inspector disagreement, for example a failed
    /// provider or a transaction that is not final yet.
    Transient,
    /// The providers reached different verdicts. This is final, so the node does not retry.
    InspectorsDisagree,
}

impl NodeOutcome {
    pub(crate) fn new(inspection: Inspection, expected_values_hash: &dtos::Hash256) -> Self {
        match inspection {
            Ok(verdict) => match NodeVerdict::new(verdict, expected_values_hash) {
                Ok(verdict) => Self::Verdict(verdict),
                Err(error) => {
                    tracing::error!(%error, "could not hash the extracted values");
                    Self::NoVerdict(NoVerdictReason::Transient)
                }
            },
            Err(ForeignChainInspectionError::InspectorResponseMismatch) => {
                Self::NoVerdict(NoVerdictReason::InspectorsDisagree)
            }
            Err(error) => {
                tracing::info!(%error, "foreign chain inspection reached no verdict");
                Self::NoVerdict(NoVerdictReason::Transient)
            }
        }
    }
}

impl NodeVerdict {
    fn new(
        verdict: Verdict<dtos::ExtractedValue>,
        expected_values_hash: &dtos::Hash256,
    ) -> std::io::Result<Self> {
        let negative = match verdict {
            Verdict::Extracted(values)
                if dtos::extracted_values_hash(&values)? == *expected_values_hash =>
            {
                return Ok(Self::Verified);
            }
            Verdict::Extracted(_) => ForeignTxVerificationNegativeVerdict::ValuesMismatch,
            Verdict::TransactionFailed => ForeignTxVerificationNegativeVerdict::TransactionFailed,
            Verdict::TransactionNotFound => {
                ForeignTxVerificationNegativeVerdict::TransactionNotFound
            }
            // The hashes come from whichever provider answered, so only the log keeps them.
            Verdict::NonCanonicalBlock {
                block_number,
                receipt_hash,
                canonical_hash,
            } => {
                tracing::info!(
                    block_number,
                    %receipt_hash,
                    %canonical_hash,
                    "the foreign transaction's block is not canonical"
                );
                ForeignTxVerificationNegativeVerdict::NonCanonicalBlock
            }
            Verdict::LogIndexOutOfBounds => {
                ForeignTxVerificationNegativeVerdict::LogIndexOutOfBounds
            }
            Verdict::AccountNotFound => ForeignTxVerificationNegativeVerdict::AccountNotFound,
        };
        tracing::info!(
            ?negative,
            "foreign chain inspection reached a negative verdict"
        );
        Ok(Self::Negative(negative))
    }
}

impl From<RoundOutcome> for dtos::ForeignTxVerificationOutcome {
    fn from(outcome: RoundOutcome) -> Self {
        match outcome {
            RoundOutcome::Verdict(verdict) => verdict.into(),
            RoundOutcome::Inconclusive => Self::Inconclusive {},
        }
    }
}

impl From<NodeVerdict> for dtos::ForeignTxVerificationOutcome {
    fn from(verdict: NodeVerdict) -> Self {
        match verdict {
            NodeVerdict::Verified => Self::Verified {},
            NodeVerdict::Negative(verdict) => Self::Negative { verdict },
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use foreign_chain_inspector::HexBytes;
    use rstest::rstest;

    fn block_hash(byte: u8) -> dtos::ExtractedValue {
        dtos::ExtractedValue::EvmExtractedValue(dtos::EvmExtractedValue::BlockHash(dtos::Hash256(
            [byte; 32],
        )))
    }

    fn values_hash(values: &[dtos::ExtractedValue]) -> dtos::Hash256 {
        dtos::extracted_values_hash(values).unwrap()
    }

    fn non_canonical_block() -> Verdict<dtos::ExtractedValue> {
        Verdict::NonCanonicalBlock {
            block_number: 7,
            receipt_hash: HexBytes(vec![0xaa; 32]),
            canonical_hash: HexBytes(vec![0xbb; 32]),
        }
    }

    #[test]
    fn node_outcome__should_verify_values_equal_to_the_expected_ones() {
        // Given
        let inspection = Ok(Verdict::Extracted(vec![block_hash(1), block_hash(2)]));

        // When
        let outcome = NodeOutcome::new(inspection, &values_hash(&[block_hash(1), block_hash(2)]));

        // Then
        assert_eq!(outcome, NodeOutcome::Verdict(NodeVerdict::Verified));
    }

    #[rstest]
    #[case::different_value(vec![block_hash(1), block_hash(3)])]
    #[case::different_order(vec![block_hash(2), block_hash(1)])]
    #[case::fewer_values(vec![block_hash(1)])]
    #[case::more_values(vec![block_hash(1), block_hash(2), block_hash(3)])]
    fn node_outcome__should_report_values_mismatch_when_values_differ(
        #[case] extracted: Vec<dtos::ExtractedValue>,
    ) {
        // Given
        let inspection = Ok(Verdict::Extracted(extracted));

        // When
        let outcome = NodeOutcome::new(inspection, &values_hash(&[block_hash(1), block_hash(2)]));

        // Then
        assert_eq!(
            outcome,
            NodeOutcome::Verdict(NodeVerdict::Negative(
                dtos::ForeignTxVerificationNegativeVerdict::ValuesMismatch
            ))
        );
    }

    #[rstest]
    #[case::transaction_failed(
        Verdict::TransactionFailed,
        dtos::ForeignTxVerificationNegativeVerdict::TransactionFailed
    )]
    #[case::transaction_not_found(
        Verdict::TransactionNotFound,
        dtos::ForeignTxVerificationNegativeVerdict::TransactionNotFound
    )]
    #[case::non_canonical_block(
        non_canonical_block(),
        dtos::ForeignTxVerificationNegativeVerdict::NonCanonicalBlock
    )]
    #[case::log_index_out_of_bounds(
        Verdict::LogIndexOutOfBounds,
        dtos::ForeignTxVerificationNegativeVerdict::LogIndexOutOfBounds
    )]
    #[case::account_not_found(
        Verdict::AccountNotFound,
        dtos::ForeignTxVerificationNegativeVerdict::AccountNotFound
    )]
    fn node_outcome__should_map_each_inspector_verdict_to_its_negative_verdict(
        #[case] verdict: Verdict<dtos::ExtractedValue>,
        #[case] expected: dtos::ForeignTxVerificationNegativeVerdict,
    ) {
        // When
        let outcome = NodeOutcome::new(Ok(verdict), &values_hash(&[block_hash(1)]));

        // Then
        assert_eq!(
            outcome,
            NodeOutcome::Verdict(NodeVerdict::Negative(expected))
        );
    }

    #[rstest]
    #[case::rpc_request_failed(ForeignChainInspectionError::RpcRequestFailed("down".to_string()))]
    #[case::timeout(ForeignChainInspectionError::Timeout)]
    #[case::rpc_request_rejected(ForeignChainInspectionError::RpcRequestRejected("401".to_string()))]
    #[case::malformed_rpc_response(ForeignChainInspectionError::MalformedRpcResponse(
        "bad json".to_string()
    ))]
    #[case::not_finalized(ForeignChainInspectionError::NotFinalized)]
    #[case::not_enough_block_confirmations(
        ForeignChainInspectionError::NotEnoughBlockConfirmations {
            expected: 6.into(),
            got: 2.into(),
        }
    )]
    #[case::inconsistent_rpc_response(ForeignChainInspectionError::InconsistentRpcResponse {
        requested_hash: HexBytes(vec![1]),
        returned_hash: HexBytes(vec![2]),
    })]
    #[case::log_not_bound_to_receipt(ForeignChainInspectionError::LogNotBoundToReceipt {
        log_index: 0,
        log_transaction_hash: HexBytes(vec![1]),
        log_block_hash: HexBytes(vec![2]),
        log_block_number: 3,
        receipt_transaction_hash: HexBytes(vec![4]),
        receipt_block_hash: HexBytes(vec![5]),
        receipt_block_number: 6,
    })]
    #[case::sub_quorum(ForeignChainInspectionError::SubQuorum {
        agreeing: 1,
        required: std::num::NonZeroUsize::new(2).unwrap(),
    })]
    fn node_outcome__should_report_provider_errors_as_no_verdict(
        #[case] error: ForeignChainInspectionError,
    ) {
        // When
        let outcome = NodeOutcome::new(Err(error), &values_hash(&[block_hash(1)]));

        // Then
        assert_eq!(outcome, NodeOutcome::NoVerdict(NoVerdictReason::Transient));
    }

    #[test]
    fn node_outcome__should_report_disagreeing_inspectors_as_no_verdict() {
        // Given
        let inspection = Err(ForeignChainInspectionError::InspectorResponseMismatch);

        // When
        let outcome = NodeOutcome::new(inspection, &values_hash(&[block_hash(1)]));

        // Then
        assert_eq!(
            outcome,
            NodeOutcome::NoVerdict(NoVerdictReason::InspectorsDisagree)
        );
    }

    #[rstest]
    #[case::verified(NodeVerdict::Verified, dtos::ForeignTxVerificationOutcome::Verified {})]
    #[case::negative(
        NodeVerdict::Negative(dtos::ForeignTxVerificationNegativeVerdict::TransactionNotFound),
        dtos::ForeignTxVerificationOutcome::Negative {
            verdict: dtos::ForeignTxVerificationNegativeVerdict::TransactionNotFound,
        }
    )]
    fn foreign_tx_verification_outcome__should_carry_the_node_verdict(
        #[case] verdict: NodeVerdict,
        #[case] expected: dtos::ForeignTxVerificationOutcome,
    ) {
        // When
        let outcome = dtos::ForeignTxVerificationOutcome::from(verdict);

        // Then
        assert_eq!(outcome, expected);
    }
}
