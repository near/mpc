use super::types::{
    TonAccountHash, TonExtractedValue, TonExtractor, TonFinality, TonTransactionId, TonWorkchain,
};
use super::{TonInspectionError, normalize_body_boc};
use crate::ton::rpc_client::TonRpcClient;
use crate::{ForeignChainInspectionError, ForeignChainInspector};
use foreign_chain_rpc_interfaces::ton::{TonMessage, TonTransaction};
use near_mpc_contract_interface::types::{Hash256, TonAddress, TonCellBody, TonCellRefs, TonLog};

/// TON chain inspector.
///
/// Trust model: the response of an agreeing set of RPC providers is taken at
/// face value (see [`crate::FanOut`]). The inspector does not re-validate the
/// response against the request or against TON protocol rules; in particular,
/// ext-out messages are indexed in the order the provider returned them, so
/// providers that disagree on ordering simply fail the fan-out agreement check.
#[derive(Clone)]
pub struct TonInspector<Client> {
    client: Client,
}

impl<Client> TonInspector<Client> {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

impl<Client: TonRpcClient> ForeignChainInspector for TonInspector<Client> {
    type TransactionId = TonTransactionId;
    type Finality = TonFinality;
    type Extractor = TonExtractor;
    type ExtractedValue = TonExtractedValue;

    async fn extract(
        &self,
        tx_id: TonTransactionId,
        finality: TonFinality,
        extractors: Vec<TonExtractor>,
    ) -> Result<Vec<TonExtractedValue>, ForeignChainInspectionError> {
        let TonTransactionId {
            workchain,
            account,
            tx_hash,
        } = tx_id;

        let response = self
            .client
            .get_transaction(workchain, account, tx_hash)
            .await
            .map_err(TonInspectionError::from)?;

        let tx = response.transactions.into_iter().next().ok_or_else(|| {
            TonInspectionError::TransactionNotFound {
                tx_hash_hex: tx_hash.to_string(),
            }
        })?;

        ensure_finalized(&tx, &finality)?;
        ensure_transaction_succeeded(&tx)?;

        // Ext-out (destination-less) messages carry the contract's emitted
        // logs; internal messages are skipped. Indexing follows the provider's
        // `out_msgs` order.
        let ext_out_msgs: Vec<&TonMessage> = tx
            .out_msgs
            .iter()
            .filter(|m| m.destination.is_none())
            .collect();

        extractors
            .iter()
            .map(|extractor| extract_value(extractor, workchain, account, &ext_out_msgs))
            .collect()
    }
}

/// `mc_block_seqno` is set once the transaction's shard block is referenced by
/// a masterchain block, which under TON's BFT consensus cannot be reverted.
///
/// Unlike the EVM/Starknet/Bitcoin inspectors, no second RPC call cross-checks
/// this: masterchain inclusion is irreversible, so there is no reorg to detect,
/// and the field itself is provider-asserted either way. A provider lying about
/// inclusion is covered by the [`crate::FanOut`] agreement check, the same
/// trust model under which those inspectors accept receipt contents.
fn ensure_finalized(
    tx: &TonTransaction,
    finality: &TonFinality,
) -> Result<(), ForeignChainInspectionError> {
    match finality {
        TonFinality::MasterchainIncluded => {
            if tx.mc_block_seqno.is_some() {
                Ok(())
            } else {
                Err(ForeignChainInspectionError::NotFinalized)
            }
        }
    }
}

/// `destroyed: true` (account destroyed at the end of the transaction, e.g.
/// send mode 32) does not by itself mean the transaction's ext-outs are
/// invalid, but v1 conservatively refuses to attest logs from a transaction
/// that destroyed its emitter.
fn ensure_transaction_succeeded(tx: &TonTransaction) -> Result<(), ForeignChainInspectionError> {
    if tx.description.aborted || tx.description.destroyed {
        return Err(ForeignChainInspectionError::TransactionFailed);
    }
    if let Some(compute_ph) = &tx.description.compute_ph
        && compute_ph.success == Some(false)
    {
        return Err(ForeignChainInspectionError::TransactionFailed);
    }
    // A successful compute phase does not imply the outbound messages were
    // committed: the action phase can still fail (and `aborted` is not always
    // set when it does), in which case the ext-out logs we would attest never
    // actually went out. Reject those transactions too.
    if let Some(action) = &tx.description.action
        && action.success == Some(false)
    {
        return Err(ForeignChainInspectionError::TransactionFailed);
    }
    Ok(())
}

fn extract_value(
    extractor: &TonExtractor,
    workchain: TonWorkchain,
    account: TonAccountHash,
    ext_out_msgs: &[&TonMessage],
) -> Result<TonExtractedValue, ForeignChainInspectionError> {
    match extractor {
        TonExtractor::Log { message_index } => {
            let msg = ext_out_msgs
                .get(*message_index)
                .ok_or(ForeignChainInspectionError::LogIndexOutOfBounds)?;

            // A missing `message_content` is the provider omitting data, which
            // is not the same as an explicitly empty body cell — treating it as
            // empty would let the network sign an empty log in place of the
            // real one. Reject it; only an explicit empty `body` maps to the
            // empty cell.
            let content =
                msg.message_content
                    .as_ref()
                    .ok_or(TonInspectionError::MessageMissingContent {
                        index: *message_index,
                    })?;

            let (body, body_refs) = if content.body.is_empty() {
                (TonCellBody::default(), TonCellRefs::default())
            } else {
                normalize_body_boc(&content.body).map_err(TonInspectionError::from)?
            };

            Ok(TonExtractedValue::Log(TonLog {
                from_address: TonAddress {
                    workchain,
                    hash: Hash256(account.into()),
                },
                body,
                body_refs,
            }))
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::RpcAuthentication;
    use crate::ton::rpc_client::{ReqwestTonClient, TonRpcError};
    use crate::ton::types::TonTransactionHash;
    use assert_matches::assert_matches;
    use foreign_chain_rpc_interfaces::ton::{
        GetTransactionsResponse, TonActionPhase, TonCellBoc, TonComputePhase, TonMessage,
        TonRawAddress, TonTransaction, TonTransactionDescription,
    };
    use test_utils::ton::{cell_body, encode_single_leaf_boc};

    /// In-memory stub client that returns a canned response.
    struct StubClient {
        response: GetTransactionsResponse,
    }

    impl TonRpcClient for StubClient {
        async fn get_transaction(
            &self,
            _workchain: TonWorkchain,
            _account: TonAccountHash,
            _tx_hash: TonTransactionHash,
        ) -> Result<GetTransactionsResponse, TonRpcError> {
            Ok(self.response.clone())
        }
    }

    const ACCOUNT_HASH: [u8; 32] = [0x11; 32];
    const TX_HASH: [u8; 32] = [0xde; 32];

    fn ext_out_with_body(body: &[u8]) -> TonMessage {
        TonMessage {
            destination: None, // ext-out
            message_content: Some(TonCellBoc {
                body: encode_single_leaf_boc(body, 8 * body.len() as u16),
            }),
        }
    }

    /// Build a valid, finalized, successful transaction with one ext-out carrying
    /// a 4-byte payload cell.
    fn happy_tx() -> TonTransaction {
        TonTransaction {
            mc_block_seqno: Some(12345),
            description: TonTransactionDescription {
                aborted: false,
                destroyed: false,
                compute_ph: Some(TonComputePhase {
                    success: Some(true),
                }),
                action: Some(TonActionPhase {
                    success: Some(true),
                }),
            },
            out_msgs: vec![ext_out_with_body(&[0x99, 0x00, 0x00, 0x01])],
        }
    }

    fn inspector_from_tx(tx: TonTransaction) -> TonInspector<StubClient> {
        TonInspector::new(StubClient {
            response: GetTransactionsResponse {
                transactions: vec![tx],
            },
        })
    }

    fn tx_id() -> TonTransactionId {
        TonTransactionId {
            workchain: TonWorkchain::Basechain,
            account: ACCOUNT_HASH.into(),
            tx_hash: TX_HASH.into(),
        }
    }

    /// Run the inspector over `tx` with the single `Log { message_index: 0 }`
    /// extractor almost every test uses.
    async fn extract_log0(
        tx: TonTransaction,
    ) -> Result<Vec<TonExtractedValue>, ForeignChainInspectionError> {
        inspector_from_tx(tx)
            .extract(
                tx_id(),
                TonFinality::MasterchainIncluded,
                vec![TonExtractor::Log { message_index: 0 }],
            )
            .await
    }

    #[tokio::test]
    async fn extract__should_return_log_for_happy_tx() {
        let values = extract_log0(happy_tx()).await.unwrap();

        assert_eq!(values.len(), 1);
        let TonExtractedValue::Log(log) = &values[0];
        assert_eq!(
            log.from_address,
            TonAddress {
                workchain: TonWorkchain::Basechain,
                hash: Hash256(ACCOUNT_HASH),
            }
        );
        assert_eq!(log.body, cell_body(vec![0x99, 0x00, 0x00, 0x01], 32));
        assert!(log.body_refs.is_empty());
    }

    #[tokio::test]
    async fn extract__should_reject_when_mc_block_seqno_is_none() {
        let mut tx = happy_tx();
        tx.mc_block_seqno = None;

        let err = extract_log0(tx).await.unwrap_err();

        assert_matches!(err, ForeignChainInspectionError::NotFinalized);
    }

    #[tokio::test]
    async fn extract__should_accept_mc_block_seqno_of_zero() {
        // Genesis seqno is 0; must be treated as finalized (not `> 0`).
        let mut tx = happy_tx();
        tx.mc_block_seqno = Some(0);

        let values = extract_log0(tx).await.unwrap();

        assert_eq!(values.len(), 1);
    }

    #[tokio::test]
    async fn extract__should_reject_aborted_transaction() {
        let mut tx = happy_tx();
        tx.description.aborted = true;

        let err = extract_log0(tx).await.unwrap_err();

        assert_matches!(err, ForeignChainInspectionError::TransactionFailed);
    }

    #[tokio::test]
    async fn extract__should_reject_compute_phase_failure() {
        let mut tx = happy_tx();
        tx.description.compute_ph = Some(TonComputePhase {
            success: Some(false),
        });

        let err = extract_log0(tx).await.unwrap_err();

        assert_matches!(err, ForeignChainInspectionError::TransactionFailed);
    }

    #[tokio::test]
    async fn extract__should_reject_action_phase_failure() {
        // Compute phase succeeded but the action phase did not commit the
        // outbound messages — the log we would attest never went out.
        let mut tx = happy_tx();
        tx.description.action = Some(TonActionPhase {
            success: Some(false),
        });

        let err = extract_log0(tx).await.unwrap_err();

        assert_matches!(err, ForeignChainInspectionError::TransactionFailed);
    }

    #[tokio::test]
    async fn extract__should_accept_when_action_phase_absent() {
        // A skipped/absent action phase is not a failure (e.g. a transaction
        // with no outbound actions); `None` must not be treated as failure.
        let mut tx = happy_tx();
        tx.description.action = None;

        let values = extract_log0(tx).await.unwrap();

        assert_eq!(values.len(), 1);
    }

    #[tokio::test]
    async fn extract__should_reject_when_no_transaction_found() {
        let inspector = TonInspector::new(StubClient {
            response: GetTransactionsResponse {
                transactions: vec![],
            },
        });

        let err = inspector
            .extract(
                tx_id(),
                TonFinality::MasterchainIncluded,
                vec![TonExtractor::Log { message_index: 0 }],
            )
            .await
            .unwrap_err();

        assert_matches!(
            err,
            ForeignChainInspectionError::Ton(TonInspectionError::TransactionNotFound { .. })
        );
    }

    #[tokio::test]
    async fn extract__should_reject_out_of_range_message_index() {
        let err = inspector_from_tx(happy_tx())
            .extract(
                tx_id(),
                TonFinality::MasterchainIncluded,
                vec![TonExtractor::Log { message_index: 5 }],
            )
            .await
            .unwrap_err();

        assert_matches!(err, ForeignChainInspectionError::LogIndexOutOfBounds);
    }

    #[tokio::test]
    async fn extract__should_skip_internal_messages_in_index() {
        // Put an internal out-msg first, then the ext-out. `message_index: 0`
        // should find the ext-out (the only ext-out), not the internal msg.
        let mut tx = happy_tx();
        let ext_out = tx.out_msgs.pop().unwrap();
        tx.out_msgs = vec![
            TonMessage {
                destination: Some(TonRawAddress {
                    workchain: 0,
                    hash: [0x33; 32],
                }),
                message_content: None,
            },
            ext_out,
        ];

        let values = extract_log0(tx).await.unwrap();

        assert_eq!(values.len(), 1);
    }

    #[tokio::test]
    async fn extract__should_index_ext_out_messages_in_provider_order() {
        // Two ext-out messages with bodies tagged distinctively; indexes must
        // follow the provider's `out_msgs` order.
        let mut tx = happy_tx();
        tx.out_msgs = vec![ext_out_with_body(&[0xaa; 4]), ext_out_with_body(&[0xbb; 4])];

        let values = inspector_from_tx(tx)
            .extract(
                tx_id(),
                TonFinality::MasterchainIncluded,
                vec![
                    TonExtractor::Log { message_index: 0 },
                    TonExtractor::Log { message_index: 1 },
                ],
            )
            .await
            .unwrap();

        assert_eq!(values.len(), 2);
        let TonExtractedValue::Log(first) = &values[0];
        let TonExtractedValue::Log(second) = &values[1];
        assert_eq!(first.body, cell_body(vec![0xaa; 4], 32));
        assert_eq!(second.body, cell_body(vec![0xbb; 4], 32));
    }

    #[tokio::test]
    async fn extract__should_return_empty_when_no_extractors_requested() {
        let values = inspector_from_tx(happy_tx())
            .extract(tx_id(), TonFinality::MasterchainIncluded, vec![])
            .await
            .unwrap();

        assert!(values.is_empty());
    }

    #[tokio::test]
    async fn extract__should_propagate_rpc_error() {
        // Base URL that will fail to connect (invalid port).
        let client = ReqwestTonClient::new(
            "http://127.0.0.1:1/".to_string(),
            RpcAuthentication::KeyInUrl,
        )
        .unwrap();
        let inspector = TonInspector::new(client);

        let err = inspector
            .extract(
                tx_id(),
                TonFinality::MasterchainIncluded,
                vec![TonExtractor::Log { message_index: 0 }],
            )
            .await
            .unwrap_err();

        assert_matches!(
            err,
            ForeignChainInspectionError::Ton(TonInspectionError::RpcError(_))
        );
    }

    #[tokio::test]
    async fn extract__should_reject_when_ext_out_has_no_message_content() {
        // A missing `message_content` is the provider omitting data, not an
        // empty log; it must be rejected rather than signed as an empty body.
        let mut tx = happy_tx();
        tx.out_msgs[0].message_content = None;

        let err = extract_log0(tx).await.unwrap_err();

        assert_matches!(
            err,
            ForeignChainInspectionError::Ton(TonInspectionError::MessageMissingContent {
                index: 0
            })
        );
    }

    #[tokio::test]
    async fn extract__should_extract_empty_body_when_message_content_body_is_empty() {
        // An explicitly empty `body` string is the provider affirming the body
        // is empty, so it maps to a zero-bit cell with no references.
        let mut tx = happy_tx();
        tx.out_msgs[0].message_content = Some(TonCellBoc {
            body: String::new(),
        });

        let values = extract_log0(tx).await.unwrap();

        assert_eq!(values.len(), 1);
        let TonExtractedValue::Log(log) = &values[0];
        assert_eq!(log.body, cell_body(vec![], 0));
        assert!(log.body_refs.is_empty());
    }
}
