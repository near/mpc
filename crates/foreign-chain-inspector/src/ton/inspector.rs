use super::{TonExtractedValue, normalize_body_boc};
use crate::ton::rpc_client::TonRpcClient;
use crate::{ForeignChainInspectionError, ForeignChainInspector};
use foreign_chain_rpc_interfaces::ton::{TonMessage, TonTransaction};
use near_mpc_contract_interface::types::{Hash256, TonLog};

/// Inspector-side finality type, convertible from the contract DTO's
/// `TonFinality`. Keeps the enum mirror of the DTO so the inspector compiles
/// without depending on schemars/abi features.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TonFinality {
    MasterchainIncluded,
}

/// Inspector-side extractor type, convertible from the contract DTO's
/// `TonExtractor`. Uses `usize` for direct slice indexing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TonExtractor {
    Log { message_index: usize },
}

/// Fully-qualified TON transaction identifier: workchain + account hash +
/// tx hash. Bundled into the `TransactionId` associated type so the
/// [`ForeignChainInspector`] trait — which only carries a single `TransactionId`
/// — can still reach the account-scoped lookup that toncenter requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TonTransactionId {
    pub workchain: i8,
    pub account: [u8; 32],
    pub tx_hash: [u8; 32],
}

/// TON chain inspector.
///
/// Generic over the transport for testing: production uses
/// [`super::rpc_client::ReqwestTonClient`]; tests use an `httpmock`-backed
/// implementation or a direct in-memory stub.
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

        if workchain != 0 {
            return Err(ForeignChainInspectionError::UnsupportedWorkchain { got: workchain });
        }

        let tx_hash_hex = hex::encode(tx_hash);

        let response = self
            .client
            .get_transaction(workchain, &account, &tx_hash_hex)
            .await?;

        let tx = response.transactions.into_iter().next().ok_or(
            ForeignChainInspectionError::TonTransactionNotFound {
                tx_hash_hex: tx_hash_hex.clone(),
            },
        )?;

        ensure_account_matches(workchain, &account, &tx.account)?;
        ensure_finalized(&tx, &finality)?;
        ensure_transaction_succeeded(&tx)?;

        let ext_out_msgs = ordered_ext_out_msgs(&tx.out_msgs)?;

        extractors
            .iter()
            .map(|extractor| extract_value(extractor, &account, &ext_out_msgs))
            .collect()
    }
}

/// Filter out internal (non-ext-out) messages and return the remainder sorted
/// by parsed `created_lt` (ascending).
///
/// Sorting by `created_lt` makes ext-out indexing deterministic across MPC
/// nodes regardless of how the upstream toncenter v3 provider chose to order
/// the `out_msgs` array in its JSON. Within a single TON transaction, every
/// emitted message has a distinct, monotonically increasing `created_lt` —
/// this is a TON protocol invariant (the TVM bumps `lt` on each
/// `SENDRAWMSG`), so sorting by it preserves the natural emission order.
///
/// If any ext-out message is missing or has an unparseable `created_lt`, the
/// caller's whole request is rejected: an inability to establish a
/// deterministic order would make consensus on `message_index` impossible.
fn ordered_ext_out_msgs(
    out_msgs: &[TonMessage],
) -> Result<Vec<&TonMessage>, ForeignChainInspectionError> {
    let mut ext_outs_with_lt: Vec<(u64, &TonMessage)> = out_msgs
        .iter()
        .filter(|m| m.destination.is_none())
        .map(|m| message_created_lt(m).map(|lt| (lt, m)))
        .collect::<Result<_, _>>()?;
    ext_outs_with_lt.sort_by_key(|(lt, _)| *lt);
    Ok(ext_outs_with_lt.into_iter().map(|(_, m)| m).collect())
}

fn message_created_lt(msg: &TonMessage) -> Result<u64, ForeignChainInspectionError> {
    let raw = msg
        .created_lt
        .as_deref()
        .ok_or(ForeignChainInspectionError::TonMessageMissingCreatedLt)?;
    raw.parse::<u64>().map_err(
        |_| ForeignChainInspectionError::TonMessageMalformedCreatedLt {
            value: raw.to_string(),
        },
    )
}

fn ensure_account_matches(
    workchain: i8,
    expected_hash: &[u8; 32],
    rpc_account: &str,
) -> Result<(), ForeignChainInspectionError> {
    let expected = crate::ton::rpc_client::format_ton_account(workchain, expected_hash);
    if expected.eq_ignore_ascii_case(rpc_account) {
        Ok(())
    } else {
        Err(ForeignChainInspectionError::AccountMismatch {
            expected,
            got: rpc_account.to_string(),
        })
    }
}

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

fn ensure_transaction_succeeded(tx: &TonTransaction) -> Result<(), ForeignChainInspectionError> {
    if tx.description.aborted || tx.description.destroyed {
        return Err(ForeignChainInspectionError::TransactionFailed);
    }
    if let Some(compute_ph) = &tx.description.compute_ph {
        if compute_ph.success == Some(false) {
            return Err(ForeignChainInspectionError::TransactionFailed);
        }
    }
    Ok(())
}

fn extract_value(
    extractor: &TonExtractor,
    expected_account_hash: &[u8; 32],
    ext_out_msgs: &[&TonMessage],
) -> Result<TonExtractedValue, ForeignChainInspectionError> {
    match extractor {
        TonExtractor::Log { message_index } => {
            let msg = ext_out_msgs
                .get(*message_index)
                .ok_or(ForeignChainInspectionError::LogIndexOutOfBounds)?;
            // Defense in depth: the filter should have already dropped
            // non-ext-out messages. A non-`None` destination here would be a
            // filter bug, not a user error — report it precisely rather than
            // as a cell error downstream.
            if msg.destination.is_some() {
                return Err(ForeignChainInspectionError::NotAnExtOutMessage {
                    index: *message_index as u64,
                });
            }

            let body_b64 = msg
                .message_content
                .as_ref()
                .map(|c| c.body.as_str())
                .unwrap_or_default();

            // Empty body is a valid ext-out (rare but permitted): normalize
            // returns `(vec![], vec![])` in that case via empty-cell handling.
            let (body_bits, body_refs) = if body_b64.is_empty() {
                (Vec::new(), Vec::new())
            } else {
                normalize_body_boc(body_b64)?
            };

            Ok(TonExtractedValue::Log(TonLog {
                from_address: Hash256(*expected_account_hash),
                body_bits,
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
    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use base64::Engine;
    use foreign_chain_rpc_interfaces::ton::{
        GetTransactionsResponse, TonCellBoc, TonComputePhase, TonMessage, TonTransaction,
        TonTransactionDescription,
    };
    use std::sync::Mutex;
    use tonlib_core::cell::{ArcCell, BagOfCells, Cell};

    /// In-memory stub client that returns a canned response.
    struct StubClient {
        response: Mutex<Option<GetTransactionsResponse>>,
    }

    impl StubClient {
        fn new(response: GetTransactionsResponse) -> Self {
            Self {
                response: Mutex::new(Some(response)),
            }
        }
    }

    #[async_trait]
    impl TonRpcClient for StubClient {
        async fn get_transaction(
            &self,
            _workchain: i8,
            _account_hash: &[u8; 32],
            _tx_hash_hex: &str,
        ) -> Result<GetTransactionsResponse, TonRpcError> {
            Ok(self
                .response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| GetTransactionsResponse {
                    transactions: vec![],
                }))
        }
    }

    fn account_hash() -> [u8; 32] {
        [0x11; 32]
    }

    fn account_string(workchain: i8, hash: &[u8; 32]) -> String {
        crate::ton::rpc_client::format_ton_account(workchain, hash)
    }

    /// Build a valid, finalized, successful transaction with one ext-out carrying
    /// a 4-byte payload cell.
    fn happy_tx() -> TonTransaction {
        TonTransaction {
            account: account_string(0, &account_hash()),
            hash: "dead".to_string(),
            mc_block_seqno: Some(12345),
            description: TonTransactionDescription {
                aborted: false,
                destroyed: false,
                compute_ph: Some(TonComputePhase {
                    success: Some(true),
                }),
            },
            out_msgs: vec![TonMessage {
                source: Some(account_string(0, &account_hash())),
                destination: None, // ext-out
                created_lt: Some("100".to_string()),
                message_content: Some(TonCellBoc {
                    body: encode_cell(vec![0x99, 0x00, 0x00, 0x01], 32, vec![]),
                }),
            }],
        }
    }

    fn encode_cell(data: Vec<u8>, bit_len: usize, refs: Vec<ArcCell>) -> String {
        let cell = std::sync::Arc::new(Cell::new(data, bit_len, refs, false).unwrap());
        base64::engine::general_purpose::STANDARD
            .encode(BagOfCells::new(&[cell]).serialize(false).unwrap())
    }

    fn inspector_from_tx(tx: TonTransaction) -> TonInspector<StubClient> {
        TonInspector::new(StubClient::new(GetTransactionsResponse {
            transactions: vec![tx],
        }))
    }

    fn tx_id() -> TonTransactionId {
        TonTransactionId {
            workchain: 0,
            account: account_hash(),
            tx_hash: [0xde; 32],
        }
    }

    #[tokio::test]
    async fn extract__should_return_log_for_happy_tx() {
        let inspector = inspector_from_tx(happy_tx());
        let values = inspector
            .extract(
                tx_id(),
                TonFinality::MasterchainIncluded,
                vec![TonExtractor::Log { message_index: 0 }],
            )
            .await
            .unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TonExtractedValue::Log(log) => {
                assert_eq!(log.from_address.0, account_hash());
                assert_eq!(log.body_bits, vec![0x99, 0x00, 0x00, 0x01]);
                assert!(log.body_refs.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn extract__should_reject_when_mc_block_seqno_is_none() {
        let mut tx = happy_tx();
        tx.mc_block_seqno = None;
        let inspector = inspector_from_tx(tx);

        let err = inspector
            .extract(
                tx_id(),
                TonFinality::MasterchainIncluded,
                vec![TonExtractor::Log { message_index: 0 }],
            )
            .await
            .unwrap_err();
        assert_matches!(err, ForeignChainInspectionError::NotFinalized);
    }

    #[tokio::test]
    async fn extract__should_accept_mc_block_seqno_of_zero() {
        // Genesis seqno is 0; must be treated as finalized (not `> 0`).
        let mut tx = happy_tx();
        tx.mc_block_seqno = Some(0);
        let inspector = inspector_from_tx(tx);

        let values = inspector
            .extract(
                tx_id(),
                TonFinality::MasterchainIncluded,
                vec![TonExtractor::Log { message_index: 0 }],
            )
            .await
            .unwrap();
        assert_eq!(values.len(), 1);
    }

    #[tokio::test]
    async fn extract__should_reject_aborted_transaction() {
        let mut tx = happy_tx();
        tx.description.aborted = true;
        let inspector = inspector_from_tx(tx);

        let err = inspector
            .extract(
                tx_id(),
                TonFinality::MasterchainIncluded,
                vec![TonExtractor::Log { message_index: 0 }],
            )
            .await
            .unwrap_err();
        assert_matches!(err, ForeignChainInspectionError::TransactionFailed);
    }

    #[tokio::test]
    async fn extract__should_reject_compute_phase_failure() {
        let mut tx = happy_tx();
        tx.description.compute_ph = Some(TonComputePhase {
            success: Some(false),
        });
        let inspector = inspector_from_tx(tx);

        let err = inspector
            .extract(
                tx_id(),
                TonFinality::MasterchainIncluded,
                vec![TonExtractor::Log { message_index: 0 }],
            )
            .await
            .unwrap_err();
        assert_matches!(err, ForeignChainInspectionError::TransactionFailed);
    }

    #[tokio::test]
    async fn extract__should_reject_when_no_transaction_found() {
        let inspector = TonInspector::new(StubClient::new(GetTransactionsResponse {
            transactions: vec![],
        }));

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
            ForeignChainInspectionError::TonTransactionNotFound { .. }
        );
    }

    #[tokio::test]
    async fn extract__should_reject_on_account_mismatch() {
        let mut tx = happy_tx();
        tx.account = account_string(0, &[0x22; 32]); // different account
        let inspector = inspector_from_tx(tx);

        let err = inspector
            .extract(
                tx_id(),
                TonFinality::MasterchainIncluded,
                vec![TonExtractor::Log { message_index: 0 }],
            )
            .await
            .unwrap_err();
        assert_matches!(err, ForeignChainInspectionError::AccountMismatch { .. });
    }

    #[tokio::test]
    async fn extract__should_reject_non_basechain_workchain() {
        let inspector = inspector_from_tx(happy_tx());

        let err = inspector
            .extract(
                TonTransactionId {
                    workchain: -1,
                    account: account_hash(),
                    tx_hash: [0xde; 32],
                },
                TonFinality::MasterchainIncluded,
                vec![TonExtractor::Log { message_index: 0 }],
            )
            .await
            .unwrap_err();
        assert_matches!(
            err,
            ForeignChainInspectionError::UnsupportedWorkchain { got: -1 }
        );
    }

    #[tokio::test]
    async fn extract__should_reject_out_of_range_message_index() {
        let inspector = inspector_from_tx(happy_tx());

        let err = inspector
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
                source: Some(account_string(0, &account_hash())),
                destination: Some(account_string(0, &[0x33; 32])),
                // Internal messages aren't required to carry created_lt for
                // ordering — the inspector filters them out before the sort.
                created_lt: None,
                message_content: None,
            },
            ext_out,
        ];
        let inspector = inspector_from_tx(tx);

        let values = inspector
            .extract(
                tx_id(),
                TonFinality::MasterchainIncluded,
                vec![TonExtractor::Log { message_index: 0 }],
            )
            .await
            .unwrap();
        assert_eq!(values.len(), 1);
    }

    #[tokio::test]
    async fn extract__should_sort_ext_out_messages_by_created_lt() {
        // Two ext-out messages with bodies tagged distinctively. The "later"
        // message (higher created_lt) is placed first in the JSON to mimic
        // a hypothetical provider that does not preserve TVM emission order.
        // The inspector must still index them in created_lt order.
        let mut tx = happy_tx();
        let later_body = encode_cell(vec![0xbb; 4], 32, vec![]);
        let earlier_body = encode_cell(vec![0xaa; 4], 32, vec![]);
        tx.out_msgs = vec![
            TonMessage {
                source: Some(account_string(0, &account_hash())),
                destination: None,
                created_lt: Some("200".to_string()),
                message_content: Some(TonCellBoc { body: later_body }),
            },
            TonMessage {
                source: Some(account_string(0, &account_hash())),
                destination: None,
                created_lt: Some("100".to_string()),
                message_content: Some(TonCellBoc { body: earlier_body }),
            },
        ];
        let inspector = inspector_from_tx(tx);

        let values = inspector
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
        assert_eq!(
            first.body_bits,
            vec![0xaa; 4],
            "earlier lt should come first"
        );
        assert_eq!(
            second.body_bits,
            vec![0xbb; 4],
            "later lt should come second"
        );
    }

    #[tokio::test]
    async fn extract__should_reject_when_ext_out_is_missing_created_lt() {
        let mut tx = happy_tx();
        tx.out_msgs[0].created_lt = None;
        let inspector = inspector_from_tx(tx);

        let err = inspector
            .extract(
                tx_id(),
                TonFinality::MasterchainIncluded,
                vec![TonExtractor::Log { message_index: 0 }],
            )
            .await
            .unwrap_err();
        assert_matches!(err, ForeignChainInspectionError::TonMessageMissingCreatedLt);
    }

    #[tokio::test]
    async fn extract__should_reject_when_ext_out_has_unparseable_created_lt() {
        let mut tx = happy_tx();
        tx.out_msgs[0].created_lt = Some("not-a-number".to_string());
        let inspector = inspector_from_tx(tx);

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
            ForeignChainInspectionError::TonMessageMalformedCreatedLt { .. }
        );
    }

    #[tokio::test]
    async fn extract__should_return_empty_when_no_extractors_requested() {
        let inspector = inspector_from_tx(happy_tx());

        let values = inspector
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
        assert_matches!(err, ForeignChainInspectionError::TonClientError(_));
    }
}
