use crate::{
    foreign_chain::{ForeignChainRequestBuilder, ForeignChainRpcRequestWithExpectations},
    sign::NotSet,
};

use near_mpc_contract_interface::types::ExtractedValue;

pub use near_mpc_contract_interface::types::{
    ForeignChainRpcRequest, TonAddress, TonExtractedValue, TonExtractor, TonFinality, TonLog,
    TonRpcRequest, TonTxId,
};

/// Type alias with concrete types for when [`TonRequest`] is ready to be built
/// as part of the [`ForeignChainRequestBuilder`] builder. A [`TonRpcRequest`]
/// needs all three of `tx_id`, `account`, and `finality` to be set before it
/// can be built — the type parameters track that via the typestate pattern.
type BuildableTonRequest = TonRequest<TonTxId, TonAddress, TonFinality>;

/// Default ext-out message index for builders that do not explicitly set one.
/// Bridge event emitters typically emit exactly one ext-out per tx, so `0` is
/// the overwhelmingly common case.
const DEFAULT_MESSAGE_INDEX: u64 = 0;

#[derive(Debug, Clone)]
pub struct TonRequest<TxId, Account, Finality> {
    tx_id: TxId,
    account: Account,
    finality: Finality,

    // Optional parameters with defaults.
    message_index: u64,
    expected_log: Option<TonLog>,
}

impl From<BuildableTonRequest> for ForeignChainRpcRequestWithExpectations {
    fn from(built: BuildableTonRequest) -> Self {
        let mut extractors = vec![];
        let mut expected_values = vec![];

        if let Some(expected_log) = built.expected_log {
            extractors.push(TonExtractor::Log {
                message_index: built.message_index,
            });
            expected_values.push(ExtractedValue::TonExtractedValue(TonExtractedValue::Log(
                expected_log,
            )));
        }

        ForeignChainRpcRequestWithExpectations {
            request: ForeignChainRpcRequest::Ton(TonRpcRequest {
                tx_id: built.tx_id,
                account: built.account,
                finality: built.finality,
                extractors,
            }),
            expected_values,
        }
    }
}

impl ForeignChainRequestBuilder<TonRequest<NotSet, NotSet, NotSet>, NotSet> {
    pub fn new_ton() -> Self {
        Self {
            request: TonRequest {
                tx_id: NotSet,
                account: NotSet,
                finality: NotSet,
                message_index: DEFAULT_MESSAGE_INDEX,
                expected_log: None,
            },
            domain_id: NotSet,
        }
    }
}

impl ForeignChainRequestBuilder<TonRequest<NotSet, NotSet, NotSet>, NotSet> {
    pub fn with_tx_id(
        self,
        tx_id: impl Into<TonTxId>,
    ) -> ForeignChainRequestBuilder<TonRequest<TonTxId, NotSet, NotSet>, NotSet> {
        ForeignChainRequestBuilder {
            request: TonRequest {
                tx_id: tx_id.into(),
                account: NotSet,
                finality: NotSet,
                message_index: self.request.message_index,
                expected_log: self.request.expected_log,
            },
            domain_id: self.domain_id,
        }
    }
}

impl ForeignChainRequestBuilder<TonRequest<TonTxId, NotSet, NotSet>, NotSet> {
    pub fn with_account(
        self,
        account: impl Into<TonAddress>,
    ) -> ForeignChainRequestBuilder<TonRequest<TonTxId, TonAddress, NotSet>, NotSet> {
        ForeignChainRequestBuilder {
            request: TonRequest {
                tx_id: self.request.tx_id,
                account: account.into(),
                finality: NotSet,
                message_index: self.request.message_index,
                expected_log: self.request.expected_log,
            },
            domain_id: self.domain_id,
        }
    }
}

impl ForeignChainRequestBuilder<TonRequest<TonTxId, TonAddress, NotSet>, NotSet> {
    pub fn with_finality(
        self,
        finality: impl Into<TonFinality>,
    ) -> ForeignChainRequestBuilder<BuildableTonRequest, NotSet> {
        ForeignChainRequestBuilder {
            request: TonRequest {
                tx_id: self.request.tx_id,
                account: self.request.account,
                finality: finality.into(),
                message_index: self.request.message_index,
                expected_log: self.request.expected_log,
            },
            domain_id: self.domain_id,
        }
    }
}

impl ForeignChainRequestBuilder<BuildableTonRequest, NotSet> {
    /// Select which ext-out message (after filtering internal messages) the
    /// inspector should extract. Defaults to `0`.
    pub fn with_message_index(self, message_index: u64) -> Self {
        ForeignChainRequestBuilder {
            request: TonRequest {
                message_index,
                ..self.request
            },
            domain_id: self.domain_id,
        }
    }

    /// Pin the expected [`TonLog`] for the request. The resulting verifier
    /// checks this value against the signed payload returned by the MPC
    /// network, and a `TonExtractor::Log` is added to the request so the
    /// nodes actually extract it.
    pub fn with_expected_log(self, expected_log: impl Into<TonLog>) -> Self {
        ForeignChainRequestBuilder {
            request: TonRequest {
                expected_log: Some(expected_log.into()),
                ..self.request
            },
            domain_id: self.domain_id,
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod test {
    use assert_matches::assert_matches;
    use near_mpc_contract_interface::types::{
        DomainId, Hash256, TonAddress, TonLog, VerifyForeignTransactionRequestArgs,
    };

    use crate::foreign_chain::{DEFAULT_PAYLOAD_VERSION, ForeignChainSignatureVerifier};

    use super::*;

    fn sample_tx_id() -> TonTxId {
        TonTxId(Hash256([0x11; 32]))
    }

    fn sample_account() -> TonAddress {
        TonAddress {
            workchain: 0,
            hash: Hash256([0x22; 32]),
        }
    }

    fn sample_log() -> TonLog {
        TonLog {
            from_address: Hash256([0x22; 32]),
            body_bits: vec![0x99, 0x00, 0x00, 0x01],
            body_refs: vec![vec![0xde, 0xad]],
        }
    }

    #[test]
    fn with_tx_id__should_set_expected_value() {
        // given / when
        let builder = ForeignChainRequestBuilder::new_ton().with_tx_id(sample_tx_id());

        // then
        assert_eq!(builder.request.tx_id, sample_tx_id());
    }

    #[test]
    fn with_account__should_set_expected_value() {
        // given / when
        let builder = ForeignChainRequestBuilder::new_ton()
            .with_tx_id(sample_tx_id())
            .with_account(sample_account());

        // then
        assert_eq!(builder.request.account, sample_account());
    }

    #[test]
    fn with_finality__should_set_expected_value() {
        // given / when
        let builder = ForeignChainRequestBuilder::new_ton()
            .with_tx_id(sample_tx_id())
            .with_account(sample_account())
            .with_finality(TonFinality::MasterchainIncluded);

        // then
        assert_eq!(builder.request.finality, TonFinality::MasterchainIncluded);
    }

    #[test]
    fn with_message_index__should_override_default() {
        // given / when
        let builder = ForeignChainRequestBuilder::new_ton()
            .with_tx_id(sample_tx_id())
            .with_account(sample_account())
            .with_finality(TonFinality::MasterchainIncluded)
            .with_message_index(7);

        // then
        assert_eq!(builder.request.message_index, 7);
    }

    #[test]
    fn build_without_expected_log__should_produce_empty_extractors() {
        // given / when
        let (_verifier, request_args) = ForeignChainRequestBuilder::new_ton()
            .with_tx_id(sample_tx_id())
            .with_account(sample_account())
            .with_finality(TonFinality::MasterchainIncluded)
            .with_domain_id(DomainId::from(4))
            .build();

        // then
        assert_matches!(&request_args.request, ForeignChainRpcRequest::Ton(rpc) => {
            assert_eq!(rpc.extractors, vec![]);
        });
    }

    #[test]
    fn build_with_expected_log__should_produce_correct_request_args() {
        // given
        let domain_id = DomainId::from(7);

        // when
        let (_verifier, request_args) = ForeignChainRequestBuilder::new_ton()
            .with_tx_id(sample_tx_id())
            .with_account(sample_account())
            .with_finality(TonFinality::MasterchainIncluded)
            .with_message_index(2)
            .with_expected_log(sample_log())
            .with_domain_id(domain_id)
            .build();

        // then
        let expected = VerifyForeignTransactionRequestArgs {
            request: ForeignChainRpcRequest::Ton(TonRpcRequest {
                tx_id: sample_tx_id(),
                account: sample_account(),
                finality: TonFinality::MasterchainIncluded,
                extractors: vec![TonExtractor::Log { message_index: 2 }],
            }),
            domain_id,
            payload_version: DEFAULT_PAYLOAD_VERSION,
        };
        assert_eq!(request_args, expected);
    }

    #[test]
    fn build_with_expected_log__should_produce_verifier_with_expected_value() {
        // given / when
        let (verifier, _request_args) = ForeignChainRequestBuilder::new_ton()
            .with_tx_id(sample_tx_id())
            .with_account(sample_account())
            .with_finality(TonFinality::MasterchainIncluded)
            .with_expected_log(sample_log())
            .with_domain_id(DomainId::from(1))
            .build();

        // then
        let expected_verifier = ForeignChainSignatureVerifier {
            expected_extracted_values: vec![ExtractedValue::TonExtractedValue(
                TonExtractedValue::Log(sample_log()),
            )],
            request: ForeignChainRpcRequest::Ton(TonRpcRequest {
                tx_id: sample_tx_id(),
                account: sample_account(),
                finality: TonFinality::MasterchainIncluded,
                extractors: vec![TonExtractor::Log {
                    message_index: DEFAULT_MESSAGE_INDEX,
                }],
            }),
        };
        assert_eq!(verifier, expected_verifier);
    }

    #[test]
    fn verifier_request__should_match_request_args_request() {
        // given / when
        let (verifier, request_args) = ForeignChainRequestBuilder::new_ton()
            .with_tx_id(sample_tx_id())
            .with_account(sample_account())
            .with_finality(TonFinality::MasterchainIncluded)
            .with_domain_id(DomainId::from(1))
            .build();

        // then
        assert_eq!(verifier.request, request_args.request);
    }
}
