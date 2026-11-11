use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::{
    AptosExtractedValue, AptosRpcRequest, BitcoinExtractedValue, BitcoinRpcRequest,
    EvmExtractedValue, EvmRpcRequest, ForeignChain, StarknetExtractedValue, StarknetRpcRequest,
    SuiExtractedValue, SuiRpcRequest, SvmExtractedValue, SvmRpcRequest, TonExtractedValue,
    TonRpcRequest,
};

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum ForeignChainRpcRequest {
    Abstract(EvmRpcRequest),
    Ethereum(EvmRpcRequest),
    Solana(SvmRpcRequest),
    Bitcoin(BitcoinRpcRequest),
    Starknet(StarknetRpcRequest),
    Bnb(EvmRpcRequest),
    Base(EvmRpcRequest),
    Arbitrum(EvmRpcRequest),
    Polygon(EvmRpcRequest),
    HyperEvm(EvmRpcRequest),
    Ton(TonRpcRequest),
    Aptos(AptosRpcRequest),
    Sui(SuiRpcRequest),
    Avalanche(EvmRpcRequest),
    Adi(EvmRpcRequest),
    Fogo(SvmRpcRequest),
}
impl ForeignChainRpcRequest {
    pub fn chain(&self) -> ForeignChain {
        match self {
            Self::Abstract(_) => ForeignChain::Abstract,
            Self::Ethereum(_) => ForeignChain::Ethereum,
            Self::Solana(_) => ForeignChain::Solana,
            Self::Bitcoin(_) => ForeignChain::Bitcoin,
            Self::Starknet(_) => ForeignChain::Starknet,
            Self::Bnb(_) => ForeignChain::Bnb,
            Self::Base(_) => ForeignChain::Base,
            Self::Arbitrum(_) => ForeignChain::Arbitrum,
            Self::Polygon(_) => ForeignChain::Polygon,
            Self::HyperEvm(_) => ForeignChain::HyperEvm,
            Self::Ton(_) => ForeignChain::Ton,
            Self::Aptos(_) => ForeignChain::Aptos,
            Self::Sui(_) => ForeignChain::Sui,
            Self::Avalanche(_) => ForeignChain::Avalanche,
            Self::Adi(_) => ForeignChain::Adi,
            Self::Fogo(_) => ForeignChain::Fogo,
        }
    }
}
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum ExtractedValue {
    BitcoinExtractedValue(BitcoinExtractedValue),
    EvmExtractedValue(EvmExtractedValue),
    StarknetExtractedValue(StarknetExtractedValue),
    TonExtractedValue(TonExtractedValue),
    AptosExtractedValue(AptosExtractedValue),
    SuiExtractedValue(SuiExtractedValue),
    SvmExtractedValue(SvmExtractedValue),
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::types::{
        AptosFinality, AptosTxId, BitcoinTxId, BlockConfirmations, EvmFinality, EvmTxId, Hash256,
        StarknetFelt, StarknetFinality, StarknetTxId, SuiFinality, SuiTxId, SvmFinality, SvmTxId,
        TonAddress, TonFinality, TonTxId,
    };
    use rstest::rstest;

    #[rstest]
    #[case::abstract_(
        ForeignChainRpcRequest::Abstract(EvmRpcRequest {
            tx_id: EvmTxId([0; 32]),
            extractors: [].into(),
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Abstract,
    )]
    #[case::ethereum(
        ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
            tx_id: EvmTxId([0; 32]),
            extractors: [].into(),
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Ethereum,
    )]
    #[case::solana(
        ForeignChainRpcRequest::Solana(SvmRpcRequest {
            tx_id: SvmTxId([0; 64]),
            finality: SvmFinality::Finalized,
            extractors: [].into(),
        }),
        ForeignChain::Solana,
    )]
    #[case::bitcoin(
        ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
            tx_id: BitcoinTxId([0; 32]),
            confirmations: BlockConfirmations(1),
            extractors: [].into(),
        }),
        ForeignChain::Bitcoin,
    )]
    #[case::starknet(
        ForeignChainRpcRequest::Starknet(StarknetRpcRequest {
            tx_id: StarknetTxId(StarknetFelt([0; 32])),
            finality: StarknetFinality::AcceptedOnL1,
            extractors: [].into(),
        }),
        ForeignChain::Starknet,
    )]
    #[case::bnb(
        ForeignChainRpcRequest::Bnb(EvmRpcRequest {
            tx_id: EvmTxId([0; 32]),
            extractors: [].into(),
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Bnb,
    )]
    #[case::base(
        ForeignChainRpcRequest::Base(EvmRpcRequest {
            tx_id: EvmTxId([0; 32]),
            extractors: [].into(),
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Base,
    )]
    #[case::arbitrum(
        ForeignChainRpcRequest::Arbitrum(EvmRpcRequest {
            tx_id: EvmTxId([12; 32]),
            extractors: [].into(),
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Arbitrum,
    )]
    #[case::hyper_evm(
        ForeignChainRpcRequest::HyperEvm(EvmRpcRequest {
            tx_id: EvmTxId([12; 32]),
            extractors: [].into(),
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::HyperEvm,
    )]
    #[case::polygon(
        ForeignChainRpcRequest::Polygon(EvmRpcRequest {
            tx_id: EvmTxId([12; 32]),
            extractors: [].into(),
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Polygon,
    )]
    #[case::ton(
        ForeignChainRpcRequest::Ton(TonRpcRequest {
            tx_id: TonTxId([0; 32]),
            account: TonAddress {
                workchain: 0,
                hash: Hash256([0; 32]),
            },
            finality: TonFinality::MasterchainIncluded,
            extractors: [].into(),
        }),
        ForeignChain::Ton,
    )]
    #[case::aptos(
        ForeignChainRpcRequest::Aptos(AptosRpcRequest {
            tx_id: AptosTxId([0; 32]),
            finality: AptosFinality::Committed,
            extractors: [].into(),
        }),
        ForeignChain::Aptos,
    )]
    #[case::sui(
        ForeignChainRpcRequest::Sui(SuiRpcRequest {
            tx_id: SuiTxId([0; 32]),
            finality: SuiFinality::Checkpointed,
            extractors: [].into(),
        }),
        ForeignChain::Sui,
    )]
    #[case::avalanche(
        ForeignChainRpcRequest::Avalanche(EvmRpcRequest {
            tx_id: EvmTxId([12; 32]),
            extractors: [].into(),
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Avalanche,
    )]
    #[case::adi(
        ForeignChainRpcRequest::Adi(EvmRpcRequest {
            tx_id: EvmTxId([12; 32]),
            extractors: [].into(),
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Adi,
    )]
    #[case::fogo(
        ForeignChainRpcRequest::Fogo(SvmRpcRequest {
            tx_id: SvmTxId([0; 64]),
            finality: SvmFinality::Finalized,
            extractors: [].into(),
        }),
        ForeignChain::Fogo,
    )]
    fn foreign_chain_rpc_request_chain__should_return_correct_chain(
        #[case] request: ForeignChainRpcRequest,
        #[case] expected_chain: ForeignChain,
    ) {
        assert_eq!(request.chain(), expected_chain);
    }
}
