use foreign_chain_rpc_interfaces::evm::Log;
use near_mpc_contract_interface::types as dtos;

use crate::BlockConfirmations;
use crate::EthereumFinality;
use crate::bitcoin::BitcoinExtractedValue;
use crate::bitcoin::inspector::BitcoinExtractor;
use crate::evm::inspector::{EvmChain, EvmExtractedValue, EvmExtractor};
use crate::starknet::StarknetExtractedValue;
use crate::starknet::inspector::{StarknetExtractor, StarknetFinality};

#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("unsupported variant for conversion: {context}")]
    UnsupportedVariant { context: &'static str },
    #[error("integer overflow during conversion: {context}")]
    IntegerOverflow { context: &'static str },
}

impl From<dtos::BlockConfirmations> for BlockConfirmations {
    fn from(value: dtos::BlockConfirmations) -> Self {
        BlockConfirmations::from(value.0)
    }
}

impl From<BlockConfirmations> for dtos::BlockConfirmations {
    fn from(value: BlockConfirmations) -> Self {
        dtos::BlockConfirmations(*value)
    }
}

impl From<EthereumFinality> for dtos::EvmFinality {
    fn from(value: EthereumFinality) -> Self {
        match value {
            EthereumFinality::Finalized => dtos::EvmFinality::Finalized,
            EthereumFinality::Safe => dtos::EvmFinality::Safe,
            EthereumFinality::Latest => dtos::EvmFinality::Latest,
        }
    }
}

impl TryFrom<dtos::EvmFinality> for EthereumFinality {
    type Error = ConversionError;
    fn try_from(value: dtos::EvmFinality) -> Result<Self, Self::Error> {
        match value {
            dtos::EvmFinality::Finalized => Ok(EthereumFinality::Finalized),
            dtos::EvmFinality::Safe => Ok(EthereumFinality::Safe),
            dtos::EvmFinality::Latest => Ok(EthereumFinality::Latest),
            _ => Err(ConversionError::UnsupportedVariant {
                context: "EvmFinality",
            }),
        }
    }
}

fn log_to_evm_log(value: Log) -> dtos::EvmLog {
    dtos::EvmLog {
        removed: value.removed,
        log_index: value.log_index.as_u64(),
        transaction_index: value.transaction_index.as_u64(),
        transaction_hash: dtos::Hash256(value.transaction_hash.0),
        block_hash: dtos::Hash256(value.block_hash.0),
        block_number: value.block_number.as_u64(),
        address: dtos::Hash160(value.address.0),
        data: value.data,
        topics: value
            .topics
            .into_iter()
            .map(|t| dtos::Hash256(t.0))
            .collect(),
    }
}

fn evm_log_to_log(value: dtos::EvmLog) -> Log {
    Log {
        removed: value.removed,
        log_index: ethereum_types::U64::from(value.log_index),
        transaction_index: ethereum_types::U64::from(value.transaction_index),
        transaction_hash: ethereum_types::H256(value.transaction_hash.0),
        block_hash: ethereum_types::H256(value.block_hash.0),
        block_number: ethereum_types::U64::from(value.block_number),
        address: ethereum_types::H160(value.address.0),
        data: value.data,
        topics: value
            .topics
            .into_iter()
            .map(|t| ethereum_types::H256(t.0))
            .collect(),
    }
}

impl From<BitcoinExtractor> for dtos::BitcoinExtractor {
    fn from(value: BitcoinExtractor) -> Self {
        match value {
            BitcoinExtractor::BlockHash => dtos::BitcoinExtractor::BlockHash,
        }
    }
}

impl TryFrom<dtos::BitcoinExtractor> for BitcoinExtractor {
    type Error = ConversionError;
    fn try_from(value: dtos::BitcoinExtractor) -> Result<Self, Self::Error> {
        match value {
            dtos::BitcoinExtractor::BlockHash => Ok(BitcoinExtractor::BlockHash),
            _ => Err(ConversionError::UnsupportedVariant {
                context: "BitcoinExtractor",
            }),
        }
    }
}

impl From<BitcoinExtractedValue> for dtos::BitcoinExtractedValue {
    fn from(value: BitcoinExtractedValue) -> Self {
        match value {
            BitcoinExtractedValue::BlockHash(hash) => {
                dtos::BitcoinExtractedValue::BlockHash(dtos::Hash256(hash.into()))
            }
        }
    }
}

impl TryFrom<dtos::BitcoinExtractedValue> for BitcoinExtractedValue {
    type Error = ConversionError;
    fn try_from(value: dtos::BitcoinExtractedValue) -> Result<Self, Self::Error> {
        match value {
            dtos::BitcoinExtractedValue::BlockHash(hash) => {
                Ok(BitcoinExtractedValue::BlockHash(hash.0.into()))
            }
            _ => Err(ConversionError::UnsupportedVariant {
                context: "BitcoinExtractedValue",
            }),
        }
    }
}

impl From<EvmExtractor> for dtos::EvmExtractor {
    fn from(value: EvmExtractor) -> Self {
        match value {
            EvmExtractor::BlockHash => dtos::EvmExtractor::BlockHash,
            EvmExtractor::Log { log_index } => dtos::EvmExtractor::Log { log_index },
        }
    }
}

impl TryFrom<dtos::EvmExtractor> for EvmExtractor {
    type Error = ConversionError;
    fn try_from(value: dtos::EvmExtractor) -> Result<Self, Self::Error> {
        match value {
            dtos::EvmExtractor::BlockHash => Ok(EvmExtractor::BlockHash),
            dtos::EvmExtractor::Log { log_index } => Ok(EvmExtractor::Log { log_index }),
            _ => Err(ConversionError::UnsupportedVariant {
                context: "EvmExtractor",
            }),
        }
    }
}

impl<Chain: EvmChain> From<EvmExtractedValue<Chain>> for dtos::EvmExtractedValue {
    fn from(value: EvmExtractedValue<Chain>) -> Self {
        match value {
            EvmExtractedValue::BlockHash(hash) => {
                dtos::EvmExtractedValue::BlockHash(dtos::Hash256(hash.into()))
            }
            EvmExtractedValue::Log(log) => dtos::EvmExtractedValue::Log(log_to_evm_log(log)),
        }
    }
}

impl<Chain: EvmChain> TryFrom<dtos::EvmExtractedValue> for EvmExtractedValue<Chain> {
    type Error = ConversionError;
    fn try_from(value: dtos::EvmExtractedValue) -> Result<Self, Self::Error> {
        match value {
            dtos::EvmExtractedValue::BlockHash(hash) => {
                Ok(EvmExtractedValue::BlockHash(hash.0.into()))
            }
            dtos::EvmExtractedValue::Log(log) => {
                Ok(EvmExtractedValue::Log(evm_log_to_log(log)))
            }
            _ => Err(ConversionError::UnsupportedVariant {
                context: "EvmExtractedValue",
            }),
        }
    }
}

impl From<BitcoinExtractedValue> for dtos::ExtractedValue {
    fn from(value: BitcoinExtractedValue) -> Self {
        dtos::ExtractedValue::BitcoinExtractedValue(value.into())
    }
}

impl<Chain: EvmChain> From<EvmExtractedValue<Chain>> for dtos::ExtractedValue {
    fn from(value: EvmExtractedValue<Chain>) -> Self {
        dtos::ExtractedValue::EvmExtractedValue(value.into())
    }
}

impl From<StarknetFinality> for dtos::StarknetFinality {
    fn from(value: StarknetFinality) -> Self {
        match value {
            StarknetFinality::AcceptedOnL2 => dtos::StarknetFinality::AcceptedOnL2,
            StarknetFinality::AcceptedOnL1 => dtos::StarknetFinality::AcceptedOnL1,
        }
    }
}

impl TryFrom<dtos::StarknetFinality> for StarknetFinality {
    type Error = ConversionError;
    fn try_from(value: dtos::StarknetFinality) -> Result<Self, Self::Error> {
        match value {
            dtos::StarknetFinality::AcceptedOnL2 => Ok(StarknetFinality::AcceptedOnL2),
            dtos::StarknetFinality::AcceptedOnL1 => Ok(StarknetFinality::AcceptedOnL1),
            _ => Err(ConversionError::UnsupportedVariant {
                context: "StarknetFinality",
            }),
        }
    }
}

impl TryFrom<StarknetExtractor> for dtos::StarknetExtractor {
    type Error = ConversionError;
    fn try_from(value: StarknetExtractor) -> Result<Self, Self::Error> {
        match value {
            StarknetExtractor::BlockHash => Ok(dtos::StarknetExtractor::BlockHash),
            StarknetExtractor::Log { log_index } => Ok(dtos::StarknetExtractor::Log {
                log_index: u64::try_from(log_index).map_err(|_| {
                    ConversionError::IntegerOverflow {
                        context: "StarknetExtractor::Log log_index exceeds u64",
                    }
                })?,
            }),
        }
    }
}

impl TryFrom<dtos::StarknetExtractor> for StarknetExtractor {
    type Error = ConversionError;
    fn try_from(value: dtos::StarknetExtractor) -> Result<Self, Self::Error> {
        match value {
            dtos::StarknetExtractor::BlockHash => Ok(StarknetExtractor::BlockHash),
            dtos::StarknetExtractor::Log { log_index } => Ok(StarknetExtractor::Log {
                log_index: usize::try_from(log_index).map_err(|_| {
                    ConversionError::IntegerOverflow {
                        context: "StarknetExtractor::Log log_index exceeds platform usize",
                    }
                })?,
            }),
            _ => Err(ConversionError::UnsupportedVariant {
                context: "StarknetExtractor",
            }),
        }
    }
}

impl From<StarknetExtractedValue> for dtos::StarknetExtractedValue {
    fn from(value: StarknetExtractedValue) -> Self {
        match value {
            StarknetExtractedValue::BlockHash(hash) => {
                dtos::StarknetExtractedValue::BlockHash(dtos::StarknetFelt(hash.into()))
            }
            StarknetExtractedValue::Log(log) => dtos::StarknetExtractedValue::Log(log),
        }
    }
}

impl TryFrom<dtos::StarknetExtractedValue> for StarknetExtractedValue {
    type Error = ConversionError;
    fn try_from(value: dtos::StarknetExtractedValue) -> Result<Self, Self::Error> {
        match value {
            dtos::StarknetExtractedValue::BlockHash(felt) => {
                Ok(StarknetExtractedValue::BlockHash(felt.0.into()))
            }
            dtos::StarknetExtractedValue::Log(log) => Ok(StarknetExtractedValue::Log(log)),
            _ => Err(ConversionError::UnsupportedVariant {
                context: "StarknetExtractedValue",
            }),
        }
    }
}

impl From<StarknetExtractedValue> for dtos::ExtractedValue {
    fn from(value: StarknetExtractedValue) -> Self {
        dtos::ExtractedValue::StarknetExtractedValue(value.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abstract_chain::AbstractBlockHash;
    use crate::abstract_chain::inspector::{AbstractExtractedValue, AbstractExtractor};
    use crate::bitcoin::BitcoinBlockHash;
    use crate::bnb::BnbBlockHash;
    use crate::bnb::inspector::{BnbExtractedValue, BnbExtractor};
    use crate::starknet::StarknetBlockHash;
    use assert_matches::assert_matches;
    use foreign_chain_rpc_interfaces::evm::Log;

    #[test]
    fn block_confirmations_roundtrip() {
        let contract = dtos::BlockConfirmations(42);
        let inspector = BlockConfirmations::from(contract.clone());
        let back = dtos::BlockConfirmations::from(inspector);
        assert_eq!(contract, back);
    }

    #[test]
    fn ethereum_finality_to_evm_finality() {
        assert_eq!(
            dtos::EvmFinality::Finalized,
            dtos::EvmFinality::from(EthereumFinality::Finalized)
        );
        assert_eq!(
            dtos::EvmFinality::Safe,
            dtos::EvmFinality::from(EthereumFinality::Safe)
        );
        assert_eq!(
            dtos::EvmFinality::Latest,
            dtos::EvmFinality::from(EthereumFinality::Latest)
        );
    }

    #[test]
    fn evm_finality_to_ethereum_finality() {
        assert_eq!(
            EthereumFinality::Finalized,
            EthereumFinality::try_from(dtos::EvmFinality::Finalized).unwrap()
        );
        assert_eq!(
            EthereumFinality::Safe,
            EthereumFinality::try_from(dtos::EvmFinality::Safe).unwrap()
        );
        assert_eq!(
            EthereumFinality::Latest,
            EthereumFinality::try_from(dtos::EvmFinality::Latest).unwrap()
        );
    }

    #[test]
    fn bitcoin_extractor_roundtrip() {
        let inspector = BitcoinExtractor::BlockHash;
        let contract = dtos::BitcoinExtractor::from(inspector.clone());
        let back = BitcoinExtractor::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn bitcoin_extracted_value_roundtrip() {
        let hash = BitcoinBlockHash::from([0xab; 32]);
        let inspector = BitcoinExtractedValue::BlockHash(hash);
        let contract = dtos::BitcoinExtractedValue::from(inspector.clone());
        let back = BitcoinExtractedValue::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn abstract_extractor_block_hash_roundtrip() {
        let inspector = AbstractExtractor::BlockHash;
        let contract = dtos::EvmExtractor::from(inspector.clone());
        let back = AbstractExtractor::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn abstract_extractor_log_roundtrip() {
        let inspector = AbstractExtractor::Log { log_index: 5 };
        let contract = dtos::EvmExtractor::from(inspector.clone());
        assert_matches!(contract, dtos::EvmExtractor::Log { log_index: 5 });
        let back = AbstractExtractor::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn abstract_extracted_value_block_hash_roundtrip() {
        let hash = AbstractBlockHash::from([0xef; 32]);
        let inspector = AbstractExtractedValue::BlockHash(hash);
        let contract = dtos::EvmExtractedValue::from(inspector.clone());
        let back = AbstractExtractedValue::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn log_to_evm_log_roundtrip() {
        let log = Log {
            removed: false,
            log_index: ethereum_types::U64::from(3),
            transaction_index: ethereum_types::U64::from(1),
            transaction_hash: ethereum_types::H256([0xaa; 32]),
            block_hash: ethereum_types::H256([0xbb; 32]),
            block_number: ethereum_types::U64::from(100),
            address: ethereum_types::H160([0xcc; 20]),
            data: "0xdeadbeef".to_string(),
            topics: vec![ethereum_types::H256([0xdd; 32])],
        };
        let evm_log = log_to_evm_log(log.clone());
        assert_eq!(evm_log.log_index, 3);
        assert_eq!(evm_log.address.0, [0xcc; 20]);
        let back = evm_log_to_log(evm_log);
        assert_eq!(log, back);
    }

    #[test]
    fn abstract_extracted_value_log_roundtrip() {
        let log = Log {
            removed: false,
            log_index: ethereum_types::U64::from(0),
            transaction_index: ethereum_types::U64::from(0),
            transaction_hash: ethereum_types::H256([0xaa; 32]),
            block_hash: ethereum_types::H256([0xbb; 32]),
            block_number: ethereum_types::U64::from(42),
            address: ethereum_types::H160([0xcc; 20]),
            data: String::new(),
            topics: vec![],
        };
        let inspector = AbstractExtractedValue::Log(log);
        let contract = dtos::EvmExtractedValue::from(inspector.clone());
        assert_matches!(contract, dtos::EvmExtractedValue::Log(_));
        let back = AbstractExtractedValue::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn bnb_extractor_block_hash_roundtrip() {
        let inspector = BnbExtractor::BlockHash;
        let contract = dtos::EvmExtractor::from(inspector.clone());
        let back = BnbExtractor::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn bnb_extractor_log_roundtrip() {
        let inspector = BnbExtractor::Log { log_index: 5 };
        let contract = dtos::EvmExtractor::from(inspector.clone());
        assert_matches!(contract, dtos::EvmExtractor::Log { log_index: 5 });
        let back = BnbExtractor::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn bnb_extracted_value_block_hash_roundtrip() {
        let hash = BnbBlockHash::from([0xef; 32]);
        let inspector = BnbExtractedValue::BlockHash(hash);
        let contract = dtos::EvmExtractedValue::from(inspector.clone());
        let back = BnbExtractedValue::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn bnb_extracted_value_log_roundtrip() {
        let log = Log {
            removed: false,
            log_index: ethereum_types::U64::from(0),
            transaction_index: ethereum_types::U64::from(0),
            transaction_hash: ethereum_types::H256([0xaa; 32]),
            block_hash: ethereum_types::H256([0xbb; 32]),
            block_number: ethereum_types::U64::from(42),
            address: ethereum_types::H160([0xcc; 20]),
            data: String::new(),
            topics: vec![],
        };
        let inspector = BnbExtractedValue::Log(log);
        let contract = dtos::EvmExtractedValue::from(inspector.clone());
        assert_matches!(contract, dtos::EvmExtractedValue::Log(_));
        let back = BnbExtractedValue::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn starknet_finality_roundtrip() {
        assert_eq!(
            dtos::StarknetFinality::AcceptedOnL2,
            dtos::StarknetFinality::from(StarknetFinality::AcceptedOnL2)
        );
        assert_eq!(
            dtos::StarknetFinality::AcceptedOnL1,
            dtos::StarknetFinality::from(StarknetFinality::AcceptedOnL1)
        );
        assert_eq!(
            StarknetFinality::AcceptedOnL2,
            StarknetFinality::try_from(dtos::StarknetFinality::AcceptedOnL2).unwrap()
        );
        assert_eq!(
            StarknetFinality::AcceptedOnL1,
            StarknetFinality::try_from(dtos::StarknetFinality::AcceptedOnL1).unwrap()
        );
    }

    #[test]
    fn starknet_extractor_roundtrip() {
        let inspector = StarknetExtractor::BlockHash;
        let contract = dtos::StarknetExtractor::try_from(inspector.clone()).unwrap();
        let back = StarknetExtractor::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn starknet_extracted_value_roundtrip() {
        let hash = StarknetBlockHash::from([0xab; 32]);
        let inspector = StarknetExtractedValue::BlockHash(hash);
        let contract = dtos::StarknetExtractedValue::from(inspector.clone());
        let back = StarknetExtractedValue::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }
}
