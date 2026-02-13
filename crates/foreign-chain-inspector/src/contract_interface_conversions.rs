use contract_interface::types as dtos;

use crate::BlockConfirmations;
use crate::EthereumFinality;
use crate::abstract_chain::inspector::{AbstractExtractedValue, AbstractExtractor};
use crate::bitcoin::BitcoinExtractedValue;
use crate::bitcoin::inspector::BitcoinExtractor;

#[derive(Debug, thiserror::Error)]
#[error("unsupported variant for conversion: {context}")]
pub struct UnsupportedVariantError {
    pub context: &'static str,
}

// --- BlockConfirmations ---

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

// --- EthereumFinality <-> EvmFinality ---

impl From<EthereumFinality> for dtos::EvmFinality {
    fn from(value: EthereumFinality) -> Self {
        match value {
            EthereumFinality::Finalized => dtos::EvmFinality::Finalized,
            EthereumFinality::Safe => dtos::EvmFinality::Safe,
        }
    }
}

impl TryFrom<dtos::EvmFinality> for EthereumFinality {
    type Error = UnsupportedVariantError;
    fn try_from(value: dtos::EvmFinality) -> Result<Self, Self::Error> {
        match value {
            dtos::EvmFinality::Finalized => Ok(EthereumFinality::Finalized),
            dtos::EvmFinality::Safe => Ok(EthereumFinality::Safe),
            _ => Err(UnsupportedVariantError {
                context: "EvmFinality",
            }),
        }
    }
}

// --- BitcoinExtractor ---

impl From<BitcoinExtractor> for dtos::BitcoinExtractor {
    fn from(value: BitcoinExtractor) -> Self {
        match value {
            BitcoinExtractor::BlockHash => dtos::BitcoinExtractor::BlockHash,
        }
    }
}

impl TryFrom<dtos::BitcoinExtractor> for BitcoinExtractor {
    type Error = UnsupportedVariantError;
    fn try_from(value: dtos::BitcoinExtractor) -> Result<Self, Self::Error> {
        match value {
            dtos::BitcoinExtractor::BlockHash => Ok(BitcoinExtractor::BlockHash),
            _ => Err(UnsupportedVariantError {
                context: "BitcoinExtractor",
            }),
        }
    }
}

// --- BitcoinExtractedValue ---

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
    type Error = UnsupportedVariantError;
    fn try_from(value: dtos::BitcoinExtractedValue) -> Result<Self, Self::Error> {
        match value {
            dtos::BitcoinExtractedValue::BlockHash(hash) => {
                Ok(BitcoinExtractedValue::BlockHash(hash.0.into()))
            }
            _ => Err(UnsupportedVariantError {
                context: "BitcoinExtractedValue",
            }),
        }
    }
}

// --- AbstractExtractor <-> EvmExtractor ---

impl TryFrom<AbstractExtractor> for dtos::EvmExtractor {
    type Error = UnsupportedVariantError;
    fn try_from(value: AbstractExtractor) -> Result<Self, Self::Error> {
        match value {
            AbstractExtractor::BlockHash => Ok(dtos::EvmExtractor::BlockHash),
            _ => Err(UnsupportedVariantError {
                context: "AbstractExtractor",
            }),
        }
    }
}

impl TryFrom<dtos::EvmExtractor> for AbstractExtractor {
    type Error = UnsupportedVariantError;
    fn try_from(value: dtos::EvmExtractor) -> Result<Self, Self::Error> {
        match value {
            dtos::EvmExtractor::BlockHash => Ok(AbstractExtractor::BlockHash),
            _ => Err(UnsupportedVariantError {
                context: "EvmExtractor",
            }),
        }
    }
}

// --- AbstractExtractedValue <-> EvmExtractedValue ---

impl TryFrom<AbstractExtractedValue> for dtos::EvmExtractedValue {
    type Error = UnsupportedVariantError;
    fn try_from(value: AbstractExtractedValue) -> Result<Self, Self::Error> {
        match value {
            AbstractExtractedValue::BlockHash(hash) => {
                Ok(dtos::EvmExtractedValue::BlockHash(dtos::Hash256(hash.into())))
            }
            _ => Err(UnsupportedVariantError {
                context: "AbstractExtractedValue",
            }),
        }
    }
}

impl TryFrom<dtos::EvmExtractedValue> for AbstractExtractedValue {
    type Error = UnsupportedVariantError;
    fn try_from(value: dtos::EvmExtractedValue) -> Result<Self, Self::Error> {
        match value {
            dtos::EvmExtractedValue::BlockHash(hash) => {
                Ok(AbstractExtractedValue::BlockHash(hash.0.into()))
            }
            _ => Err(UnsupportedVariantError {
                context: "EvmExtractedValue",
            }),
        }
    }
}

// --- BitcoinExtractedValue -> ExtractedValue (wrapper) ---

impl From<BitcoinExtractedValue> for dtos::ExtractedValue {
    fn from(value: BitcoinExtractedValue) -> Self {
        dtos::ExtractedValue::BitcoinExtractedValue(value.into())
    }
}

impl TryFrom<dtos::ExtractedValue> for BitcoinExtractedValue {
    type Error = UnsupportedVariantError;
    fn try_from(value: dtos::ExtractedValue) -> Result<Self, Self::Error> {
        match value {
            dtos::ExtractedValue::BitcoinExtractedValue(v) => v.try_into(),
            _ => Err(UnsupportedVariantError {
                context: "ExtractedValue(Bitcoin)",
            }),
        }
    }
}

// --- AbstractExtractedValue -> ExtractedValue (wrapper via EvmExtractedValue) ---

impl TryFrom<AbstractExtractedValue> for dtos::ExtractedValue {
    type Error = UnsupportedVariantError;
    fn try_from(value: AbstractExtractedValue) -> Result<Self, Self::Error> {
        let evm: dtos::EvmExtractedValue = value.try_into()?;
        Ok(dtos::ExtractedValue::EvmExtractedValue(evm))
    }
}

impl TryFrom<dtos::ExtractedValue> for AbstractExtractedValue {
    type Error = UnsupportedVariantError;
    fn try_from(value: dtos::ExtractedValue) -> Result<Self, Self::Error> {
        match value {
            dtos::ExtractedValue::EvmExtractedValue(v) => v.try_into(),
            _ => Err(UnsupportedVariantError {
                context: "ExtractedValue(Evm)",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abstract_chain::AbstractBlockHash;
    use crate::bitcoin::BitcoinBlockHash;

    #[test]
    fn block_confirmations_roundtrip() {
        let contract = dtos::BlockConfirmations(42);
        let inspector: BlockConfirmations = contract.clone().into();
        let back: dtos::BlockConfirmations = inspector.into();
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
        EthereumFinality::try_from(dtos::EvmFinality::Latest).unwrap_err();
    }

    #[test]
    fn bitcoin_extractor_roundtrip() {
        let inspector = BitcoinExtractor::BlockHash;
        let contract: dtos::BitcoinExtractor = inspector.clone().into();
        let back = BitcoinExtractor::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn bitcoin_extracted_value_roundtrip() {
        let hash = BitcoinBlockHash::from([0xab; 32]);
        let inspector = BitcoinExtractedValue::BlockHash(hash);
        let contract: dtos::BitcoinExtractedValue = inspector.clone().into();
        let back = BitcoinExtractedValue::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn abstract_extractor_block_hash_roundtrip() {
        let inspector = AbstractExtractor::BlockHash;
        let contract: dtos::EvmExtractor = inspector.clone().try_into().unwrap();
        let back = AbstractExtractor::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn abstract_extractor_log_fails_conversion() {
        let inspector = AbstractExtractor::Log { log_index: 0 };
        dtos::EvmExtractor::try_from(inspector).unwrap_err();
    }

    #[test]
    fn abstract_extracted_value_block_hash_roundtrip() {
        let hash = AbstractBlockHash::from([0xef; 32]);
        let inspector = AbstractExtractedValue::BlockHash(hash);
        let contract: dtos::EvmExtractedValue = inspector.clone().try_into().unwrap();
        let back = AbstractExtractedValue::try_from(contract).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn bitcoin_extracted_value_to_extracted_value_roundtrip() {
        let hash = BitcoinBlockHash::from([0xab; 32]);
        let inspector = BitcoinExtractedValue::BlockHash(hash);
        let wrapped: dtos::ExtractedValue = inspector.clone().into();
        assert!(matches!(
            wrapped,
            dtos::ExtractedValue::BitcoinExtractedValue(_)
        ));
        let back = BitcoinExtractedValue::try_from(wrapped).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn abstract_extracted_value_to_extracted_value_roundtrip() {
        let hash = AbstractBlockHash::from([0xef; 32]);
        let inspector = AbstractExtractedValue::BlockHash(hash);
        let wrapped: dtos::ExtractedValue = inspector.clone().try_into().unwrap();
        assert!(matches!(
            wrapped,
            dtos::ExtractedValue::EvmExtractedValue(_)
        ));
        let back = AbstractExtractedValue::try_from(wrapped).unwrap();
        assert_eq!(inspector, back);
    }

    #[test]
    fn bitcoin_extracted_value_from_evm_wrapper_fails() {
        let evm = dtos::ExtractedValue::EvmExtractedValue(dtos::EvmExtractedValue::BlockHash(
            dtos::Hash256([0; 32]),
        ));
        BitcoinExtractedValue::try_from(evm).unwrap_err();
    }

    #[test]
    fn abstract_extracted_value_from_bitcoin_wrapper_fails() {
        let btc = dtos::ExtractedValue::BitcoinExtractedValue(
            dtos::BitcoinExtractedValue::BlockHash(dtos::Hash256([0; 32])),
        );
        AbstractExtractedValue::try_from(btc).unwrap_err();
    }
}
