use jsonrpsee::core::client::ClientT;

use crate::bitcoin::{BitcoinExtractedValue, BitcoinTransactionHash};
use crate::{BlockConfirmations, ForeignChainInspectionError, ForeignChainInspector};
use foreign_chain_rpc_interfaces::bitcoin::{
    GET_BLOCK_VERBOSITY_HEADER_AND_TXIDS, GetBlockArgs, GetBlockHashArgs, GetBlockResponse,
    GetRawTransactionArgs, GetRawTransactionVerboseResponse, TransportBitcoinBlockHash,
    TransportBitcoinTransactionHash,
};

/// https://developer.bitcoin.org/reference/rpc/getrawtransaction.html
const GET_RAW_TRANSACTION_METHOD: &str = "getrawtransaction";
const VERBOSE_RESPONSE: bool = true;

/// https://developer.bitcoin.org/reference/rpc/getblock.html
const GET_BLOCK_METHOD: &str = "getblock";
/// https://developer.bitcoin.org/reference/rpc/getblockhash.html
const GET_BLOCK_HASH_METHOD: &str = "getblockhash";

pub struct BitcoinInspector<Client> {
    client: Client,
}

impl<Client> ForeignChainInspector for BitcoinInspector<Client>
where
    Client: ClientT + Send,
{
    type TransactionId = BitcoinTransactionHash;
    type Finality = BlockConfirmations;
    type Extractor = BitcoinExtractor;
    type ExtractedValue = BitcoinExtractedValue;

    async fn extract(
        &self,
        transaction: BitcoinTransactionHash,
        block_confirmations_threshold: BlockConfirmations,
        extractors: Vec<BitcoinExtractor>,
    ) -> Result<Vec<BitcoinExtractedValue>, ForeignChainInspectionError> {
        let request_parameters = GetRawTransactionArgs {
            transaction_hash: TransportBitcoinTransactionHash::from(*transaction),
            verbose: VERBOSE_RESPONSE,
        };

        // TODO(#1978): add retry mechanism if the error from the request is transient
        let rpc_response: GetRawTransactionVerboseResponse = self
            .client
            .request(GET_RAW_TRANSACTION_METHOD, &request_parameters)
            .await?;

        let transaction_block_confirmation = rpc_response.confirmations.into();
        let enough_block_confirmations =
            block_confirmations_threshold <= transaction_block_confirmation;

        if !enough_block_confirmations {
            return Err(ForeignChainInspectionError::NotEnoughBlockConfirmations {
                expected: block_confirmations_threshold,
                got: transaction_block_confirmation,
            });
        }

        self.verify_block_is_canonical(rpc_response.blockhash)
            .await?;

        let extracted_values = extractors
            .iter()
            .map(|extractor| extractor.extract_value(&rpc_response))
            .collect();

        Ok(extracted_values)
    }
}

impl<Client> BitcoinInspector<Client>
where
    Client: ClientT + Send,
{
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Checks that the receipt's block is on the canonical chain by resolving its height via
    /// `getblock` and then asking the RPC for the canonical hash at that height via
    /// `getblockhash`. `getblockhash` only ever returns canonical blocks, so a mismatch means
    /// the `getrawtransaction` response was anchored to a side block (stale tx index,
    /// partially-applied reorg, divergent RPC backend, etc.).
    async fn verify_block_is_canonical(
        &self,
        receipt_blockhash: TransportBitcoinBlockHash,
    ) -> Result<(), ForeignChainInspectionError> {
        let get_block_args = GetBlockArgs {
            blockhash: receipt_blockhash,
            verbosity: GET_BLOCK_VERBOSITY_HEADER_AND_TXIDS,
        };
        let block: GetBlockResponse = self
            .client
            .request(GET_BLOCK_METHOD, &get_block_args)
            .await?;

        let get_block_hash_args = GetBlockHashArgs {
            height: block.height,
        };
        let canonical_blockhash: TransportBitcoinBlockHash = self
            .client
            .request(GET_BLOCK_HASH_METHOD, &get_block_hash_args)
            .await?;

        if canonical_blockhash != receipt_blockhash {
            return Err(ForeignChainInspectionError::NonCanonicalBlock {
                block_number: block.height,
                receipt_hash: (*receipt_blockhash).to_vec().into(),
                canonical_hash: (*canonical_blockhash).to_vec().into(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BitcoinExtractor {
    BlockHash,
}

impl BitcoinExtractor {
    fn extract_value(
        &self,
        rpc_response: &GetRawTransactionVerboseResponse,
    ) -> BitcoinExtractedValue {
        match self {
            BitcoinExtractor::BlockHash => {
                BitcoinExtractedValue::BlockHash(From::from(*rpc_response.blockhash))
            }
        }
    }
}
