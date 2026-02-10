use jsonrpsee::core::client::ClientT;

use crate::bitcoin::{BitcoinExtractedValue, BitcoinTransactionHash};
use crate::rpc_schema::bitcoin::{
    GetRawTransactionArgs, GetRawTransactionVerboseResponse, TransportBitcoinTransactionHash,
};
use crate::{BlockConfirmations, ForeignChainInspectionError, ForeignChainInspector};

/// https://developer.bitcoin.org/reference/rpc/getrawtransaction.html
const GET_RAW_TRANSACTION_METHOD: &str = "getrawtransaction";
const VERBOSE_RESPONSE: bool = true;

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
