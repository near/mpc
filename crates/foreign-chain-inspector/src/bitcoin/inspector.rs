use jsonrpsee::core::client::ClientT;

use crate::bitcoin::{BitcoinExtractedValue, BitcoinTransactionHash};
use crate::{
    BlockConfirmations, ClassifyRpcOutcome, ForeignChainInspectionError, ForeignChainInspector,
    NetworkFingerprint, NetworkFingerprintInspector, Verdict,
};
use foreign_chain_rpc_interfaces::bitcoin::{
    GetBlockHashArgs, GetBlockHashResponse, GetBlockHeaderArgs, GetBlockHeaderVerboseResponse,
    GetRawTransactionArgs, GetRawTransactionVerboseResponse, TransportBitcoinBlockHash,
    TransportBitcoinTransactionHash,
};

/// <https://developer.bitcoin.org/reference/rpc/getrawtransaction.html>
const GET_RAW_TRANSACTION_METHOD: &str = "getrawtransaction";
const VERBOSE_RESPONSE: bool = true;

/// <https://developer.bitcoin.org/reference/rpc/getblockheader.html>
const GET_BLOCK_HEADER_METHOD: &str = "getblockheader";
/// <https://developer.bitcoin.org/reference/rpc/getblockhash.html>
const GET_BLOCK_HASH_METHOD: &str = "getblockhash";

/// Bitcoin has no chain id, so the genesis block is what tells the networks apart.
const GENESIS_BLOCK_HEIGHT: u64 = 0;

#[derive(Clone)]
pub struct BitcoinInspector<Client> {
    client: Client,
}

impl<Client> NetworkFingerprintInspector for BitcoinInspector<Client>
where
    Client: ClientT + Send + Sync,
{
    async fn network_fingerprint(&self) -> Result<NetworkFingerprint, ForeignChainInspectionError> {
        let args = GetBlockHashArgs {
            height: GENESIS_BLOCK_HEIGHT,
        };
        let genesis_hash: GetBlockHashResponse = self
            .client
            .request(GET_BLOCK_HASH_METHOD, &args)
            .await
            .classified()?;
        Ok(NetworkFingerprint::new(genesis_hash.canonical_text()))
    }

    fn canonical_fingerprint(fingerprint: &str) -> NetworkFingerprint {
        NetworkFingerprint::new(GetBlockHashResponse(fingerprint.to_owned()).canonical_text())
    }
}

impl<Client> ForeignChainInspector for BitcoinInspector<Client>
where
    Client: ClientT + Send + Sync,
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
    ) -> Result<Verdict<BitcoinExtractedValue>, ForeignChainInspectionError> {
        let request_parameters = GetRawTransactionArgs {
            transaction_hash: TransportBitcoinTransactionHash::from(*transaction),
            verbose: VERBOSE_RESPONSE,
        };

        // TODO(#1978): add retry mechanism if the error from the request is transient
        let rpc_response: GetRawTransactionVerboseResponse = self
            .client
            .request(GET_RAW_TRANSACTION_METHOD, &request_parameters)
            .await
            .classified()?;

        let transaction_block_confirmation = rpc_response.confirmations.into();
        let enough_block_confirmations =
            block_confirmations_threshold <= transaction_block_confirmation;

        if !enough_block_confirmations {
            return Err(ForeignChainInspectionError::NotEnoughBlockConfirmations {
                expected: block_confirmations_threshold,
                got: transaction_block_confirmation,
            });
        }

        let (block_height, canonical_blockhash) = self
            .canonical_blockhash_at_height_of(rpc_response.blockhash)
            .await?;
        if canonical_blockhash != rpc_response.blockhash {
            // Bitcoin block hashes travel over JSON-RPC in reversed ("RPC byte order") form, so
            // the bytes recorded here are reversed relative to the on-chain orientation a block
            // explorer expects. A triager reading this verdict needs to reverse the hex to look
            // the block up.
            return Ok(Verdict::NonCanonicalBlock {
                block_number: block_height,
                receipt_hash: (*rpc_response.blockhash).to_vec().into(),
                canonical_hash: (*canonical_blockhash).to_vec().into(),
            });
        }

        let extracted_values = extractors
            .iter()
            .map(|extractor| extractor.extract_value(&rpc_response))
            .collect();

        Ok(Verdict::Extracted(extracted_values))
    }
}

impl<Client> BitcoinInspector<Client>
where
    Client: ClientT + Send + Sync,
{
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// The height of the receipt's block, resolved via `getblockheader`, and the canonical
    /// hash at that height via `getblockhash`. `getblockhash` only ever returns canonical
    /// blocks, so a receipt block disagreeing with it was anchored to a side block (stale tx
    /// index, partially-applied reorg, divergent RPC backend, etc.).
    ///
    /// The two RPC calls are necessarily sequential — `getblockhash`'s height parameter
    /// depends on `getblockheader`'s response — so a reorg landing between them could in
    /// principle yield a spurious [`Verdict::NonCanonicalBlock`]. The caller is expected to
    /// retry.
    ///
    /// Failures from the RPCs themselves ("Block not found" / "block height out of range")
    /// surface as [`RpcRequestRejected`](crate::ForeignChainInspectionError::RpcRequestRejected)
    /// rather than [`Verdict::NonCanonicalBlock`]; mapping those error messages to a more
    /// specific outcome is left to a follow-up.
    async fn canonical_blockhash_at_height_of(
        &self,
        receipt_blockhash: TransportBitcoinBlockHash,
    ) -> Result<(u64, TransportBitcoinBlockHash), ForeignChainInspectionError> {
        let get_block_header_args = GetBlockHeaderArgs {
            blockhash: receipt_blockhash,
            verbose: VERBOSE_RESPONSE,
        };
        let block: GetBlockHeaderVerboseResponse = self
            .client
            .request(GET_BLOCK_HEADER_METHOD, &get_block_header_args)
            .await
            .classified()?;

        // Defensive: `getblockheader` looks the header up *by hash*, so a well-behaved backend
        // always echoes back the hash we queried
        if block.hash != receipt_blockhash {
            return Err(ForeignChainInspectionError::InconsistentRpcResponse {
                requested_hash: (*receipt_blockhash).to_vec().into(),
                returned_hash: (*block.hash).to_vec().into(),
            });
        }

        let get_block_hash_args = GetBlockHashArgs {
            height: block.height,
        };
        let canonical_blockhash: TransportBitcoinBlockHash = self
            .client
            .request(GET_BLOCK_HASH_METHOD, &get_block_hash_args)
            .await
            .classified()?;

        Ok((block.height, canonical_blockhash))
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
