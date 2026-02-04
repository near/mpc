use mpc_primitives::hash::Hash32;

use crate::RpcExtractor;

struct Bitcoin;
enum BitcoinExtractor {
    BlockHash(BitcoinBlockHash),
}
struct BlockConfirmations(u64);

struct BitcoinBlock;
struct BitcoinTransaction;

type BitcoinBlockHash = Hash32<BitcoinBlock>;
type BitcoinTransactionHash = Hash32<BitcoinTransaction>;

enum BitcoinExtractedValue {
    Hash,
}
struct BitcoinRpcExtractor;

impl RpcExtractor for BitcoinExtractor {
    type Chain = Bitcoin;
    type Extractor = BitcoinExtractor;
    type Finality = BlockConfirmations;
    type ExtractedValue = BitcoinExtractedValue;
    type TxId = BitcoinTransactionHash;

    async fn extract(
        tx_id: Self::TxId,
        extractors: Vec<Self::Extractor>,
        finality: Self::Finality,
    ) -> Self::ExtractedValue {
        todo!()
    }
}

struct BitcoinRpcResponse {
    block_height: u64,
    block_hash: BitcoinBlockHash,
    /// number of confirmations on top of block_height
    confirmations: u64,
}

enum BitcoinRpcProviders {
    MempoolSpace,
}

mod mempool_space {
    use crate::{RpcClient, RpcError, bitcoin::BitcoinBlockHash};
    use reqwest::{Method, StatusCode};
    use serde::{Deserialize, Serialize, de::DeserializeOwned};

    // const BASE_URL: &str = "https://mempool.space/api";
    const TX_STATUS_PATH_FORMAT: &str = "tx/$TXID/status";
    const TX_STATUS_PATH_PLACE_HOLDER: &str = "$TXID";

    const BLOCK_TIP: &str = "/blocks/tip/height";

    #[derive(Serialize, Deserialize)]
    struct TxStatusMempoolSpaceResponse {
        confirmed: bool,
        block_height: u64,
        block_hash: BitcoinBlockHash,
        block_time: u64,
    }

    type TipHeightMempoolSpaceResponse = u64;

    #[derive(Debug, Clone)]
    struct BitcoinRpcMempoolExtractor {
        request_client: reqwest::Client,
        base_url: String,
    }

    impl BitcoinRpcMempoolExtractor {
        fn new(base_url: String) -> Self {
            let request_client = reqwest::Client::new();
            Self {
                base_url,
                request_client,
            }
        }

        async fn get_resource<T>(&self, resource_path: &str) -> Result<T, RpcError>
        where
            T: DeserializeOwned,
        {
            let rpc_url = format!("{}{}", self.base_url, resource_path);

            let tx_status_response = self
                .request_client
                .request(Method::GET, rpc_url)
                .send()
                .await
                .map_err(|_| RpcError::ClientError)?;

            if tx_status_response.status() != StatusCode::OK {
                return Err(RpcError::BadResponse);
            }

            tx_status_response
                .json()
                .await
                .map_err(|_| RpcError::BadResponse)
        }
    }

    impl RpcClient for BitcoinRpcMempoolExtractor {
        type Finality = super::BlockConfirmations;
        type TxId = super::BitcoinTransactionHash;
        type RpcResponse = super::BitcoinRpcResponse;
        // type RpcError;

        async fn get(
            &self,
            transaction: Self::TxId,
            _finality: Self::Finality,
        ) -> Result<Self::RpcResponse, RpcError> {
            let tx_status_path =
                TX_STATUS_PATH_FORMAT.replace(TX_STATUS_PATH_PLACE_HOLDER, &transaction.as_hex());

            let tx_status: TxStatusMempoolSpaceResponse =
                self.get_resource(&tx_status_path).await?;
            let tip_height: TipHeightMempoolSpaceResponse = self.get_resource(BLOCK_TIP).await?;

            let confirmations = tip_height - tx_status.block_height;

            Ok(super::BitcoinRpcResponse {
                block_height: tx_status.block_height,
                block_hash: tx_status.block_hash,
                confirmations,
            })
        }
    }
}
