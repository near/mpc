#![allow(dead_code)]

use mpc_primitives::hash::Hash32;

trait RpcExtractor {
    type Chain;
    type Extractor;
    type Finality;
    type ExtractedValue;

    fn extract(
        extractors: Vec<Self::Extractor>,
        finality: Self::Finality,
    ) -> impl Future<Output = Self::ExtractedValue>;
}

struct Bitcoin;
enum BitcoinExtractor {
    BlockHash(BitcoinBlockHash),
}
struct BlockConfirmations(u64);

struct BitcoinBlock;
type BitcoinBlockHash = Hash32<BitcoinBlock>;

enum BitcoinExtractedValue {
    Hash,
}

struct BitcoinRpcExtractor;

impl RpcExtractor for BitcoinExtractor {
    type Chain = Bitcoin;
    type Extractor = BitcoinExtractor;
    type Finality = BlockConfirmations;
    type ExtractedValue = BitcoinExtractedValue;

    // TODO: continue from here.
    async fn extract(
        extractors: Vec<Self::Extractor>,
        finality: Self::Finality,
    ) -> Self::ExtractedValue {
        async { todo!() }
    }
}
