use mpc_primitives::hash::Hash32;

pub mod inspector;
pub mod rpc_client;

struct BitcoinBlock;
struct BitcoinTransaction;

type BitcoinBlockHash = Hash32<BitcoinBlock>;
type BitcoinTransactionHash = Hash32<BitcoinTransaction>;
