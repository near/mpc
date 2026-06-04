mpc_primitives::define_hash!(TonTxId, 32);
mpc_primitives::define_hash!(TonAddressHash, 32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TonFinality {
    MasterchainIncluded,
}

/// https://docs.ton.org/blockchain-basics/tolk/types/address#components
pub struct TonAddress {
    workchain: i8,
    hash: TonAddressHash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TonExtractor {
    Log { message_index: usize },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TonExtractedValue {
    Log(TonLog),
}
