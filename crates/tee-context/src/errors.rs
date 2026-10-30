#[derive(Debug, thiserror::Error)]
pub enum TeeContextError {
    #[error("allowed-hashes watcher closed before delivering an initial value")]
    HashWatcherClosed,
    #[error(transparent)]
    ContractCall(
        #[from] near_kit_primitives::ContractError<chain_gateway::transaction_sender::SendFailure>,
    ),
}
