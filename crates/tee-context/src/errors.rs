#[derive(Debug, thiserror::Error)]
pub enum TeeContextError {
    #[error("allowed-hashes watcher closed before delivering an initial value")]
    HashWatcherClosed,
    #[error(transparent)]
    ContractCall(
        #[from]
        near_mpc_contract_interface::client::MpcContractHandleError<
            chain_gateway::errors::ChainGatewayError,
        >,
    ),
}
