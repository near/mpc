#[derive(Debug, thiserror::Error)]
pub enum TeeContextError {
    #[error("chain gateway error: {0}")]
    ChainGateway(#[from] chain_gateway::errors::ChainGatewayError),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
