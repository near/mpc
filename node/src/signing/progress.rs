use crate::indexer::types::ChainRespondArgs;

#[derive(Default)]
pub struct SignatureComputationProgress {
    pub attempts: u64,
    pub computed_response: Option<ChainRespondArgs>,
    pub last_response_submission: Option<near_time::Instant>,
}
