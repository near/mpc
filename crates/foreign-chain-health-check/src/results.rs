//! Per-provider check outcome.

#[derive(Debug)]
pub enum Status {
    Passed,
    Failed(String),
    Skipped(String),
}

#[derive(Debug)]
pub struct ProviderResult {
    pub chain: &'static str,
    pub provider: String,
    pub status: Status,
}

impl ProviderResult {
    pub fn skipped(chain: &'static str, provider: String, reason: impl Into<String>) -> Self {
        Self {
            chain,
            provider,
            status: Status::Skipped(reason.into()),
        }
    }
}
