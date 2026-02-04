use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::config::foreign_chains;
use crate::config::foreign_chains::auth;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SolanaChainConfig {
    pub timeout_sec: u64,
    pub max_retries: u64,
    pub providers: BTreeMap<String, SolanaProviderConfig>,
}

impl SolanaChainConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        foreign_chains::validate_chain_config(
            "solana",
            self.timeout_sec,
            self.max_retries,
            &self.providers,
            |provider| provider.rpc_url.as_str(),
            |provider, provider_name| provider.validate("solana", provider_name),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SolanaProviderConfig {
    pub rpc_url: String,
    pub api_variant: SolanaApiVariant,
    #[serde(default)]
    pub auth: auth::AuthConfig,
}

impl SolanaProviderConfig {
    fn validate(&self, chain_label: &str, provider_name: &str) -> anyhow::Result<()> {
        auth::validate_auth_config(&self.auth, &self.rpc_url, chain_label, provider_name)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum SolanaApiVariant {
    Standard,
    Alchemy,
    Helius,
    Quicknode,
    Ankr,
}
