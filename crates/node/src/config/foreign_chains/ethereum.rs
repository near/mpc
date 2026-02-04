use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::config::foreign_chains;
use crate::config::foreign_chains::auth;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumChainConfig {
    pub timeout_sec: u64,
    pub max_retries: u64,
    pub providers: BTreeMap<String, EthereumProviderConfig>,
}

impl EthereumChainConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        foreign_chains::validate_chain_config(
            "ethereum",
            self.timeout_sec,
            &self.providers,
            |provider| provider.rpc_url.as_str(),
            |provider, provider_name| provider.validate("ethereum", provider_name),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumProviderConfig {
    pub rpc_url: String,
    pub api_variant: EthereumApiVariant,
    #[serde(default)]
    pub auth: auth::AuthConfig,
}

impl EthereumProviderConfig {
    fn validate(&self, chain_label: &str, provider_name: &str) -> anyhow::Result<()> {
        auth::validate_auth_config(&self.auth, &self.rpc_url, chain_label, provider_name)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum EthereumApiVariant {
    Standard,
    Alchemy,
    Infura,
    Quicknode,
    Ankr,
}
