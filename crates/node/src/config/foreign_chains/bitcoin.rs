use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::auth::{validate_auth_config, AuthConfig};
use super::validate_chain_config;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitcoinChainConfig {
    pub timeout_sec: u64,
    pub max_retries: u64,
    pub providers: BTreeMap<String, BitcoinProviderConfig>,
}

impl BitcoinChainConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        validate_chain_config(
            "bitcoin",
            self.timeout_sec,
            &self.providers,
            |provider| provider.rpc_url.as_str(),
            |provider, provider_name| provider.validate("bitcoin", provider_name),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitcoinProviderConfig {
    pub rpc_url: String,
    pub api_variant: BitcoinApiVariant,
    #[serde(default)]
    pub auth: AuthConfig,
}

impl BitcoinProviderConfig {
    fn validate(&self, chain_label: &str, provider_name: &str) -> anyhow::Result<()> {
        validate_auth_config(&self.auth, &self.rpc_url, chain_label, provider_name)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum BitcoinApiVariant {
    Standard,
    #[serde(alias = "blockstream")]
    #[serde(alias = "mempool-space")]
    Esplora,
}
