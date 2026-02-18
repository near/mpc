use std::borrow::Cow;

use non_empty_collections::NonEmptyBTreeMap;
use serde::{Deserialize, Serialize};

use crate::config::foreign_chains::auth;
use crate::config::foreign_chains::{self, ForeignChainProviderConfig};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EthereumChainConfig {
    pub timeout_sec: u64,
    pub max_retries: u64,
    pub providers: NonEmptyBTreeMap<String, EthereumProviderConfig>,
}

impl EthereumChainConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        foreign_chains::validate_chain_config(
            "ethereum",
            self.timeout_sec,
            self.max_retries,
            &self.providers,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EthereumProviderConfig {
    pub rpc_url: String,
    pub api_variant: EthereumApiVariant,
    #[serde(default)]
    pub auth: auth::AuthConfig,
}

impl ForeignChainProviderConfig for EthereumProviderConfig {
    fn rpc_url(&self) -> Cow<'_, str> {
        self.auth.strip_placeholder(&self.rpc_url)
    }

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
