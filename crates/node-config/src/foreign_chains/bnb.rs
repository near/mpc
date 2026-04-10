use std::borrow::Cow;

use near_mpc_bounded_collections::NonEmptyBTreeMap;
use serde::{Deserialize, Serialize};

use crate::foreign_chains::auth;
use crate::foreign_chains::{self, ForeignChainProviderConfig};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BnbChainConfig {
    pub timeout_sec: u64,
    pub max_retries: u64,
    pub providers: NonEmptyBTreeMap<String, BnbProviderConfig>,
}

impl BnbChainConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        foreign_chains::validate_chain_config(
            "bnb",
            self.timeout_sec,
            self.max_retries,
            &self.providers,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BnbProviderConfig {
    pub rpc_url: String,
    pub api_variant: BnbApiVariant,
    #[serde(default)]
    pub auth: auth::AuthConfig,
}

impl ForeignChainProviderConfig for BnbProviderConfig {
    fn rpc_url(&self) -> Cow<'_, str> {
        self.auth.strip_placeholder(&self.rpc_url)
    }

    fn validate(&self, chain_label: &str, provider_name: &str) -> anyhow::Result<()> {
        auth::validate_auth_config(&self.auth, &self.rpc_url, chain_label, provider_name)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum BnbApiVariant {
    Standard,
    Alchemy,
    Infura,
    Quicknode,
    Ankr,
}
