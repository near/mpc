use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AuthConfig {
    None,
    Header {
        name: String,
        #[serde(default)]
        scheme: Option<String>,
        token: TokenConfig,
    },
    Path {
        placeholder: String,
        token: TokenConfig,
    },
    Query {
        name: String,
        token: TokenConfig,
    },
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum TokenConfig {
    Env { env: String },
    Val { val: String },
}

impl TokenConfig {
    pub fn resolve(&self) -> anyhow::Result<String> {
        match self {
            TokenConfig::Env { env } => {
                std::env::var(env).with_context(|| format!("environment variable {env} is not set"))
            }
            TokenConfig::Val { val } => Ok(val.clone()),
        }
    }
}

pub(crate) fn validate_auth_config(
    auth: &AuthConfig,
    rpc_url: &str,
    chain_label: &str,
    provider_name: &str,
) -> anyhow::Result<()> {
    match auth {
        AuthConfig::None => Ok(()),
        AuthConfig::Header { name, scheme, .. } => {
            anyhow::ensure!(
                !name.trim().is_empty(),
                "foreign_chains.{chain_label}.providers.{provider_name}.auth.name must be non-empty"
            );
            if let Some(scheme) = scheme {
                anyhow::ensure!(
                    !scheme.trim().is_empty(),
                    "foreign_chains.{chain_label}.providers.{provider_name}.auth.scheme must be non-empty if provided"
                );
            }
            Ok(())
        }
        AuthConfig::Path { placeholder, .. } => {
            anyhow::ensure!(
                !placeholder.trim().is_empty(),
                "foreign_chains.{chain_label}.providers.{provider_name}.auth.placeholder must be non-empty"
            );
            anyhow::ensure!(
                rpc_url.contains(placeholder),
                "foreign_chains.{chain_label}.providers.{provider_name}.rpc_url must include the path placeholder"
            );
            Ok(())
        }
        AuthConfig::Query { name, .. } => {
            anyhow::ensure!(
                !name.trim().is_empty(),
                "foreign_chains.{chain_label}.providers.{provider_name}.auth.name must be non-empty"
            );
            Ok(())
        }
    }
}
