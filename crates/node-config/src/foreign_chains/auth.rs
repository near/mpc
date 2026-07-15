use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};

#[serde_as]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AuthConfig {
    #[default]
    None,
    Header {
        #[serde_as(as = "DisplayFromStr")]
        name: http::HeaderName,
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum TokenConfig {
    Env { env: String },
    Val { val: String },
}

impl TokenConfig {
    pub fn resolve(&self) -> anyhow::Result<String> {
        match self {
            // TODO(#2335): do not resolve env variables this deep in the binary.
            // Should be resolved at start, preferably in the config so we can kill env configs
            //
            // One option is to have a separate secrets config file.
            TokenConfig::Env { env } => {
                std::env::var(env).with_context(|| format!("environment variable {env} is not set"))
            }
            TokenConfig::Val { val } => Ok(val.clone()),
        }
    }
}

pub(crate) fn validate_auth_config(auth: &AuthConfig, rpc_url: &str) -> anyhow::Result<()> {
    match auth {
        AuthConfig::None => Ok(()),
        AuthConfig::Header { scheme, .. } => {
            if let Some(scheme) = scheme {
                anyhow::ensure!(
                    !scheme.trim().is_empty(),
                    "the authentication header can not be empty. given: {scheme}"
                );
            }
            Ok(())
        }
        AuthConfig::Path { placeholder, .. } => {
            anyhow::ensure!(
                !placeholder.trim().is_empty(),
                "the placeholder for path authentication can not be empty. given: {placeholder}"
            );
            anyhow::ensure!(
                rpc_url.contains(placeholder),
                "the placeholder, `{placeholder}`, for path authentication is not found in the rpc url {rpc_url}"
            );
            Ok(())
        }
        AuthConfig::Query { name, .. } => {
            anyhow::ensure!(
                !name.trim().is_empty(),
                "the name of the query parameter for authentication can not be empty. Given `{name}`"
            );
            Ok(())
        }
    }
}
