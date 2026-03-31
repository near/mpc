use std::borrow::Cow;

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

impl AuthConfig {
    /// Returns the RPC URL with auth placeholders stripped.
    ///
    /// For `Path` auth, removes the placeholder string from the URL (returning an owned `String`).
    /// For all other auth kinds, returns the original URL by reference (zero-cost borrow).
    pub(crate) fn strip_placeholder<'a>(&self, rpc_url: &'a str) -> Cow<'a, str> {
        match self {
            AuthConfig::Path { placeholder, .. } => Cow::Owned(rpc_url.replace(placeholder, "")),
            _ => Cow::Borrowed(rpc_url),
        }
    }

    /// Returns the RPC URL with the `Path` auth placeholder substituted with the resolved token.
    ///
    /// For `Path` auth, replaces the placeholder string in the URL with the resolved token value.
    /// For all other auth kinds, returns the original URL unchanged.
    pub(crate) fn resolve_url(&self, rpc_url: &str) -> anyhow::Result<String> {
        match self {
            AuthConfig::Path { placeholder, token } => {
                let token_value = token.resolve()?;
                Ok(rpc_url.replace(placeholder.as_str(), &token_value))
            }
            _ => Ok(rpc_url.to_string()),
        }
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

pub(crate) fn validate_auth_config(
    auth: &AuthConfig,
    rpc_url: &str,
    chain_label: &str,
    provider_name: &str,
) -> anyhow::Result<()> {
    match auth {
        AuthConfig::None => Ok(()),
        AuthConfig::Header { scheme, .. } => {
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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn strip_placeholder__borrows_for_none_auth() {
        let auth = AuthConfig::None;
        let url = "https://rpc.example.com";
        let result = auth.strip_placeholder(url);
        assert_matches!(result, Cow::Borrowed(_));
        assert_eq!(result, url);
    }

    #[test]
    fn strip_placeholder__borrows_for_header_auth() {
        let auth = AuthConfig::Header {
            name: http::HeaderName::from_static("authorization"),
            scheme: Some("Bearer".to_string()),
            token: TokenConfig::Val {
                val: "secret".to_string(),
            },
        };
        let url = "https://rpc.example.com/v2/";
        let result = auth.strip_placeholder(url);
        assert_matches!(result, Cow::Borrowed(_));
        assert_eq!(result, url);
    }

    #[test]
    fn strip_placeholder__borrows_for_query_auth() {
        let auth = AuthConfig::Query {
            name: "api_key".to_string(),
            token: TokenConfig::Val {
                val: "secret".to_string(),
            },
        };
        let url = "https://rpc.example.com";
        let result = auth.strip_placeholder(url);
        assert_matches!(result, Cow::Borrowed(_));
        assert_eq!(result, url);
    }

    #[test]
    fn strip_placeholder__strips_placeholder_for_path_auth() {
        let auth = AuthConfig::Path {
            placeholder: "{api_key}".to_string(),
            token: TokenConfig::Val {
                val: "secret".to_string(),
            },
        };
        let url = "https://rpc.ankr.com/near/{api_key}";
        let result = auth.strip_placeholder(url);
        assert_matches!(result, Cow::Owned(_));
        assert_eq!(result, "https://rpc.ankr.com/near/");
    }

    #[test]
    fn resolve_url__returns_original_for_none_auth() {
        let auth = AuthConfig::None;
        let url = "https://rpc.example.com";
        let result = auth.resolve_url(url).unwrap();
        assert_eq!(result, url);
    }

    #[test]
    fn resolve_url__returns_original_for_header_auth() {
        let auth = AuthConfig::Header {
            name: http::HeaderName::from_static("authorization"),
            scheme: Some("Bearer".to_string()),
            token: TokenConfig::Val {
                val: "secret".to_string(),
            },
        };
        let url = "https://rpc.example.com/v2/";
        let result = auth.resolve_url(url).unwrap();
        assert_eq!(result, url);
    }

    #[test]
    fn resolve_url__substitutes_placeholder_for_path_auth() {
        let auth = AuthConfig::Path {
            placeholder: "{api_key}".to_string(),
            token: TokenConfig::Val {
                val: "my-secret-key".to_string(),
            },
        };
        let url = "https://abstract-mainnet.g.alchemy.com/v2/{api_key}";
        let result = auth.resolve_url(url).unwrap();
        assert_eq!(result, "https://abstract-mainnet.g.alchemy.com/v2/my-secret-key");
    }

    #[test]
    fn resolve_url__returns_original_for_query_auth() {
        let auth = AuthConfig::Query {
            name: "api_key".to_string(),
            token: TokenConfig::Val {
                val: "secret".to_string(),
            },
        };
        let url = "https://rpc.example.com";
        let result = auth.resolve_url(url).unwrap();
        assert_eq!(result, url);
    }
}
