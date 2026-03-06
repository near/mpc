use std::borrow::Cow;

use anyhow::Context;
use foreign_chain_inspector::RpcAuthentication;
use http::HeaderValue;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

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
    /// Returns a copy with all [`TokenConfig`] values redacted.
    pub fn redacted(&self) -> Self {
        match self {
            AuthConfig::None => AuthConfig::None,
            AuthConfig::Header {
                name,
                scheme,
                token,
            } => AuthConfig::Header {
                name: name.clone(),
                scheme: scheme.clone(),
                token: token.redacted(),
            },
            AuthConfig::Path { placeholder, token } => AuthConfig::Path {
                placeholder: placeholder.clone(),
                token: token.redacted(),
            },
            AuthConfig::Query { name, token } => AuthConfig::Query {
                name: name.clone(),
                token: token.redacted(),
            },
        }
    }

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
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum TokenConfig {
    Env { env: String },
    Val { val: String },
}

impl TokenConfig {
    /// Returns a copy with secret values replaced by `"***"`.
    ///
    /// `Env` variants keep the environment-variable name (it is not a secret),
    /// while `Val` variants have their plaintext value masked.
    pub fn redacted(&self) -> Self {
        match self {
            TokenConfig::Env { env } => TokenConfig::Env { env: env.clone() },
            TokenConfig::Val { .. } => TokenConfig::Val {
                val: "***".to_string(),
            },
        }
    }

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

impl TryInto<RpcAuthentication> for AuthConfig {
    type Error = anyhow::Error;

    // TODO: implement all branches of the conversion here
    fn try_into(self) -> Result<RpcAuthentication, Self::Error> {
        match self {
            AuthConfig::None => Ok(RpcAuthentication::KeyInUrl),
            AuthConfig::Header {
                name: header_name,
                scheme,
                token,
            } => {
                let scheme = scheme.unwrap_or_else(|| "Bearer".to_string());
                let token_value = token.resolve()?;
                let header_value = HeaderValue::from_str(&format!("{scheme} {token_value}"))?;
                Ok(RpcAuthentication::CustomHeader {
                    header_name,
                    header_value,
                })
            }
            AuthConfig::Path {
                placeholder: _,
                token: _,
            } => Ok(RpcAuthentication::KeyInUrl),
            AuthConfig::Query { name: _, token: _ } => anyhow::bail!("this is not supported yet"),
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
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

    // ---- redacted() tests ----

    #[test]
    fn token_config_redacted__masks_val() {
        let token = TokenConfig::Val {
            val: "super-secret".to_string(),
        };
        assert_eq!(
            token.redacted(),
            TokenConfig::Val {
                val: "***".to_string()
            }
        );
    }

    #[test]
    fn token_config_redacted__preserves_env_name() {
        let token = TokenConfig::Env {
            env: "MY_API_KEY".to_string(),
        };
        assert_eq!(
            token.redacted(),
            TokenConfig::Env {
                env: "MY_API_KEY".to_string()
            }
        );
    }

    #[test]
    fn auth_config_redacted__none_stays_none() {
        assert_eq!(AuthConfig::None.redacted(), AuthConfig::None);
    }

    #[test]
    fn auth_config_redacted__header_masks_token() {
        let auth = AuthConfig::Header {
            name: http::HeaderName::from_static("authorization"),
            scheme: Some("Bearer".to_string()),
            token: TokenConfig::Val {
                val: "secret".to_string(),
            },
        };
        let redacted = auth.redacted();
        assert_eq!(
            redacted,
            AuthConfig::Header {
                name: http::HeaderName::from_static("authorization"),
                scheme: Some("Bearer".to_string()),
                token: TokenConfig::Val {
                    val: "***".to_string()
                },
            }
        );
    }

    #[test]
    fn auth_config_redacted__path_masks_token() {
        let auth = AuthConfig::Path {
            placeholder: "{key}".to_string(),
            token: TokenConfig::Val {
                val: "secret".to_string(),
            },
        };
        let redacted = auth.redacted();
        assert_eq!(
            redacted,
            AuthConfig::Path {
                placeholder: "{key}".to_string(),
                token: TokenConfig::Val {
                    val: "***".to_string()
                },
            }
        );
    }

    #[test]
    fn auth_config_redacted__query_masks_token() {
        let auth = AuthConfig::Query {
            name: "api_key".to_string(),
            token: TokenConfig::Val {
                val: "secret".to_string(),
            },
        };
        let redacted = auth.redacted();
        assert_eq!(
            redacted,
            AuthConfig::Query {
                name: "api_key".to_string(),
                token: TokenConfig::Val {
                    val: "***".to_string()
                },
            }
        );
    }
}
