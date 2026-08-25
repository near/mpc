//! Turns a foreign chain provider's configuration into a client that can talk to it, with the
//! provider's credentials already applied.

use std::time::Duration;

use anyhow::Context;
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use foreign_chain_rpc_interfaces::sui::GrpcSuiClient;
use http::{HeaderMap, HeaderName, HeaderValue};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use mpc_node_config::{AuthConfig, ForeignChainProviderConfig};

/// How a provider expects its API key to be presented.
#[derive(Debug, Clone)]
pub enum RpcAuthentication {
    /// The key is in the URL (e.g., Alchemy, QuickNode).
    /// Example: `https://eth-mainnet.alchemyapi.io/v2/your-api-key`
    KeyInUrl,
    /// Custom header for providers like NOWNodes or GetBlock.
    /// Example: key="x-api-key", value="your-secret-token"
    CustomHeader {
        header_name: HeaderName,
        header_value: HeaderValue,
    },
}

/// Builds an HTTP client with the specified authentication method, for callers that already
/// hold a resolved [`RpcAuthentication`]. Most callers want [`http_client`] instead, which
/// resolves it from a provider's config.
pub fn build_http_client(
    base_url: String,
    rpc_authentication: RpcAuthentication,
) -> Result<HttpClient, jsonrpsee::core::client::error::Error> {
    let mut headers = HeaderMap::new();

    match rpc_authentication {
        RpcAuthentication::KeyInUrl => {}
        RpcAuthentication::CustomHeader {
            header_name,
            header_value,
        } => {
            headers.insert(header_name, header_value);
        }
    }

    let client = HttpClientBuilder::default()
        .set_headers(headers)
        .build(&base_url)?;

    Ok(client)
}

/// Convert an [`AuthConfig`] into an [`RpcAuthentication`].
///
/// Shared by the MPC node and the foreign-chain config tester so both exercise the
/// exact same URL/auth handling. It lives in its own crate (rather than the
/// lightweight `mpc-node-config`) to keep `foreign-chain-inspector` out of the
/// config crate's dependency tree.
pub fn auth_config_to_rpc_auth(
    auth: AuthConfig,
    rpc_url: &mut String,
) -> anyhow::Result<RpcAuthentication> {
    match auth {
        AuthConfig::None => Ok(RpcAuthentication::KeyInUrl),
        AuthConfig::Header {
            name: header_name,
            scheme,
            token,
        } => {
            let token_value = token.resolve()?;
            let header_value_str = match scheme {
                Some(scheme) => format!("{scheme} {token_value}"),
                None => token_value,
            };
            let mut header_value = HeaderValue::from_str(&header_value_str)?;
            // Redacts the token from `Debug` output and excludes it from HPACK
            // dynamic-table indexing on h2 connections.
            header_value.set_sensitive(true);
            Ok(RpcAuthentication::CustomHeader {
                header_name,
                header_value,
            })
        }
        AuthConfig::Path { placeholder, token } => {
            let token_value = token.resolve()?;
            *rpc_url = rpc_url.replace(&placeholder, &token_value);
            Ok(RpcAuthentication::KeyInUrl)
        }
        AuthConfig::Query { name, token } => {
            let token_value = token.resolve()?;
            let mut parsed_rpc_url = url::Url::parse(rpc_url)
                .with_context(|| format!("invalid RPC URL: `{rpc_url}`"))?;
            parsed_rpc_url
                .query_pairs_mut()
                .append_pair(&name, &token_value);
            *rpc_url = parsed_rpc_url.as_str().to_string();
            Ok(RpcAuthentication::KeyInUrl)
        }
    }
}

/// The URL to dial and the header to install for a provider, with `Path` and `Query` auth
/// already spliced into the URL.
fn authenticated_endpoint(
    provider: &ForeignChainProviderConfig,
) -> anyhow::Result<(String, Option<(HeaderName, HeaderValue)>)> {
    let mut url = provider.rpc_url.clone();
    let header = match auth_config_to_rpc_auth(provider.auth.clone(), &mut url)? {
        RpcAuthentication::KeyInUrl => None,
        RpcAuthentication::CustomHeader {
            header_name,
            header_value,
        } => Some((header_name, header_value)),
    };
    Ok((url, header))
}

/// The authenticated JSON-RPC client for a provider, used by every chain the node reaches over
/// jsonrpsee. Carries no timeout: those chains are bounded by their caller's deadline.
pub fn http_client(provider: &ForeignChainProviderConfig) -> anyhow::Result<HttpClient> {
    let mut url = provider.rpc_url.clone();
    let auth = auth_config_to_rpc_auth(provider.auth.clone(), &mut url)?;
    build_http_client(url, auth).map_err(|e| anyhow::anyhow!("failed to build HTTP client: {e}"))
}

/// The authenticated Aptos REST client for a provider.
pub fn aptos_client(
    provider: &ForeignChainProviderConfig,
    timeout: Duration,
) -> anyhow::Result<ReqwestAptosClient> {
    let (url, header) = authenticated_endpoint(provider)?;
    Ok(ReqwestAptosClient::new(url, header, timeout))
}

/// The authenticated Sui gRPC client for a provider.
pub fn sui_client(
    provider: &ForeignChainProviderConfig,
    timeout: Duration,
) -> anyhow::Result<GrpcSuiClient> {
    let (url, header) = authenticated_endpoint(provider)?;
    GrpcSuiClient::new(url, header, timeout)
        .map_err(|e| anyhow::anyhow!("failed to build the Sui gRPC client: {e}"))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use mpc_node_config::TokenConfig;

    #[test]
    fn auth_config_to_rpc_auth__path_auth_substitutes_token_into_url() {
        // Given
        let auth = AuthConfig::Path {
            placeholder: "{api_key}".to_string(),
            token: TokenConfig::Val {
                val: "my-secret-key".to_string(),
            },
        };
        let mut url = "https://rpc.ankr.com/near/{api_key}".to_string();

        // When
        let result = auth_config_to_rpc_auth(auth, &mut url).unwrap();

        // Then
        assert_matches!(result, RpcAuthentication::KeyInUrl);
        assert_eq!(url, "https://rpc.ankr.com/near/my-secret-key");
    }

    #[test]
    fn auth_config_to_rpc_auth__none_auth_leaves_url_unchanged() {
        // Given
        let auth = AuthConfig::None;
        let mut url = "https://rpc.example.com".to_string();

        // When
        let result = auth_config_to_rpc_auth(auth, &mut url).unwrap();

        // Then
        assert_matches!(result, RpcAuthentication::KeyInUrl);
        assert_eq!(url, "https://rpc.example.com");
    }

    #[test]
    fn auth_config_to_rpc_auth__header_auth_leaves_url_unchanged() {
        // Given
        let auth = AuthConfig::Header {
            name: http::HeaderName::from_static("authorization"),
            scheme: Some("Bearer".to_string()),
            token: TokenConfig::Val {
                val: "secret".to_string(),
            },
        };
        let mut url = "https://rpc.example.com/v2/".to_string();

        // When
        let result = auth_config_to_rpc_auth(auth, &mut url).unwrap();

        // Then
        assert_matches!(result, RpcAuthentication::CustomHeader { .. });
        assert_eq!(url, "https://rpc.example.com/v2/");
    }

    #[test]
    fn auth_config_to_rpc_auth__header_auth_with_scheme_prepends_scheme() {
        // Given
        let auth = AuthConfig::Header {
            name: http::HeaderName::from_static("authorization"),
            scheme: Some("Bearer".to_string()),
            token: TokenConfig::Val {
                val: "secret".to_string(),
            },
        };
        let mut url = "https://rpc.example.com".to_string();

        // When
        let result = auth_config_to_rpc_auth(auth, &mut url).unwrap();

        // Then
        let RpcAuthentication::CustomHeader { header_value, .. } = result else {
            panic!("expected CustomHeader, got {result:?}");
        };
        assert_eq!(header_value.to_str().unwrap(), "Bearer secret");
    }

    #[test]
    fn auth_config_to_rpc_auth__header_auth_without_scheme_uses_raw_token() {
        // Given: providers like Tatum (`x-api-key`) and NowNodes (`api-key`) use
        // the raw token as the header value, with no scheme prefix.
        let auth = AuthConfig::Header {
            name: http::HeaderName::from_static("x-api-key"),
            scheme: None,
            token: TokenConfig::Val {
                val: "raw-token-value".to_string(),
            },
        };
        let mut url = "https://gateway.example.com".to_string();

        // When
        let result = auth_config_to_rpc_auth(auth, &mut url).unwrap();

        // Then
        let RpcAuthentication::CustomHeader { header_value, .. } = result else {
            panic!("expected CustomHeader, got {result:?}");
        };
        assert_eq!(header_value.to_str().unwrap(), "raw-token-value");
    }

    #[test]
    fn auth_config_to_rpc_auth__should_mark_header_value_sensitive() {
        // Given
        let auth = AuthConfig::Header {
            name: http::HeaderName::from_static("authorization"),
            scheme: Some("Bearer".to_string()),
            token: TokenConfig::Val {
                val: "secret".to_string(),
            },
        };
        let mut url = "https://rpc.example.com".to_string();

        // When
        let result = auth_config_to_rpc_auth(auth, &mut url).unwrap();

        // Then
        let RpcAuthentication::CustomHeader { header_value, .. } = result else {
            panic!("expected CustomHeader, got {result:?}");
        };
        assert!(header_value.is_sensitive());
        assert_eq!(format!("{header_value:?}"), "Sensitive");
    }

    #[test]
    fn auth_config_to_rpc_auth__query_auth_appends_param_to_url_without_query() {
        // Given: providers like Helius use `?api-key=<KEY>` on a URL with no query.
        let auth = AuthConfig::Query {
            name: "api-key".to_string(),
            token: TokenConfig::Val {
                val: "my-secret-key".to_string(),
            },
        };
        let mut url = "https://mainnet.helius-rpc.com/".to_string();

        // When
        let result = auth_config_to_rpc_auth(auth, &mut url).unwrap();

        // Then
        assert_matches!(result, RpcAuthentication::KeyInUrl);
        assert_eq!(url, "https://mainnet.helius-rpc.com/?api-key=my-secret-key");
    }

    #[test]
    fn auth_config_to_rpc_auth__query_auth_appends_param_to_url_with_existing_query() {
        // Given: dRPC's `?network=ethereum&dkey=<KEY>` form — the URL already has
        // query parameters and the auth key must be appended with `&`.
        let auth = AuthConfig::Query {
            name: "dkey".to_string(),
            token: TokenConfig::Val {
                val: "my-drpc-key".to_string(),
            },
        };
        let mut url = "https://lb.drpc.org/ogrpc?network=ethereum".to_string();

        // When
        let result = auth_config_to_rpc_auth(auth, &mut url).unwrap();

        // Then
        assert_matches!(result, RpcAuthentication::KeyInUrl);
        assert_eq!(
            url,
            "https://lb.drpc.org/ogrpc?network=ethereum&dkey=my-drpc-key"
        );
    }

    #[test]
    fn auth_config_to_rpc_auth__query_auth_url_encodes_special_characters() {
        // Given: tokens may contain characters that must be URL-encoded.
        let auth = AuthConfig::Query {
            name: "api-key".to_string(),
            token: TokenConfig::Val {
                val: "a b+c".to_string(),
            },
        };
        let mut url = "https://rpc.example.com/".to_string();

        // When
        let result = auth_config_to_rpc_auth(auth, &mut url).unwrap();

        // Then
        assert_matches!(result, RpcAuthentication::KeyInUrl);
        assert_eq!(url, "https://rpc.example.com/?api-key=a+b%2Bc");
    }

    #[test]
    fn auth_config_to_rpc_auth__query_auth_returns_error_for_invalid_url() {
        // Given
        let auth = AuthConfig::Query {
            name: "api-key".to_string(),
            token: TokenConfig::Val {
                val: "secret".to_string(),
            },
        };
        let mut url = "not a valid url".to_string();

        // When
        let result = auth_config_to_rpc_auth(auth, &mut url);

        // Then
        result.unwrap_err();
    }
}
