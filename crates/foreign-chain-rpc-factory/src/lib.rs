use anyhow::Context;
use http::{HeaderMap, HeaderName, HeaderValue};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use mpc_node_config::foreign_chains;
use mpc_node_config::{AuthConfig, ForeignChainProviderConfig};

pub mod inspectors;

#[derive(Debug, Clone)]
pub(crate) enum RpcAuthentication {
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

/// Convert an [`AuthConfig`] into a [`RpcAuthentication`], substituting `Path`/`Query` tokens
/// into `rpc_url` as it goes.
fn auth_config_to_rpc_auth(
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
            let mut header_value = HeaderValue::from_str(&header_value_str)
                .map_err(|e| anyhow::anyhow!("invalid header value: {e}"))?;
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
            *rpc_url = foreign_chains::substitute_path_token(rpc_url, &placeholder, &token_value)?;
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

pub fn resolve_provider_auth(
    provider: &ForeignChainProviderConfig,
) -> anyhow::Result<(String, Option<(HeaderName, HeaderValue)>)> {
    let mut url = provider.rpc_url.clone();
    let auth = auth_config_to_rpc_auth(provider.auth.clone(), &mut url)?;
    Ok((
        url,
        match auth {
            RpcAuthentication::KeyInUrl => None,
            RpcAuthentication::CustomHeader {
                header_name,
                header_value,
            } => Some((header_name, header_value)),
        },
    ))
}

/// Builds an HTTP client for a configured provider, resolving its URL and authentication.
/// This client can be used to construct a [`foreign_chain_inspector::ForeignChainInspector`].
pub fn build_http_client(provider: &ForeignChainProviderConfig) -> anyhow::Result<HttpClient> {
    let (url, auth) = resolve_provider_auth(provider)?;
    let mut headers = HeaderMap::new();

    if let Some((header_name, header_value)) = auth {
        headers.insert(header_name, header_value);
    }

    let client = HttpClientBuilder::default()
        .set_headers(headers)
        .build(&url)?;

    Ok(client)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use mpc_node_config::foreign_chains::RpcProviderName;
    use mpc_node_config::foreign_chains::provider_identity::ProviderWhitelistMatches;
    use mpc_node_config::{ForeignChainConfig, TokenConfig};
    use near_mpc_contract_interface::types::{
        AuthScheme, ChainEntry, ChainRouting, ProviderConfig, ProviderId,
    };
    use rstest::rstest;
    use std::assert_matches;
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    fn val_token(val: &str) -> TokenConfig {
        TokenConfig::Val {
            val: val.to_string(),
        }
    }

    #[rstest]
    #[case::none_auth_leaves_url_unchanged(
        AuthConfig::None,
        "https://rpc.example.com",
        "https://rpc.example.com"
    )]
    #[case::path_auth_substitutes_token_into_url(
        AuthConfig::Path {
            placeholder: "{api_key}".to_string(),
            token: val_token("my-secret-key")
        },
        "https://rpc.ankr.com/near/{api_key}",
        "https://rpc.ankr.com/near/my-secret-key"
    )]
    #[case::query_auth_appends_param_to_url_without_query(
        AuthConfig::Query { name: "api-key".to_string(), token: val_token("my-secret-key") },
        "https://mainnet.helius-rpc.com/",
        "https://mainnet.helius-rpc.com/?api-key=my-secret-key"
    )]
    #[case::query_auth_appends_param_to_url_with_existing_query(
        AuthConfig::Query { name: "dkey".to_string(), token: val_token("my-drpc-key") },
        "https://lb.drpc.org/ogrpc?network=ethereum",
        "https://lb.drpc.org/ogrpc?network=ethereum&dkey=my-drpc-key"
    )]
    #[case::query_auth_url_encodes_special_characters(
        AuthConfig::Query { name: "api-key".to_string(), token: val_token("a b+c") },
        "https://rpc.example.com/",
        "https://rpc.example.com/?api-key=a+b%2Bc"
    )]
    fn auth_config_to_rpc_auth__should_return_key_in_url_and_produce_expected_url(
        #[case] auth: AuthConfig,
        #[case] original_url: &str,
        #[case] expected_url: &str,
    ) {
        // Given
        let mut url = original_url.to_string();

        // When
        let result = auth_config_to_rpc_auth(auth, &mut url).unwrap();

        // Then
        assert_matches!(result, RpcAuthentication::KeyInUrl);
        assert_eq!(url, expected_url);
    }

    #[rstest]
    #[case::with_scheme_prepends_scheme(
        AuthConfig::Header {
            name: HeaderName::from_static("authorization"),
            scheme: Some("Bearer".to_string()),
            token: val_token("secret")
        },
        "Bearer secret"
    )]
    #[case::without_scheme_uses_raw_token(
        AuthConfig::Header {
            name: HeaderName::from_static("x-api-key"),
            scheme: None,
            token: val_token("raw-token-value")
        },
        "raw-token-value"
    )]
    fn auth_config_to_rpc_auth__should_build_sensitive_header_and_leave_url_unchanged(
        #[case] auth: AuthConfig,
        #[case] expected_header_value: &str,
    ) {
        // Given
        let original_url = "https://rpc.example.com/v2/";
        let mut url = original_url.to_string();

        // When
        let result = auth_config_to_rpc_auth(auth, &mut url).unwrap();

        // Then
        let RpcAuthentication::CustomHeader { header_value, .. } = result else {
            panic!("expected CustomHeader, got {result:?}");
        };
        assert_eq!(header_value.to_str().unwrap(), expected_header_value);
        assert!(header_value.is_sensitive());
        assert_eq!(format!("{header_value:?}"), "Sensitive");
        assert_eq!(url, original_url);
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

    #[rstest]
    #[case::alchemy_placeholder_in_the_host(
        "https://base-mainnet.g.alchemy.com/v2",
        "https://base-mainnet.g.alchemy.com/v2/com",
        "com",
        "example.org",
        "base-mainnet.g.alchemy.com"
    )]
    #[case::quicknode_placeholder_in_the_slug(
        "https://{}.base-mainnet.quiknode.pro",
        "https://base.base-mainnet.quiknode.pro/base",
        "base",
        "evil.example.org/x",
        "base.base-mainnet.quiknode.pro"
    )]
    // The host is never substituted, even when it contains the placeholder literally.
    #[case::placeholder_in_the_host_is_left_untouched(
        "https://{}.base-mainnet.quiknode.pro",
        "https://{api_key}.base-mainnet.quiknode.pro/{api_key}",
        "{api_key}",
        "evil.example.org/x",
        "{api_key}.base-mainnet.quiknode.pro"
    )]
    fn resolve_provider_auth__should_keep_the_host_of_a_whitelist_conforming_provider(
        #[case] whitelisted_base_url: &str,
        #[case] rpc_url: &str,
        #[case] placeholder: &str,
        #[case] token: &str,
        #[case] checked_host: &str,
    ) {
        // Given
        let local_name = RpcProviderName::from("local".to_string());
        let provider = ForeignChainProviderConfig {
            rpc_url: rpc_url.to_string(),
            auth: AuthConfig::Path {
                placeholder: placeholder.to_string(),
                token: TokenConfig::Val {
                    val: token.to_string(),
                },
            },
        };
        let local = ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: BTreeMap::from([(local_name.clone(), provider.clone())])
                .try_into()
                .unwrap(),
            expected_network_fingerprint: None,
        };
        let whitelisted_id = ProviderId("whitelisted".to_string());
        let entry = ChainEntry {
            providers: BTreeMap::from([(
                whitelisted_id.clone(),
                ProviderConfig {
                    base_url: whitelisted_base_url.to_string(),
                    auth_scheme: AuthScheme::Path {
                        placeholder: "{API_KEY}".to_string(),
                    },
                    chain_routing: ChainRouting::Embedded,
                },
            )])
            .try_into()
            .unwrap(),
            quorum: 1,
        };
        assert_eq!(
            ProviderWhitelistMatches::for_chain(&local, &entry)
                .whitelist_conforming_providers()
                .whitelist_provider_id(&local_name),
            Some(&whitelisted_id),
            "the provider must conform to the whitelist for this test to be meaningful"
        );

        // When
        let (resolved_url, _) = resolve_provider_auth(&provider).unwrap();

        // Then
        let resolved_host = url::Url::parse(&resolved_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned));
        assert_eq!(
            resolved_host.as_deref(),
            Some(checked_host),
            "resolved URL: {resolved_url}"
        );
    }
}
