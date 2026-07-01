use anyhow::Context;
use foreign_chain_inspector::RpcAuthentication;
use http::HeaderValue;
use mpc_node_config::AuthConfig;

/// Convert an [`AuthConfig`] into a [`foreign_chain_inspector::RpcAuthentication`].
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
            let header_value = HeaderValue::from_str(&header_value_str)?;
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
