use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use url::Url;

use super::provider_identity::{ConfiguredAuth, encode_path_segment};

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

impl<'a> From<&'a AuthConfig> for ConfiguredAuth<'a> {
    fn from(auth: &'a AuthConfig) -> Self {
        match auth {
            AuthConfig::None => Self::None,
            AuthConfig::Header { name, scheme, .. } => Self::Header {
                name: name.as_str(),
                scheme: scheme.as_deref(),
            },
            AuthConfig::Path { placeholder, .. } => Self::Path { placeholder },
            AuthConfig::Query { name, .. } => Self::Query { name },
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
            let url = Url::parse(rpc_url)
                .with_context(|| format!("provided RPC URL is invalid: `{rpc_url}`"))?;
            placeholder_segment_index(&url, placeholder)?;
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

/// Replaces only the path segment that is `placeholder`, so the token cannot change the host,
/// port or any other part of the URL that the whitelist checks.
pub fn substitute_path_token(
    rpc_url: &str,
    placeholder: &str,
    token: &str,
) -> anyhow::Result<String> {
    let mut url =
        Url::parse(rpc_url).with_context(|| format!("provided RPC URL is invalid: `{rpc_url}`"))?;
    let index = placeholder_segment_index(&url, placeholder)?;
    let encoded_token = encode_path_segment(&url, token)
        .context("the token for path authentication is not a valid path segment")?;
    let mut segments: Vec<&str> = url.path_segments().into_iter().flatten().collect();
    if let Some(segment) = segments.get_mut(index) {
        *segment = &encoded_token;
    }
    let path = segments.join("/");
    url.set_path(&format!("/{path}"));
    Ok(url.into())
}

fn placeholder_segment_index(url: &Url, placeholder: &str) -> anyhow::Result<usize> {
    let encoded_placeholder = encode_path_segment(url, placeholder).with_context(|| {
        format!(
            "the placeholder, `{placeholder}`, for path authentication is not a valid path segment"
        )
    })?;
    let mut indices = url
        .path_segments()
        .into_iter()
        .flatten()
        .enumerate()
        .filter(|(_, segment)| *segment == encoded_placeholder)
        .map(|(index, _)| index);
    match (indices.next(), indices.next()) {
        (Some(index), None) => Ok(index),
        _ => anyhow::bail!(
            "the placeholder, `{placeholder}`, for path authentication must be exactly one full path segment of the rpc url {url}"
        ),
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::last_segment(
        "https://rpc.ankr.com/eth/{api_key}",
        "{api_key}",
        "key",
        "https://rpc.ankr.com/eth/key"
    )]
    #[case::followed_by_a_segment(
        "https://slug.quiknode.pro/{api_key}/v1",
        "{api_key}",
        "key",
        "https://slug.quiknode.pro/key/v1"
    )]
    #[case::trailing_slash(
        "https://rpc.ankr.com/eth/{api_key}/",
        "{api_key}",
        "key",
        "https://rpc.ankr.com/eth/key/"
    )]
    #[case::placeholder_text_in_the_host(
        "https://base-mainnet.g.alchemy.com/v2/com",
        "com",
        "example.org",
        "https://base-mainnet.g.alchemy.com/v2/example.org"
    )]
    #[case::followed_by_a_query(
        "https://rpc.ankr.com/eth/{api_key}?network=main",
        "{api_key}",
        "key",
        "https://rpc.ankr.com/eth/key?network=main"
    )]
    #[case::braced_placeholder_in_the_host(
        "https://{api_key}.quiknode.pro/{api_key}",
        "{api_key}",
        "evil.example.org",
        "https://{api_key}.quiknode.pro/evil.example.org"
    )]
    #[case::percent_in_the_token(
        "https://rpc.ankr.com/eth/{api_key}",
        "{api_key}",
        "a%2Fb",
        "https://rpc.ankr.com/eth/a%252Fb"
    )]
    #[case::url_delimiters_in_the_token(
        "https://rpc.ankr.com/eth/{api_key}",
        "{api_key}",
        "a/b?c#d",
        "https://rpc.ankr.com/eth/a%2Fb%3Fc%23d"
    )]
    fn substitute_path_token__should_replace_only_the_placeholder_segment(
        #[case] rpc_url: &str,
        #[case] placeholder: &str,
        #[case] token: &str,
        #[case] expected: &str,
    ) {
        // When
        let substituted = substitute_path_token(rpc_url, placeholder, token).unwrap();

        // Then
        assert_eq!(substituted, expected);
    }

    #[rstest]
    #[case::absent("https://rpc.ankr.com/eth/key", "{api_key}", "key")]
    #[case::two_segments("https://rpc.ankr.com/{api_key}/{api_key}", "{api_key}", "key")]
    #[case::part_of_a_segment("https://rpc.ankr.com/eth/key{api_key}", "{api_key}", "key")]
    #[case::in_the_query("https://rpc.ankr.com/eth?key={api_key}", "{api_key}", "key")]
    #[case::only_in_the_host("https://{api_key}.quiknode.pro/", "{api_key}", "key")]
    #[case::percent_encoded_placeholder(
        "https://rpc.ankr.com/eth/%7Bapi_key%7D",
        "%7Bapi_key%7D",
        "key"
    )]
    #[case::dot_placeholder("https://rpc.ankr.com/eth/", ".", "key")]
    #[case::empty_placeholder("https://rpc.ankr.com/eth/", "", "key")]
    #[case::dot_dot_token("https://rpc.ankr.com/eth/{api_key}", "{api_key}", "..")]
    fn substitute_path_token__should_fail_unless_placeholder_and_token_are_full_path_segments(
        #[case] rpc_url: &str,
        #[case] placeholder: &str,
        #[case] token: &str,
    ) {
        // When
        let substituted = substitute_path_token(rpc_url, placeholder, token);

        // Then
        assert!(substituted.is_err(), "got {substituted:?}");
    }

    #[test]
    fn validate_auth_config__should_reject_a_path_placeholder_that_is_not_a_full_path_segment() {
        // Given
        let auth = AuthConfig::Path {
            placeholder: "{api_key}".to_string(),
            token: TokenConfig::Val {
                val: "key".to_string(),
            },
        };

        // When
        let validated = validate_auth_config(&auth, "https://rpc.ankr.com/eth?key={api_key}");

        // Then
        assert!(validated.is_err());
    }
}
