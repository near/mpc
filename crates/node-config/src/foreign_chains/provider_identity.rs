//! Matches local RPC providers of a chain against the chain's whitelist entry, see
//! [`ProviderWhitelistMatches`]. Only conforming providers count toward the
//! voted quorum, see [`WhitelistConformingProviders`].
//!
//! The URL host identifies a provider. The local config name has no effect.
//!
//! The host of a whitelisted [`ProviderConfig::base_url`] can have one `{}` label, in any position.
//! It matches exactly one label of the local host, for example a QuickNode slug. Any other `{` or
//! `}` in the host makes the `base_url` invalid, see [`InvalidBaseUrl`].
//!
//! When more than one whitelist provider matches the host, [`ProviderWhitelistMatches`] selects
//! the most specific one, so a local provider that conforms to one entry never gets mismatches
//! from a broader entry. The rules apply in this order:
//! 1. An exact host comes before a `{}` host: `api.quiknode.pro` before `{}.quiknode.pro`.
//! 2. A longer base path prefix comes before a shorter one: for
//!    `https://api.example.com/v1/beta/x`, `api.example.com/v1/beta` before `api.example.com/v1`.
//! 3. A lower [`ProviderId`] comes before a higher one.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;

use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types::{
    AuthScheme, ChainEntry, ChainRouting, ProviderConfig, ProviderId,
};
use url::Url;

use super::{ForeignChainConfig, RpcProviderName};

/// The auth of a local provider, without its token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfiguredAuth<'a> {
    None,
    Header {
        name: &'a str,
        scheme: Option<&'a str>,
    },
    Path {
        placeholder: &'a str,
    },
    Query {
        name: &'a str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderWhitelistMatches<'w> {
    match_by_local_name: BTreeMap<RpcProviderName, ProviderWhitelistMatch<'w>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderWhitelistMatch<'w> {
    Unlisted,
    Conforming {
        id: &'w ProviderId,
    },
    Misconfigured {
        id: &'w ProviderId,
        whitelisted: &'w ProviderConfig,
        mismatches: NonEmptyVec<Mismatch>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhitelistConformingProviders {
    whitelist_id_by_local_name: BTreeMap<RpcProviderName, ProviderId>,
}

impl<'w> ProviderWhitelistMatches<'w> {
    pub fn for_chain(local_chain: &ForeignChainConfig, whitelist_entry: &'w ChainEntry) -> Self {
        Self {
            match_by_local_name: local_chain
                .providers
                .iter()
                .map(|(local_name, local_provider)| {
                    let provider_match = match Url::parse(&local_provider.rpc_url) {
                        Ok(local_url) => match_provider(
                            whitelist_entry,
                            &local_url,
                            (&local_provider.auth).into(),
                        ),
                        Err(_) => ProviderWhitelistMatch::Unlisted,
                    };
                    (local_name.clone(), provider_match)
                })
                .collect(),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&RpcProviderName, &ProviderWhitelistMatch<'w>)> {
        self.match_by_local_name.iter()
    }

    pub fn whitelist_conforming_providers(&self) -> WhitelistConformingProviders {
        WhitelistConformingProviders {
            whitelist_id_by_local_name: self
                .match_by_local_name
                .iter()
                .filter_map(|(local_name, provider_match)| match provider_match {
                    ProviderWhitelistMatch::Conforming { id } => {
                        Some((local_name.clone(), (*id).clone()))
                    }
                    ProviderWhitelistMatch::Unlisted
                    | ProviderWhitelistMatch::Misconfigured { .. } => None,
                })
                .collect(),
        }
    }
}

impl WhitelistConformingProviders {
    pub fn iter(&self) -> impl Iterator<Item = (&RpcProviderName, &ProviderId)> {
        self.whitelist_id_by_local_name.iter()
    }

    pub fn whitelist_provider_id(&self, local_name: &RpcProviderName) -> Option<&ProviderId> {
        self.whitelist_id_by_local_name.get(local_name)
    }

    pub fn whitelist_provider_count(&self) -> usize {
        self.whitelist_id_by_local_name
            .values()
            .collect::<BTreeSet<_>>()
            .len()
    }

    pub fn meets_quorum(&self, quorum: NonZeroUsize) -> bool {
        self.whitelist_provider_count() >= quorum.get()
    }
}

/// A part of a local provider config differs from the whitelist provider it matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mismatch {
    BaseUrl,
    ChainRouting,
    AuthKind {
        local: &'static str,
        whitelisted: &'static str,
    },
    HeaderName {
        local: String,
        whitelisted: String,
    },
    HeaderScheme {
        local: Option<String>,
        whitelisted: Option<String>,
    },
    QueryName {
        local: String,
        whitelisted: String,
    },
    /// The path auth placeholder is not the full path segment after the base path and the routing
    /// segment.
    PlaceholderPosition,
    /// The whitelist uses a chain routing or auth variant that this node version does not know.
    UnknownContractVariant,
}

fn match_provider<'w>(
    entry: &'w ChainEntry,
    rpc_url: &Url,
    auth: ConfiguredAuth<'_>,
) -> ProviderWhitelistMatch<'w> {
    let path = path_segments(rpc_url);
    let Some(best) = entry
        .providers
        .iter()
        .filter_map(|(id, whitelisted)| Candidate::if_host_matches(id, whitelisted, rpc_url, &path))
        .max_by_key(|candidate| {
            (
                candidate.exact_host,
                candidate.base_path_prefix_len,
                Reverse(candidate.id),
            )
        })
    else {
        return ProviderWhitelistMatch::Unlisted;
    };
    let path_mismatch = first_path_mismatch(best.whitelisted, &best.base, &path, auth);
    let path_mismatch = path_mismatch.as_ref();
    let mismatches = compare_base_url(&best.base, rpc_url, path_mismatch)
        .into_iter()
        .chain(compare_chain_routing(
            &best.whitelisted.chain_routing,
            rpc_url,
            path_mismatch,
        ))
        .chain(compare_auth(
            auth,
            &best.whitelisted.auth_scheme,
            path_mismatch,
        ))
        .collect::<Vec<_>>();
    match NonEmptyVec::try_from(mismatches) {
        Ok(mismatches) => ProviderWhitelistMatch::Misconfigured {
            id: best.id,
            whitelisted: best.whitelisted,
            mismatches,
        },
        Err(_) => ProviderWhitelistMatch::Conforming { id: best.id },
    }
}

struct Candidate<'w> {
    id: &'w ProviderId,
    whitelisted: &'w ProviderConfig,
    base: Url,
    exact_host: bool,
    base_path_prefix_len: Option<usize>,
}

impl<'w> Candidate<'w> {
    fn if_host_matches(
        id: &'w ProviderId,
        whitelisted: &'w ProviderConfig,
        rpc_url: &Url,
        path: &[&str],
    ) -> Option<Self> {
        let base = parse_base_url(&whitelisted.base_url).ok()?;
        if !host_matches(&base, rpc_url) {
            return None;
        }
        let base_path = path_segments(&base);
        Some(Self {
            id,
            whitelisted,
            exact_host: !base.host_str().is_some_and(|host| host.contains(WILDCARD)),
            base_path_prefix_len: path.starts_with(&base_path).then_some(base_path.len()),
            base,
        })
    }
}

const WILDCARD: &str = "{}";

/// A whitelist provider whose `base_url` fails here can never match.
pub fn parse_base_url(base_url: &str) -> Result<Url, InvalidBaseUrl> {
    let url = Url::parse(base_url).map_err(InvalidBaseUrl::Parse)?;
    let braced_labels: Vec<&str> = url
        .host_str()
        .ok_or(InvalidBaseUrl::NoHost)?
        .split('.')
        .filter(|label| label.contains(['{', '}']))
        .collect();
    if braced_labels.is_empty() || braced_labels == [WILDCARD] {
        Ok(url)
    } else {
        Err(InvalidBaseUrl::Wildcard)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidBaseUrl {
    #[error("Failed to parse the base URL: {0}")]
    Parse(url::ParseError),
    #[error("The base URL has no host")]
    NoHost,
    #[error("The base URL host has a brace outside a whole `{{}}` label")]
    Wildcard,
}

/// Expects a `base` that [`parse_base_url`] accepted.
fn host_matches(base: &Url, url: &Url) -> bool {
    let (Some(pattern), Some(domain)) = (base.host_str(), url.domain()) else {
        return base.host() == url.host();
    };
    if !pattern.contains(WILDCARD) {
        return pattern == domain;
    }
    pattern.split('.').count() == domain.split('.').count()
        && pattern
            .split('.')
            .zip(domain.split('.'))
            .all(|(expected, label)| match expected {
                WILDCARD => !label.is_empty(),
                _ => expected == label,
            })
}

fn compare_base_url(base: &Url, url: &Url, path_mismatch: Option<&Mismatch>) -> Option<Mismatch> {
    let matches = url.scheme() == base.scheme()
        && url.port_or_known_default() == base.port_or_known_default()
        && path_mismatch != Some(&Mismatch::BaseUrl);
    (!matches).then_some(Mismatch::BaseUrl)
}

fn compare_chain_routing(
    routing: &ChainRouting,
    url: &Url,
    path_mismatch: Option<&Mismatch>,
) -> Option<Mismatch> {
    match routing {
        ChainRouting::Embedded => None,
        ChainRouting::PathSegment { .. } => {
            (path_mismatch == Some(&Mismatch::ChainRouting)).then_some(Mismatch::ChainRouting)
        }
        ChainRouting::QueryParam { name, value } => {
            let values: Vec<_> = url
                .query_pairs()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| value)
                .collect();
            (values != [value.as_str()]).then_some(Mismatch::ChainRouting)
        }
        _ => Some(Mismatch::UnknownContractVariant),
    }
}

fn compare_auth(
    auth: ConfiguredAuth<'_>,
    whitelisted: &AuthScheme,
    path_mismatch: Option<&Mismatch>,
) -> Vec<Mismatch> {
    match (auth, whitelisted) {
        (ConfiguredAuth::None, AuthScheme::None) => vec![],
        (
            ConfiguredAuth::Header { name, scheme },
            AuthScheme::Header {
                name: whitelisted_name,
                scheme: whitelisted_scheme,
            },
        ) => {
            let name_mismatch =
                (!name.eq_ignore_ascii_case(whitelisted_name)).then(|| Mismatch::HeaderName {
                    local: name.to_owned(),
                    whitelisted: whitelisted_name.clone(),
                });
            let schemes_match = match (scheme, whitelisted_scheme.as_deref()) {
                (Some(scheme), Some(whitelisted_scheme)) => {
                    scheme.eq_ignore_ascii_case(whitelisted_scheme)
                }
                (None, None) => true,
                _ => false,
            };
            let scheme_mismatch = (!schemes_match).then(|| Mismatch::HeaderScheme {
                local: scheme.map(str::to_owned),
                whitelisted: whitelisted_scheme.clone(),
            });
            name_mismatch.into_iter().chain(scheme_mismatch).collect()
        }
        (ConfiguredAuth::Path { .. }, AuthScheme::Path { .. }) => (path_mismatch
            == Some(&Mismatch::PlaceholderPosition))
        .then_some(Mismatch::PlaceholderPosition)
        .into_iter()
        .collect(),
        (
            ConfiguredAuth::Query { name },
            AuthScheme::Query {
                name: whitelisted_name,
            },
        ) => (name != whitelisted_name)
            .then(|| Mismatch::QueryName {
                local: name.to_owned(),
                whitelisted: whitelisted_name.clone(),
            })
            .into_iter()
            .collect(),
        _ => match whitelisted_auth_kind(whitelisted) {
            Some(whitelisted) => vec![Mismatch::AuthKind {
                local: local_auth_kind(auth),
                whitelisted,
            }],
            None => vec![Mismatch::UnknownContractVariant],
        },
    }
}

fn local_auth_kind(auth: ConfiguredAuth<'_>) -> &'static str {
    match auth {
        ConfiguredAuth::None => "None",
        ConfiguredAuth::Header { .. } => "Header",
        ConfiguredAuth::Path { .. } => "Path",
        ConfiguredAuth::Query { .. } => "Query",
    }
}

/// [`None`] for a variant that this node version does not know.
fn whitelisted_auth_kind(auth: &AuthScheme) -> Option<&'static str> {
    match auth {
        AuthScheme::None => Some("None"),
        AuthScheme::Header { .. } => Some("Header"),
        AuthScheme::Path { .. } => Some("Path"),
        AuthScheme::Query { .. } => Some("Query"),
        _ => None,
    }
}

/// Stops at the first wrong part, so one wrong path segment gives one mismatch only.
fn first_path_mismatch(
    whitelisted: &ProviderConfig,
    base: &Url,
    path: &[&str],
    auth: ConfiguredAuth<'_>,
) -> Option<Mismatch> {
    let mut expected: Vec<String> = path_segments(base).into_iter().map(str::to_owned).collect();
    if !has_prefix(path, &expected) {
        return Some(Mismatch::BaseUrl);
    }
    if let ChainRouting::PathSegment { segment } = &whitelisted.chain_routing
        && !extend_prefix(&mut expected, base, segment, path)
    {
        return Some(Mismatch::ChainRouting);
    }
    if let (ConfiguredAuth::Path { placeholder }, AuthScheme::Path { .. }) =
        (auth, &whitelisted.auth_scheme)
        && !extend_prefix(&mut expected, base, placeholder, path)
    {
        return Some(Mismatch::PlaceholderPosition);
    }
    None
}

/// Appends the encoded `segment` to `prefix`; `false` if `path` no longer starts with `prefix`.
fn extend_prefix(prefix: &mut Vec<String>, base: &Url, segment: &str, path: &[&str]) -> bool {
    let Some(encoded) = encode_path_segment(base, segment) else {
        return false;
    };
    prefix.push(encoded);
    has_prefix(path, prefix)
}

fn has_prefix(path: &[&str], prefix: &[String]) -> bool {
    path.get(..prefix.len()).is_some_and(|head| head == prefix)
}

/// Encodes `segment` as [`url::PathSegmentsMut::push`] does; [`None`] for an empty, `.` or `..`.
pub(super) fn encode_path_segment(url: &Url, segment: &str) -> Option<String> {
    if matches!(segment, "" | "." | "..") {
        return None;
    }
    let mut probe = url.clone();
    probe.path_segments_mut().ok()?.clear().push(segment);
    Some(probe.path().trim_start_matches('/').to_owned())
}

fn path_segments(url: &Url) -> Vec<&str> {
    let mut segments: Vec<&str> = url.path_segments().into_iter().flatten().collect();
    while segments.last().is_some_and(|segment| segment.is_empty()) {
        segments.pop();
    }
    segments
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::assert_matches;
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use rstest::rstest;

    use super::*;
    use crate::foreign_chains::{AuthConfig, ForeignChainProviderConfig, TokenConfig};

    const API_KEY: ConfiguredAuth<'static> = ConfiguredAuth::Path {
        placeholder: "{api_key}",
    };

    fn whitelisted(base_url: &str) -> ProviderConfig {
        whitelisted_with(base_url, AuthScheme::None, ChainRouting::Embedded)
    }

    fn whitelisted_with(
        base_url: &str,
        auth_scheme: AuthScheme,
        chain_routing: ChainRouting,
    ) -> ProviderConfig {
        ProviderConfig {
            base_url: base_url.to_string(),
            auth_scheme,
            chain_routing,
        }
    }

    fn path_auth(base_url: &str, chain_routing: ChainRouting) -> ProviderConfig {
        let auth_scheme = AuthScheme::Path {
            placeholder: "{API_KEY}".to_string(),
        };
        whitelisted_with(base_url, auth_scheme, chain_routing)
    }

    fn header_auth(scheme: Option<&str>) -> ProviderConfig {
        let auth_scheme = AuthScheme::Header {
            name: "Authorization".to_string(),
            scheme: scheme.map(str::to_string),
        };
        whitelisted_with(GEOMI_URL, auth_scheme, ChainRouting::Embedded)
    }

    fn chain_entry(providers: &[(&str, ProviderConfig)]) -> ChainEntry {
        let providers: BTreeMap<ProviderId, ProviderConfig> = providers
            .iter()
            .map(|(id, config)| (ProviderId(id.to_string()), config.clone()))
            .collect();
        ChainEntry {
            providers: NonEmptyBTreeMap::try_from(providers)
                .expect("a test whitelist has a provider"),
            quorum: 1,
        }
    }

    fn match_provider_with_str<'w>(
        entry: &'w ChainEntry,
        rpc_url: &str,
        auth: ConfiguredAuth<'_>,
    ) -> Option<(&'w str, Vec<Mismatch>)> {
        let url = Url::parse(rpc_url).expect("a test rpc_url parses");
        match match_provider(entry, &url, auth) {
            ProviderWhitelistMatch::Unlisted => None,
            ProviderWhitelistMatch::Conforming { id } => Some((id.0.as_str(), vec![])),
            ProviderWhitelistMatch::Misconfigured { id, mismatches, .. } => {
                Some((id.0.as_str(), mismatches.as_slice().to_vec()))
            }
        }
    }

    fn host_patterns() -> ChainEntry {
        chain_entry(&[
            ("alchemy", whitelisted("https://ETH.Alchemy.com/v2/")),
            (
                "quicknode",
                whitelisted("https://{}.base-sepolia.quiknode.pro"),
            ),
            ("middle-wildcard", whitelisted("https://api.{}.example.net")),
            ("two-wildcards", whitelisted("https://{}.{}.example.org")),
            (
                "wildcard-in-a-label",
                whitelisted("https://api-{}.example.com"),
            ),
            ("unparseable", whitelisted("eth.example.net/v2")),
        ])
    }

    #[rstest]
    #[case::exact_host("https://eth.alchemy.com/v2/", Ok(()))]
    #[case::wildcard_in_the_first_label("https://{}.base-sepolia.quiknode.pro", Ok(()))]
    #[case::wildcard_in_the_second_label("https://api.{}.example.com", Ok(()))]
    #[case::not_a_url(
        "eth.alchemy.com/v2/",
        Err(InvalidBaseUrl::Parse(url::ParseError::RelativeUrlWithoutBase))
    )]
    #[case::no_host("mailto:ops@example.com", Err(InvalidBaseUrl::NoHost))]
    #[case::wildcard_inside_a_label("https://api-{}.example.com", Err(InvalidBaseUrl::Wildcard))]
    #[case::two_wildcards("https://{}.{}.example.org", Err(InvalidBaseUrl::Wildcard))]
    #[case::stray_brace("https://api{.example.com", Err(InvalidBaseUrl::Wildcard))]
    fn parse_base_url__should_accept_at_most_one_whole_wildcard_label(
        #[case] base_url: &str,
        #[case] expected: Result<(), InvalidBaseUrl>,
    ) {
        // When
        let base = parse_base_url(base_url);

        // Then
        assert_eq!(base.map(|_| ()), expected);
    }

    #[rstest]
    #[case::host_letter_case("https://eth.alchemy.COM/v2/key", "alchemy")]
    #[case::explicit_default_port("https://eth.alchemy.com:443/v2/key", "alchemy")]
    #[case::one_label_for_the_wildcard(
        "https://Misty-Fabled-7.base-sepolia.quiknode.pro/key",
        "quicknode"
    )]
    #[case::wildcard_in_the_second_label("https://api.slug.example.net/key", "middle-wildcard")]
    fn match_provider__should_match_by_host(#[case] rpc_url: &str, #[case] expected: &str) {
        // Given
        let entry = host_patterns();

        // When
        let provider_match = match_provider_with_str(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(provider_match, Some((expected, vec![])));
    }

    #[rstest]
    #[case::other_host("https://eth.alchemy.io/v2/key")]
    #[case::whitelisted_host_as_a_subdomain("https://eth.alchemy.com.evil.io/v2/key")]
    #[case::two_labels_for_the_wildcard("https://a.b.base-sepolia.quiknode.pro/key")]
    #[case::no_label_for_the_wildcard("https://base-sepolia.quiknode.pro/key")]
    #[case::empty_label_for_the_wildcard("https://.base-sepolia.quiknode.pro/key")]
    #[case::suffix_moved_into_the_path("https://evil.io/.base-sepolia.quiknode.pro/key")]
    #[case::suffix_extended("https://slug.base-sepolia.quiknode.pro.evil.io/key")]
    #[case::suffix_as_user_info("https://slug.base-sepolia.quiknode.pro@evil.io/key")]
    #[case::two_labels_for_a_wildcard_in_the_second_label("https://api.a.b.example.net/key")]
    #[case::two_wildcards("https://a.b.example.org/key")]
    #[case::wildcard_inside_a_label("https://api-x.example.com/key")]
    #[case::unparseable_base_url("https://eth.example.net/v2/key")]
    fn match_provider__should_not_match_a_url_whose_host_matches_no_entry(#[case] rpc_url: &str) {
        // Given
        let entry = host_patterns();

        // When
        let provider_match = match_provider_with_str(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(provider_match, None);
    }

    #[rstest]
    #[case::exact_host_over_wildcard("https://api.quiknode.pro/", "exact", vec![Mismatch::BaseUrl])]
    #[case::longest_base_path_prefix("https://api.example.com/v1/beta/x", "beta", vec![])]
    #[case::lowest_id_among_equal_prefixes("https://api.example.com/v1/x", "stable", vec![])]
    #[case::lowest_id_when_no_prefix_matches("https://api.example.com/v3", "beta", vec![Mismatch::BaseUrl])]
    fn match_provider__should_prefer_exact_host_then_longest_base_path_then_lowest_id(
        #[case] rpc_url: &str,
        #[case] expected_id: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let entry = chain_entry(&[
            ("wild", whitelisted("https://{}.quiknode.pro")),
            ("exact", whitelisted("https://api.quiknode.pro/v1")),
            ("beta", whitelisted("https://api.example.com/v1/beta")),
            ("stable", whitelisted("https://api.example.com/v1")),
            ("stable-copy", whitelisted("https://api.example.com/v1")),
        ]);

        // When
        let provider_match = match_provider_with_str(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(provider_match, Some((expected_id, expected_mismatches)));
    }

    #[rstest]
    #[case::trailing_slash_on_the_rpc_url("https://eth.alchemy.com/v2/", vec![])]
    #[case::no_trailing_slash("https://eth.alchemy.com/v2", vec![])]
    #[case::other_port("https://eth.alchemy.com:8443/v2/key", vec![Mismatch::BaseUrl])]
    #[case::other_scheme("http://eth.alchemy.com/v2/key", vec![Mismatch::BaseUrl])]
    #[case::websocket_scheme("wss://eth.alchemy.com/v2/key", vec![Mismatch::BaseUrl])]
    #[case::path_with_only_a_string_prefix("https://eth.alchemy.com/v2-evil/key", vec![Mismatch::BaseUrl])]
    #[case::empty_segment_before_the_base_path("https://eth.alchemy.com//v2/key", vec![Mismatch::BaseUrl])]
    fn match_provider__should_compare_scheme_port_and_base_path_segments(
        #[case] rpc_url: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let entry = chain_entry(&[("alchemy", whitelisted("https://eth.alchemy.com/v2/"))]);

        // When
        let provider_match = match_provider_with_str(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(provider_match, Some(("alchemy", expected_mismatches)));
    }

    #[rstest]
    #[case::exact_segment("https://rpc.ankr.com/eth", vec![])]
    #[case::longer_segment("https://rpc.ankr.com/ethereum", vec![Mismatch::ChainRouting])]
    #[case::segment_further_down("https://rpc.ankr.com/x/eth", vec![Mismatch::ChainRouting])]
    #[case::missing_segment("https://rpc.ankr.com", vec![Mismatch::ChainRouting])]
    fn match_provider__should_require_the_routing_segment_right_after_the_base_path(
        #[case] rpc_url: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let routing = ChainRouting::PathSegment {
            segment: "eth".to_string(),
        };
        let entry = chain_entry(&[(
            "ankr",
            whitelisted_with("https://rpc.ankr.com", AuthScheme::None, routing),
        )]);

        // When
        let provider_match = match_provider_with_str(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(provider_match, Some(("ankr", expected_mismatches)));
    }

    #[rstest]
    #[case::exact_pair("?network=ethereum", vec![])]
    #[case::encoded_value("?network=ethere%75m&dkey=k", vec![])]
    #[case::longer_value("?network=ethereum-sepolia", vec![Mismatch::ChainRouting])]
    #[case::longer_name("?xnetwork=ethereum", vec![Mismatch::ChainRouting])]
    #[case::repeated_name("?network=ethereum&network=bsc", vec![Mismatch::ChainRouting])]
    #[case::missing_pair("", vec![Mismatch::ChainRouting])]
    fn match_provider__should_require_exactly_the_routing_query_pair(
        #[case] query: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let routing = ChainRouting::QueryParam {
            name: "network".to_string(),
            value: "ethereum".to_string(),
        };
        let entry = chain_entry(&[(
            "drpc",
            whitelisted_with("https://lb.drpc.org/ogrpc", AuthScheme::None, routing),
        )]);
        let rpc_url = format!("https://lb.drpc.org/ogrpc{query}");

        // When
        let provider_match = match_provider_with_str(&entry, &rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(provider_match, Some(("drpc", expected_mismatches)));
    }

    #[rstest]
    #[case::other_text_than_whitelisted("https://eth.alchemy.com/v2/{api_key}", "{api_key}", vec![])]
    #[case::followed_by_more_segments("https://eth.alchemy.com/v2/{api_key}/v1", "{api_key}", vec![])]
    #[case::space("https://eth.alchemy.com/v2/{api key}", "{api key}", vec![])]
    #[case::angle_brackets("https://eth.alchemy.com/v2/<KEY>", "<KEY>", vec![])]
    #[case::one_segment_late("https://eth.alchemy.com/v2/x/{api_key}", "{api_key}", vec![Mismatch::PlaceholderPosition])]
    #[case::after_an_empty_segment("https://eth.alchemy.com/v2//{api_key}", "{api_key}", vec![Mismatch::PlaceholderPosition])]
    #[case::part_of_the_segment("https://eth.alchemy.com/v2/key{api_key}", "{api_key}", vec![Mismatch::PlaceholderPosition])]
    #[case::in_the_query("https://eth.alchemy.com/v2?key={api_key}", "{api_key}", vec![Mismatch::PlaceholderPosition])]
    #[case::in_the_host("https://eth.alchemy.com/v2/key", "alchemy", vec![Mismatch::PlaceholderPosition])]
    #[case::dot("https://eth.alchemy.com/v2/", ".", vec![Mismatch::PlaceholderPosition])]
    #[case::spanning_segments("https://eth.alchemy.com/v2/a/b", "a/b", vec![Mismatch::PlaceholderPosition])]
    fn match_provider__should_check_the_placeholder_by_position_as_the_url_encodes_it(
        #[case] rpc_url: &str,
        #[case] placeholder: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let entry = chain_entry(&[(
            "alchemy",
            path_auth("https://eth.alchemy.com/v2/", ChainRouting::Embedded),
        )]);

        // When
        let provider_match =
            match_provider_with_str(&entry, rpc_url, ConfiguredAuth::Path { placeholder });

        // Then
        assert_eq!(provider_match, Some(("alchemy", expected_mismatches)));
    }

    #[rstest]
    #[case::after_the_routing_segment("https://rpc.ankr.com/eth/{api_key}", vec![])]
    #[case::before_the_routing_segment("https://rpc.ankr.com/{api_key}/eth", vec![Mismatch::ChainRouting])]
    #[case::one_segment_late("https://rpc.ankr.com/eth/x/{api_key}", vec![Mismatch::PlaceholderPosition])]
    fn match_provider__should_expect_the_placeholder_after_the_routing_segment(
        #[case] rpc_url: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let routing = ChainRouting::PathSegment {
            segment: "eth".to_string(),
        };
        let entry = chain_entry(&[("ankr", path_auth("https://rpc.ankr.com", routing))]);

        // When
        let provider_match = match_provider_with_str(&entry, rpc_url, API_KEY);

        // Then
        assert_eq!(provider_match, Some(("ankr", expected_mismatches)));
    }

    #[test]
    fn match_provider__should_report_a_wrong_base_path_once() {
        // Given
        let routing = ChainRouting::PathSegment {
            segment: "eth".to_string(),
        };
        let entry = chain_entry(&[("ankr", path_auth("https://rpc.ankr.com/v1", routing))]);

        // When
        let provider_match =
            match_provider_with_str(&entry, "https://rpc.ankr.com/v2/eth/{api_key}", API_KEY);

        // Then
        assert_eq!(provider_match, Some(("ankr", vec![Mismatch::BaseUrl])));
    }

    const GEOMI_URL: &str = "https://api.mainnet.aptoslabs.com/v1";

    const BEARER: ConfiguredAuth<'static> = ConfiguredAuth::Header {
        name: "authorization",
        scheme: Some("bearer"),
    };

    #[rstest]
    #[case::name_and_scheme_in_other_letter_case(Some("Bearer"), BEARER, vec![])]
    #[case::other_name_and_scheme(
        Some("Bearer"),
        ConfiguredAuth::Header { name: "x-api-key", scheme: Some("Basic") },
        vec![
            Mismatch::HeaderName { local: "x-api-key".to_string(), whitelisted: "Authorization".to_string() },
            Mismatch::HeaderScheme { local: Some("Basic".to_string()), whitelisted: Some("Bearer".to_string()) },
        ]
    )]
    #[case::scheme_only_whitelisted(
        Some("Bearer"),
        ConfiguredAuth::Header { name: "Authorization", scheme: None },
        vec![Mismatch::HeaderScheme { local: None, whitelisted: Some("Bearer".to_string()) }]
    )]
    #[case::scheme_only_configured(
        None,
        BEARER,
        vec![Mismatch::HeaderScheme { local: Some("bearer".to_string()), whitelisted: None }]
    )]
    #[case::other_auth_kind(
        None,
        ConfiguredAuth::None,
        vec![Mismatch::AuthKind { local: "None", whitelisted: "Header" }]
    )]
    fn match_provider__should_compare_header_auth_without_letter_case(
        #[case] whitelisted_scheme: Option<&str>,
        #[case] configured: ConfiguredAuth<'_>,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let entry = chain_entry(&[("geomi", header_auth(whitelisted_scheme))]);

        // When
        let provider_match = match_provider_with_str(&entry, GEOMI_URL, configured);

        // Then
        assert_eq!(provider_match, Some(("geomi", expected_mismatches)));
    }

    #[rstest]
    #[case::same_name("apikey", vec![])]
    #[case::other_letter_case("ApiKey", vec![Mismatch::QueryName { local: "ApiKey".to_string(), whitelisted: "apikey".to_string() }])]
    #[case::other_name("dkey", vec![Mismatch::QueryName { local: "dkey".to_string(), whitelisted: "apikey".to_string() }])]
    fn match_provider__should_compare_the_query_auth_name_exactly(
        #[case] configured: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let auth_scheme = AuthScheme::Query {
            name: "apikey".to_string(),
        };
        let entry = chain_entry(&[(
            "drpc",
            whitelisted_with(
                "https://lb.drpc.org/ogrpc",
                auth_scheme,
                ChainRouting::Embedded,
            ),
        )]);

        // When
        let provider_match = match_provider_with_str(
            &entry,
            "https://lb.drpc.org/ogrpc",
            ConfiguredAuth::Query { name: configured },
        );

        // Then
        assert_eq!(provider_match, Some(("drpc", expected_mismatches)));
    }

    fn local_name(name: &str) -> RpcProviderName {
        RpcProviderName::from(name.to_string())
    }

    fn local_chain(providers: &[(&str, &str)]) -> ForeignChainConfig {
        let providers: BTreeMap<RpcProviderName, ForeignChainProviderConfig> = providers
            .iter()
            .map(|(name, rpc_url)| {
                let provider = ForeignChainProviderConfig {
                    rpc_url: rpc_url.to_string(),
                    auth: AuthConfig::Path {
                        placeholder: "{api_key}".to_string(),
                        token: TokenConfig::Val {
                            val: "abc".to_string(),
                        },
                    },
                };
                (RpcProviderName::from(name.to_string()), provider)
            })
            .collect();
        ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            expected_network_fingerprint: None,
            providers: NonEmptyBTreeMap::try_from(providers).expect("a test chain has a provider"),
        }
    }

    fn alchemy_and_quicknode_whitelist() -> ChainEntry {
        chain_entry(&[
            (
                "alchemy",
                path_auth(
                    "https://eth-mainnet.g.alchemy.com/v2/",
                    ChainRouting::Embedded,
                ),
            ),
            (
                "quicknode",
                path_auth("https://{}.quiknode.pro", ChainRouting::Embedded),
            ),
        ])
    }

    fn one_local_provider_per_kind_of_match() -> ForeignChainConfig {
        local_chain(&[
            ("alchemy", "https://eth-mainnet.g.alchemy.com/v3/{api_key}"),
            ("own-node", "https://eth.example.com/{api_key}"),
            ("not-a-url", "not a url"),
            ("quicknode", "https://my-slug.quiknode.pro/{api_key}"),
        ])
    }

    fn quorum(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    #[test]
    fn provider_whitelist_matches__should_keep_the_match_of_every_local_provider() {
        // Given
        let local = one_local_provider_per_kind_of_match();
        let entry = alchemy_and_quicknode_whitelist();

        // When
        let matches = ProviderWhitelistMatches::for_chain(&local, &entry);

        // Then
        let match_by_local_name: BTreeMap<&str, &ProviderWhitelistMatch<'_>> = matches
            .iter()
            .map(|(local_name, provider_match)| (local_name.as_str(), provider_match))
            .collect();
        assert_matches!(
            match_by_local_name["alchemy"],
            ProviderWhitelistMatch::Misconfigured { id, mismatches, .. }
                if id.0 == "alchemy" && mismatches.as_slice() == [Mismatch::BaseUrl]
        );
        assert_matches!(
            match_by_local_name["own-node"],
            ProviderWhitelistMatch::Unlisted
        );
        assert_matches!(
            match_by_local_name["not-a-url"],
            ProviderWhitelistMatch::Unlisted
        );
        assert_matches!(
            match_by_local_name["quicknode"],
            ProviderWhitelistMatch::Conforming { id } if id.0 == "quicknode"
        );
    }

    #[test]
    fn whitelist_conforming_providers__should_keep_only_the_conforming_providers() {
        // Given
        let local = one_local_provider_per_kind_of_match();
        let entry = alchemy_and_quicknode_whitelist();

        // When
        let conforming =
            ProviderWhitelistMatches::for_chain(&local, &entry).whitelist_conforming_providers();

        // Then
        let quicknode = ProviderId("quicknode".to_string());
        assert_eq!(
            conforming.iter().collect::<Vec<_>>(),
            vec![(&local_name("quicknode"), &quicknode)]
        );
        assert_eq!(
            conforming.whitelist_provider_id(&local_name("quicknode")),
            Some(&quicknode)
        );
        assert_eq!(
            conforming.whitelist_provider_id(&local_name("alchemy")),
            None
        );
    }

    #[rstest]
    #[case::two_local_providers_on_one_whitelist_provider_count_once(
        &[
            ("quicknode-a", "https://slug-a.quiknode.pro/{api_key}"),
            ("quicknode-b", "https://slug-b.quiknode.pro/{api_key}"),
        ],
        quorum(2),
        1,
        false
    )]
    #[case::distinct_whitelist_providers_meet_the_quorum(
        &[
            ("my-alchemy", "https://eth-mainnet.g.alchemy.com/v2/{api_key}"),
            ("my-quicknode", "https://my-slug.quiknode.pro/{api_key}"),
        ],
        quorum(2),
        2,
        true
    )]
    #[case::count_equal_to_the_quorum_meets_it(
        &[("quicknode", "https://my-slug.quiknode.pro/{api_key}")],
        quorum(1),
        1,
        true
    )]
    fn whitelist_conforming_providers__should_count_distinct_whitelist_providers_against_the_quorum(
        #[case] local_providers: &[(&str, &str)],
        #[case] required: NonZeroUsize,
        #[case] expected_count: usize,
        #[case] expected_meets_quorum: bool,
    ) {
        // Given
        let local = local_chain(local_providers);
        let entry = alchemy_and_quicknode_whitelist();

        // When
        let conforming =
            ProviderWhitelistMatches::for_chain(&local, &entry).whitelist_conforming_providers();

        // Then
        assert_eq!(conforming.whitelist_provider_count(), expected_count);
        assert_eq!(conforming.meets_quorum(required), expected_meets_quorum);
    }
}
