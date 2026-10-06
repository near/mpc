//! Finds the whitelist provider that matches a local foreign chain RPC provider, and lists the
//! parts of the local provider that differ from it.
//!
//! The URL host identifies the provider. The local config name has no effect.
//!
//! The host of a whitelisted [`ProviderConfig::base_url`] can start with the label `{}`. This
//! label matches exactly one label of the local host, for example a QuickNode slug.
//!
//! When more than one whitelist provider matches the host, [`find_match`] selects one with these
//! rules, in this order:
//! 1. An exact host comes before a `{}` host.
//! 2. A longer base path prefix comes before a shorter one.
//! 3. A lower [`ProviderId`] comes before a higher one.

use near_mpc_contract_interface::types::{
    AuthScheme, ChainEntry, ChainRouting, ProviderConfig, ProviderId,
};
use url::Url;

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

/// The whitelist provider with the same URL host as a local provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhitelistMatch<'w> {
    pub id: &'w ProviderId,
    pub whitelisted: &'w ProviderConfig,
    pub mismatches: Vec<Mismatch>,
}

impl WhitelistMatch<'_> {
    pub fn conforms(&self) -> bool {
        self.mismatches.is_empty()
    }
}

/// A part of a local provider config that differs from its [`WhitelistMatch::whitelisted`] provider.
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

pub fn find_match<'w>(
    entry: &'w ChainEntry,
    rpc_url: &Url,
    auth: ConfiguredAuth<'_>,
) -> Option<WhitelistMatch<'w>> {
    let path = path_segments(rpc_url);
    let mut best: Option<(Rank, &ProviderId, &ProviderConfig, Url)> = None;
    for (id, whitelisted) in entry.providers.iter() {
        let Ok(base) = Url::parse(&whitelisted.base_url) else {
            continue;
        };
        if !host_matches(&base, rpc_url) {
            continue;
        }
        let base_path = path_segments(&base);
        let exact_host = wildcard_suffix(&base).is_none();
        let prefix_len = path.starts_with(&base_path).then_some(base_path.len());
        let rank: Rank = (exact_host, prefix_len);
        // Ids come in ascending order, so on a tie the lower id stays.
        if best
            .as_ref()
            .is_none_or(|(best_rank, ..)| rank > *best_rank)
        {
            best = Some((rank, id, whitelisted, base));
        }
    }

    let (_, id, whitelisted, base) = best?;
    let path_mismatch = first_path_mismatch(whitelisted, &base, &path, auth);
    let path_mismatch = path_mismatch.as_ref();
    let mismatches = compare_base_url(&base, rpc_url, path_mismatch)
        .into_iter()
        .chain(compare_chain_routing(
            &whitelisted.chain_routing,
            rpc_url,
            path_mismatch,
        ))
        .chain(compare_auth(auth, &whitelisted.auth_scheme, path_mismatch))
        .collect();
    Some(WhitelistMatch {
        id,
        whitelisted,
        mismatches,
    })
}

/// Tuples compare in order: an exact host ranks first, then the longer base path prefix.
type Rank = (bool, Option<usize>);

fn wildcard_suffix(base: &Url) -> Option<&str> {
    base.host_str()?.strip_prefix("{}.")
}

fn host_matches(base: &Url, url: &Url) -> bool {
    match wildcard_suffix(base) {
        Some(suffix) => url
            .domain()
            .and_then(|domain| domain.split_once('.'))
            .is_some_and(|(slug, rest)| !slug.is_empty() && rest == suffix),
        None => base.host() == url.host(),
    }
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
    let expected = base.clone();
    if !path.starts_with(&path_segments(&expected)) {
        return Some(Mismatch::BaseUrl);
    }
    let expected = match &whitelisted.chain_routing {
        ChainRouting::PathSegment { segment } => {
            let expected = with_segment(expected, segment);
            if !path.starts_with(&path_segments(&expected)) {
                return Some(Mismatch::ChainRouting);
            }
            expected
        }
        _ => expected,
    };
    if let (ConfiguredAuth::Path { placeholder }, AuthScheme::Path { .. }) =
        (auth, &whitelisted.auth_scheme)
    {
        let expected = with_segment(expected, placeholder);
        if !path.starts_with(&path_segments(&expected)) {
            return Some(Mismatch::PlaceholderPosition);
        }
    }
    None
}

/// Encodes `segment` as [`Url::parse`] does, so `{api_key}` becomes `%7Bapi_key%7D` and equals the
/// placeholder in a parsed local URL.
fn with_segment(mut url: Url, segment: &str) -> Url {
    if let Ok(mut segments) = url.path_segments_mut() {
        segments.pop_if_empty().push(segment);
    }
    url
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
    use std::collections::BTreeMap;

    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use rstest::rstest;

    use super::*;

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

    fn must_chain_entry(providers: &[(&str, ProviderConfig)]) -> ChainEntry {
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

    fn must_find_match<'w>(
        entry: &'w ChainEntry,
        rpc_url: &str,
        auth: ConfiguredAuth<'_>,
    ) -> Option<(&'w str, Vec<Mismatch>)> {
        let url = Url::parse(rpc_url).expect("a test rpc_url parses");
        find_match(entry, &url, auth).map(|found| (found.id.0.as_str(), found.mismatches))
    }

    fn must_host_patterns() -> ChainEntry {
        must_chain_entry(&[
            ("alchemy", whitelisted("https://ETH.Alchemy.com/v2/")),
            (
                "quicknode",
                whitelisted("https://{}.base-sepolia.quiknode.pro"),
            ),
            ("two-wildcards", whitelisted("https://{}.{}.example.org")),
            (
                "wildcard-in-a-label",
                whitelisted("https://api-{}.example.com"),
            ),
            ("unparseable", whitelisted("eth.example.net/v2")),
        ])
    }

    #[rstest]
    #[case::host_letter_case("https://eth.alchemy.COM/v2/key", "alchemy")]
    #[case::explicit_default_port("https://eth.alchemy.com:443/v2/key", "alchemy")]
    #[case::one_label_for_the_wildcard(
        "https://Misty-Fabled-7.base-sepolia.quiknode.pro/key",
        "quicknode"
    )]
    fn find_match__should_match_by_host(#[case] rpc_url: &str, #[case] expected: &str) {
        // Given
        let entry = must_host_patterns();

        // When
        let whitelist_match = must_find_match(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(whitelist_match, Some((expected, vec![])));
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
    #[case::wildcard_after_the_first_label("https://a.b.example.org/key")]
    #[case::wildcard_inside_a_label("https://api-x.example.com/key")]
    #[case::unparseable_base_url("https://eth.example.net/v2/key")]
    fn find_match__should_not_match_a_url_whose_host_matches_no_entry(#[case] rpc_url: &str) {
        // Given
        let entry = must_host_patterns();

        // When
        let whitelist_match = must_find_match(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(whitelist_match, None);
    }

    #[rstest]
    #[case::exact_host_over_wildcard("https://api.quiknode.pro/", "exact", vec![Mismatch::BaseUrl])]
    #[case::longest_base_path_prefix("https://api.example.com/v1/beta/x", "beta", vec![])]
    #[case::lowest_id_among_equal_prefixes("https://api.example.com/v1/x", "stable", vec![])]
    #[case::lowest_id_when_no_prefix_matches("https://api.example.com/v3", "beta", vec![Mismatch::BaseUrl])]
    fn find_match__should_prefer_exact_host_then_longest_base_path_then_lowest_id(
        #[case] rpc_url: &str,
        #[case] expected_id: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let entry = must_chain_entry(&[
            ("wild", whitelisted("https://{}.quiknode.pro")),
            ("exact", whitelisted("https://api.quiknode.pro/v1")),
            ("beta", whitelisted("https://api.example.com/v1/beta")),
            ("stable", whitelisted("https://api.example.com/v1")),
            ("stable-copy", whitelisted("https://api.example.com/v1")),
        ]);

        // When
        let whitelist_match = must_find_match(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(whitelist_match, Some((expected_id, expected_mismatches)));
    }

    #[rstest]
    #[case::trailing_slash_on_the_rpc_url("https://eth.alchemy.com/v2/", vec![])]
    #[case::no_trailing_slash("https://eth.alchemy.com/v2", vec![])]
    #[case::other_port("https://eth.alchemy.com:8443/v2/key", vec![Mismatch::BaseUrl])]
    #[case::other_scheme("http://eth.alchemy.com/v2/key", vec![Mismatch::BaseUrl])]
    #[case::websocket_scheme("wss://eth.alchemy.com/v2/key", vec![Mismatch::BaseUrl])]
    #[case::path_with_only_a_string_prefix("https://eth.alchemy.com/v2-evil/key", vec![Mismatch::BaseUrl])]
    #[case::empty_segment_before_the_base_path("https://eth.alchemy.com//v2/key", vec![Mismatch::BaseUrl])]
    fn find_match__should_compare_scheme_port_and_base_path_segments(
        #[case] rpc_url: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let entry = must_chain_entry(&[("alchemy", whitelisted("https://eth.alchemy.com/v2/"))]);

        // When
        let whitelist_match = must_find_match(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(whitelist_match, Some(("alchemy", expected_mismatches)));
    }

    #[rstest]
    #[case::exact_segment("https://rpc.ankr.com/eth", vec![])]
    #[case::longer_segment("https://rpc.ankr.com/ethereum", vec![Mismatch::ChainRouting])]
    #[case::segment_further_down("https://rpc.ankr.com/x/eth", vec![Mismatch::ChainRouting])]
    #[case::missing_segment("https://rpc.ankr.com", vec![Mismatch::ChainRouting])]
    fn find_match__should_require_the_routing_segment_right_after_the_base_path(
        #[case] rpc_url: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let routing = ChainRouting::PathSegment {
            segment: "eth".to_string(),
        };
        let entry = must_chain_entry(&[(
            "ankr",
            whitelisted_with("https://rpc.ankr.com", AuthScheme::None, routing),
        )]);

        // When
        let whitelist_match = must_find_match(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(whitelist_match, Some(("ankr", expected_mismatches)));
    }

    #[rstest]
    #[case::exact_pair("?network=ethereum", vec![])]
    #[case::encoded_value("?network=ethere%75m&dkey=k", vec![])]
    #[case::longer_value("?network=ethereum-sepolia", vec![Mismatch::ChainRouting])]
    #[case::longer_name("?xnetwork=ethereum", vec![Mismatch::ChainRouting])]
    #[case::repeated_name("?network=ethereum&network=bsc", vec![Mismatch::ChainRouting])]
    #[case::missing_pair("", vec![Mismatch::ChainRouting])]
    fn find_match__should_require_exactly_the_routing_query_pair(
        #[case] query: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let routing = ChainRouting::QueryParam {
            name: "network".to_string(),
            value: "ethereum".to_string(),
        };
        let entry = must_chain_entry(&[(
            "drpc",
            whitelisted_with("https://lb.drpc.org/ogrpc", AuthScheme::None, routing),
        )]);
        let rpc_url = format!("https://lb.drpc.org/ogrpc{query}");

        // When
        let whitelist_match = must_find_match(&entry, &rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(whitelist_match, Some(("drpc", expected_mismatches)));
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
    #[case::spanning_segments("https://eth.alchemy.com/v2/a/b", "a/b", vec![Mismatch::PlaceholderPosition])]
    fn find_match__should_check_the_placeholder_by_position_as_the_url_encodes_it(
        #[case] rpc_url: &str,
        #[case] placeholder: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let entry = must_chain_entry(&[(
            "alchemy",
            path_auth("https://eth.alchemy.com/v2/", ChainRouting::Embedded),
        )]);

        // When
        let whitelist_match =
            must_find_match(&entry, rpc_url, ConfiguredAuth::Path { placeholder });

        // Then
        assert_eq!(whitelist_match, Some(("alchemy", expected_mismatches)));
    }

    #[rstest]
    #[case::after_the_routing_segment("https://rpc.ankr.com/eth/{api_key}", vec![])]
    #[case::before_the_routing_segment("https://rpc.ankr.com/{api_key}/eth", vec![Mismatch::ChainRouting])]
    #[case::one_segment_late("https://rpc.ankr.com/eth/x/{api_key}", vec![Mismatch::PlaceholderPosition])]
    fn find_match__should_expect_the_placeholder_after_the_routing_segment(
        #[case] rpc_url: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let routing = ChainRouting::PathSegment {
            segment: "eth".to_string(),
        };
        let entry = must_chain_entry(&[("ankr", path_auth("https://rpc.ankr.com", routing))]);

        // When
        let whitelist_match = must_find_match(&entry, rpc_url, API_KEY);

        // Then
        assert_eq!(whitelist_match, Some(("ankr", expected_mismatches)));
    }

    #[test]
    fn find_match__should_report_a_wrong_base_path_once() {
        // Given
        let routing = ChainRouting::PathSegment {
            segment: "eth".to_string(),
        };
        let entry = must_chain_entry(&[("ankr", path_auth("https://rpc.ankr.com/v1", routing))]);

        // When
        let whitelist_match =
            must_find_match(&entry, "https://rpc.ankr.com/v2/eth/{api_key}", API_KEY);

        // Then
        assert_eq!(whitelist_match, Some(("ankr", vec![Mismatch::BaseUrl])));
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
    fn find_match__should_compare_header_auth_without_letter_case(
        #[case] whitelisted_scheme: Option<&str>,
        #[case] configured: ConfiguredAuth<'_>,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let entry = must_chain_entry(&[("geomi", header_auth(whitelisted_scheme))]);

        // When
        let whitelist_match = must_find_match(&entry, GEOMI_URL, configured);

        // Then
        assert_eq!(whitelist_match, Some(("geomi", expected_mismatches)));
    }

    #[rstest]
    #[case::same_name("apikey", vec![])]
    #[case::other_letter_case("ApiKey", vec![Mismatch::QueryName { local: "ApiKey".to_string(), whitelisted: "apikey".to_string() }])]
    #[case::other_name("dkey", vec![Mismatch::QueryName { local: "dkey".to_string(), whitelisted: "apikey".to_string() }])]
    fn find_match__should_compare_the_query_auth_name_exactly(
        #[case] configured: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let auth_scheme = AuthScheme::Query {
            name: "apikey".to_string(),
        };
        let entry = must_chain_entry(&[(
            "drpc",
            whitelisted_with(
                "https://lb.drpc.org/ogrpc",
                auth_scheme,
                ChainRouting::Embedded,
            ),
        )]);

        // When
        let whitelist_match = must_find_match(
            &entry,
            "https://lb.drpc.org/ogrpc",
            ConfiguredAuth::Query { name: configured },
        );

        // Then
        assert_eq!(whitelist_match, Some(("drpc", expected_mismatches)));
    }
}
