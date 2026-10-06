//! Links a configured foreign chain RPC provider to the whitelist entry it stands for, by URL, and
//! lists every way the provider differs from that entry.
//!
//! A configured provider links to the entry of its chain whose [`ProviderConfig::base_url`] has
//! the same host. Its config name plays no part. A `{}` label in a base URL host stands for exactly
//! one host label of `[A-Za-z0-9-]`, such as a QuickNode slug. When several entries match the
//! host, an exact host beats a `{}`, then the longest base path prefix wins, then the lowest
//! [`ProviderId`].
//!
//! ```
//! use mpc_node_config::foreign_chains::provider_identity::{ConfiguredAuth, link};
//! use near_mpc_contract_interface::types::{ChainEntry, ProviderId};
//! use url::Url;
//!
//! fn conforming_id<'w>(entry: &'w ChainEntry, rpc_url: &Url) -> Option<&'w ProviderId> {
//!     let link = link(entry, rpc_url, ConfiguredAuth::None)?;
//!     link.conforms().then_some(link.id)
//! }
//! ```

use near_mpc_contract_interface::types::{
    AuthScheme, ChainEntry, ChainRouting, ProviderConfig, ProviderId,
};
use url::Url;

const WILDCARD_LABEL: &str = "{}";

/// The auth of a configured provider, without its token.
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

/// A configured provider linked to the whitelisted provider with its URL host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhitelistLink<'w> {
    pub id: &'w ProviderId,
    pub whitelisted: &'w ProviderConfig,
    /// Every way the configured provider differs from [`Self::whitelisted`].
    pub mismatches: Vec<Mismatch>,
}

impl WhitelistLink<'_> {
    /// Whether scheme, port, path, chain routing and auth all match [`Self::whitelisted`].
    pub fn conforms(&self) -> bool {
        self.mismatches.is_empty()
    }
}

/// A way a configured provider differs from its [`WhitelistLink::whitelisted`] provider. Holds no
/// configured URL part but its scheme and port, so it is safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mismatch {
    Scheme {
        configured: String,
        whitelisted: String,
    },
    /// Only reported when the schemes match, since the default port follows the scheme.
    Port {
        configured: Option<u16>,
        whitelisted: Option<u16>,
    },
    /// The whitelisted base path is not a segment prefix of the configured path.
    Path,
    /// The configured URL does not carry the whitelisted [`ChainRouting`].
    ChainRouting,
    /// The configured auth is not of the whitelisted kind.
    AuthKind { whitelisted: AuthScheme },
    HeaderName {
        configured: String,
        whitelisted: String,
    },
    HeaderScheme {
        configured: Option<String>,
        whitelisted: Option<String>,
    },
    QueryName {
        configured: String,
        whitelisted: String,
    },
    /// The path auth placeholder is not the whole path segment after the base path and any
    /// routing segment.
    PlaceholderPosition,
    /// The whitelisted [`ChainRouting`] or [`AuthScheme`] is a variant this binary does not know.
    UnknownContractVariant,
}

/// Links a configured provider to the whitelisted provider with its host, or returns [`None`] if
/// `entry` has none. A `base_url` that does not parse links to nothing.
pub fn link<'w>(
    entry: &'w ChainEntry,
    rpc_url: &Url,
    auth: ConfiguredAuth<'_>,
) -> Option<WhitelistLink<'w>> {
    let path = path_segments(rpc_url);
    entry
        .providers
        .iter()
        .rev()
        .filter_map(|(id, whitelisted)| {
            let base = Url::parse(&whitelisted.base_url).ok()?;
            host_matches(&base, rpc_url).then_some((id, whitelisted, base))
        })
        // `max_by_key` keeps the last of equals, so the reversed order yields the lowest id.
        .max_by_key(|(_, _, base)| {
            let exact_host = !base
                .host_str()
                .is_some_and(|host| host.contains(WILDCARD_LABEL));
            let base_path = path_segments(base);
            let prefix_len = path.starts_with(&base_path).then_some(base_path.len());
            (exact_host, prefix_len)
        })
        .map(|(id, whitelisted, base)| WhitelistLink {
            id,
            whitelisted,
            mismatches: compare(whitelisted, &base, rpc_url, &path, auth),
        })
}

fn host_matches(base: &Url, url: &Url) -> bool {
    let (Some(pattern), Some(host)) = (base.host_str(), url.host_str()) else {
        return false;
    };
    let pattern: Vec<&str> = pattern.split('.').collect();
    let host: Vec<&str> = host.split('.').collect();
    pattern.len() == host.len()
        && pattern.iter().zip(&host).all(|(expected, actual)| {
            if *expected == WILDCARD_LABEL {
                is_host_label(actual)
            } else {
                expected == actual
            }
        })
}

fn is_host_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn compare(
    whitelisted: &ProviderConfig,
    base: &Url,
    url: &Url,
    path: &[&str],
    auth: ConfiguredAuth<'_>,
) -> Vec<Mismatch> {
    let base_path = path_segments(base);
    let after_base = path.strip_prefix(base_path.as_slice());
    let (routing, token_position) = compare_routing(&whitelisted.chain_routing, url, after_base);
    compare_scheme_and_port(base, url)
        .into_iter()
        .chain(after_base.is_none().then_some(Mismatch::Path))
        .chain(routing)
        .chain(compare_auth(
            auth,
            &whitelisted.auth_scheme,
            url,
            token_position,
        ))
        .collect()
}

fn compare_scheme_and_port(base: &Url, url: &Url) -> Option<Mismatch> {
    if url.scheme() != base.scheme() {
        Some(Mismatch::Scheme {
            configured: url.scheme().to_owned(),
            whitelisted: base.scheme().to_owned(),
        })
    } else if url.port_or_known_default() != base.port_or_known_default() {
        Some(Mismatch::Port {
            configured: url.port_or_known_default(),
            whitelisted: base.port_or_known_default(),
        })
    } else {
        None
    }
}

/// Returns the routing mismatch and the path segments where a path auth token belongs, or
/// [`None`] if the configured path leaves that position undefined.
fn compare_routing<'p>(
    routing: &ChainRouting,
    url: &Url,
    after_base: Option<&'p [&'p str]>,
) -> (Option<Mismatch>, Option<&'p [&'p str]>) {
    match routing {
        ChainRouting::Embedded => (None, after_base),
        ChainRouting::PathSegment { segment } => {
            let after_routing = after_base.and_then(|rest| strip_segment(url, rest, segment));
            let mismatch = after_base.is_some() && after_routing.is_none();
            (mismatch.then_some(Mismatch::ChainRouting), after_routing)
        }
        ChainRouting::QueryParam { name, value } => {
            let mut values = url.query_pairs().filter(|(key, _)| key == name);
            let found =
                matches!((values.next(), values.next()), (Some((_, v)), None) if v == *value);
            ((!found).then_some(Mismatch::ChainRouting), after_base)
        }
        _ => (Some(Mismatch::UnknownContractVariant), None),
    }
}

fn compare_auth(
    configured: ConfiguredAuth<'_>,
    whitelisted: &AuthScheme,
    url: &Url,
    token_position: Option<&[&str]>,
) -> Vec<Mismatch> {
    match (configured, whitelisted) {
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
                    configured: name.to_owned(),
                    whitelisted: whitelisted_name.clone(),
                });
            let schemes_match = match (scheme, whitelisted_scheme.as_deref()) {
                (Some(configured), Some(whitelisted)) => {
                    configured.eq_ignore_ascii_case(whitelisted)
                }
                (None, None) => true,
                _ => false,
            };
            let scheme_mismatch = (!schemes_match).then(|| Mismatch::HeaderScheme {
                configured: scheme.map(str::to_owned),
                whitelisted: whitelisted_scheme.clone(),
            });
            name_mismatch.into_iter().chain(scheme_mismatch).collect()
        }
        (ConfiguredAuth::Path { placeholder }, AuthScheme::Path { .. }) => token_position
            .filter(|position| strip_segment(url, position, placeholder).is_none())
            .map(|_| Mismatch::PlaceholderPosition)
            .into_iter()
            .collect(),
        (
            ConfiguredAuth::Query { name },
            AuthScheme::Query {
                name: whitelisted_name,
            },
        ) => (name != whitelisted_name)
            .then(|| Mismatch::QueryName {
                configured: name.to_owned(),
                whitelisted: whitelisted_name.clone(),
            })
            .into_iter()
            .collect(),
        (
            _,
            AuthScheme::None
            | AuthScheme::Header { .. }
            | AuthScheme::Path { .. }
            | AuthScheme::Query { .. },
        ) => {
            vec![Mismatch::AuthKind {
                whitelisted: whitelisted.clone(),
            }]
        }
        _ => vec![Mismatch::UnknownContractVariant],
    }
}

/// Strips `segment` off the front of `path`, comparing it the way [`Url`] encodes a path segment.
/// [`None`] if `segment` is not the first segment or spans several.
fn strip_segment<'p>(url: &Url, path: &'p [&'p str], segment: &str) -> Option<&'p [&'p str]> {
    let (first, rest) = path.split_first()?;
    let mut encoded = url.clone();
    encoded.set_path(segment);
    let mut segments = encoded.path_segments()?;
    matches!((segments.next(), segments.next()), (Some(only), None) if only == *first)
        .then_some(rest)
}

/// Drops the empty segments a trailing slash leaves. Inner empty segments stay, since the node
/// sends them.
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

    /// The linked whitelist id and the mismatches, or [`None`] if `rpc_url` links to no entry.
    fn must_link<'w>(
        entry: &'w ChainEntry,
        rpc_url: &str,
        auth: ConfiguredAuth<'_>,
    ) -> Option<(&'w str, Vec<Mismatch>)> {
        let url = Url::parse(rpc_url).expect("a test rpc_url parses");
        link(entry, &url, auth).map(|link| (link.id.0.as_str(), link.mismatches))
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
    #[case::one_label_for_each_wildcard("https://a.b.example.org/key", "two-wildcards")]
    fn link__should_link_by_host(#[case] rpc_url: &str, #[case] expected: &str) {
        // Given
        let entry = must_host_patterns();

        // When
        let link = must_link(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(link, Some((expected, vec![])));
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
    #[case::one_label_for_two_wildcards("https://a.example.org/key")]
    #[case::wildcard_inside_a_label("https://api-x.example.com/key")]
    #[case::unparseable_base_url("https://eth.example.net/v2/key")]
    fn link__should_not_link_a_url_whose_host_matches_no_entry(#[case] rpc_url: &str) {
        // Given
        let entry = must_host_patterns();

        // When
        let link = must_link(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(link, None);
    }

    #[rstest]
    #[case::exact_host_over_wildcard("https://api.quiknode.pro/", "exact", vec![Mismatch::Path])]
    #[case::longest_base_path_prefix("https://api.example.com/v1/beta/x", "beta", vec![])]
    #[case::lowest_id_among_equal_prefixes("https://api.example.com/v1/x", "stable", vec![])]
    #[case::lowest_id_when_no_prefix_matches("https://api.example.com/v3", "beta", vec![Mismatch::Path])]
    fn link__should_prefer_exact_host_then_longest_base_path_then_lowest_id(
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
        let link = must_link(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(link, Some((expected_id, expected_mismatches)));
    }

    #[rstest]
    #[case::trailing_slash_on_the_rpc_url("https://eth.alchemy.com/v2/", vec![])]
    #[case::no_trailing_slash("https://eth.alchemy.com/v2", vec![])]
    #[case::other_port(
        "https://eth.alchemy.com:8443/v2/key",
        vec![Mismatch::Port { configured: Some(8443), whitelisted: Some(443) }]
    )]
    #[case::other_scheme(
        "http://eth.alchemy.com/v2/key",
        vec![Mismatch::Scheme { configured: "http".to_string(), whitelisted: "https".to_string() }]
    )]
    #[case::websocket_scheme(
        "wss://eth.alchemy.com/v2/key",
        vec![Mismatch::Scheme { configured: "wss".to_string(), whitelisted: "https".to_string() }]
    )]
    #[case::path_with_only_a_string_prefix("https://eth.alchemy.com/v2-evil/key", vec![Mismatch::Path])]
    #[case::empty_segment_before_the_base_path("https://eth.alchemy.com//v2/key", vec![Mismatch::Path])]
    fn link__should_compare_scheme_port_and_path_segments(
        #[case] rpc_url: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let entry = must_chain_entry(&[("alchemy", whitelisted("https://eth.alchemy.com/v2/"))]);

        // When
        let link = must_link(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(link, Some(("alchemy", expected_mismatches)));
    }

    #[rstest]
    #[case::exact_segment("https://rpc.ankr.com/eth", vec![])]
    #[case::longer_segment("https://rpc.ankr.com/ethereum", vec![Mismatch::ChainRouting])]
    #[case::segment_further_down("https://rpc.ankr.com/x/eth", vec![Mismatch::ChainRouting])]
    #[case::missing_segment("https://rpc.ankr.com", vec![Mismatch::ChainRouting])]
    fn link__should_require_the_routing_segment_right_after_the_base_path(
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
        let link = must_link(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(link, Some(("ankr", expected_mismatches)));
    }

    #[rstest]
    #[case::exact_pair("?network=ethereum", vec![])]
    #[case::encoded_value("?network=ethere%75m&dkey=k", vec![])]
    #[case::longer_value("?network=ethereum-sepolia", vec![Mismatch::ChainRouting])]
    #[case::longer_name("?xnetwork=ethereum", vec![Mismatch::ChainRouting])]
    #[case::repeated_name("?network=ethereum&network=bsc", vec![Mismatch::ChainRouting])]
    #[case::missing_pair("", vec![Mismatch::ChainRouting])]
    fn link__should_require_exactly_the_routing_query_pair(
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
        let link = must_link(&entry, &rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(link, Some(("drpc", expected_mismatches)));
    }

    #[rstest]
    #[case::other_text_than_whitelisted("https://eth.alchemy.com/v2/{api_key}", "{api_key}", vec![])]
    #[case::followed_by_more_segments("https://eth.alchemy.com/v2/{api_key}/v1", "{api_key}", vec![])]
    #[case::space("https://eth.alchemy.com/v2/{api key}", "{api key}", vec![])]
    #[case::angle_brackets("https://eth.alchemy.com/v2/<KEY>", "<KEY>", vec![])]
    #[case::already_encoded("https://eth.alchemy.com/v2/%7Bkey%7D", "%7Bkey%7D", vec![])]
    #[case::one_segment_late("https://eth.alchemy.com/v2/x/{api_key}", "{api_key}", vec![Mismatch::PlaceholderPosition])]
    #[case::after_an_empty_segment("https://eth.alchemy.com/v2//{api_key}", "{api_key}", vec![Mismatch::PlaceholderPosition])]
    #[case::part_of_the_segment("https://eth.alchemy.com/v2/key{api_key}", "{api_key}", vec![Mismatch::PlaceholderPosition])]
    #[case::in_the_query("https://eth.alchemy.com/v2?key={api_key}", "{api_key}", vec![Mismatch::PlaceholderPosition])]
    #[case::in_the_host("https://eth.alchemy.com/v2/key", "alchemy", vec![Mismatch::PlaceholderPosition])]
    #[case::spanning_segments("https://eth.alchemy.com/v2/a/b", "a/b", vec![Mismatch::PlaceholderPosition])]
    fn link__should_check_the_placeholder_by_position_as_the_url_encodes_it(
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
        let link = must_link(&entry, rpc_url, ConfiguredAuth::Path { placeholder });

        // Then
        assert_eq!(link, Some(("alchemy", expected_mismatches)));
    }

    #[rstest]
    #[case::after_the_routing_segment("https://rpc.ankr.com/eth/{api_key}", vec![])]
    #[case::before_the_routing_segment("https://rpc.ankr.com/{api_key}/eth", vec![Mismatch::ChainRouting])]
    #[case::one_segment_late("https://rpc.ankr.com/eth/x/{api_key}", vec![Mismatch::PlaceholderPosition])]
    fn link__should_expect_the_placeholder_after_the_routing_segment(
        #[case] rpc_url: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let routing = ChainRouting::PathSegment {
            segment: "eth".to_string(),
        };
        let entry = must_chain_entry(&[("ankr", path_auth("https://rpc.ankr.com", routing))]);

        // When
        let link = must_link(&entry, rpc_url, API_KEY);

        // Then
        assert_eq!(link, Some(("ankr", expected_mismatches)));
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
            Mismatch::HeaderName { configured: "x-api-key".to_string(), whitelisted: "Authorization".to_string() },
            Mismatch::HeaderScheme { configured: Some("Basic".to_string()), whitelisted: Some("Bearer".to_string()) },
        ]
    )]
    #[case::scheme_only_whitelisted(
        Some("Bearer"),
        ConfiguredAuth::Header { name: "Authorization", scheme: None },
        vec![Mismatch::HeaderScheme { configured: None, whitelisted: Some("Bearer".to_string()) }]
    )]
    #[case::scheme_only_configured(
        None,
        BEARER,
        vec![Mismatch::HeaderScheme { configured: Some("bearer".to_string()), whitelisted: None }]
    )]
    #[case::other_auth_kind(
        None,
        ConfiguredAuth::None,
        vec![Mismatch::AuthKind { whitelisted: AuthScheme::Header { name: "Authorization".to_string(), scheme: None } }]
    )]
    fn link__should_compare_header_auth_without_letter_case(
        #[case] whitelisted_scheme: Option<&str>,
        #[case] configured: ConfiguredAuth<'_>,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let entry = must_chain_entry(&[("geomi", header_auth(whitelisted_scheme))]);

        // When
        let link = must_link(&entry, GEOMI_URL, configured);

        // Then
        assert_eq!(link, Some(("geomi", expected_mismatches)));
    }

    #[rstest]
    #[case::same_name("apikey", vec![])]
    #[case::other_letter_case("ApiKey", vec![Mismatch::QueryName { configured: "ApiKey".to_string(), whitelisted: "apikey".to_string() }])]
    #[case::other_name("dkey", vec![Mismatch::QueryName { configured: "dkey".to_string(), whitelisted: "apikey".to_string() }])]
    fn link__should_compare_the_query_auth_name_exactly(
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
        let link = must_link(
            &entry,
            "https://lb.drpc.org/ogrpc",
            ConfiguredAuth::Query { name: configured },
        );

        // Then
        assert_eq!(link, Some(("drpc", expected_mismatches)));
    }
}
