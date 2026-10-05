//! Identifies the whitelist entry a configured foreign chain RPC provider stands for, by its URL,
//! and lists every way the provider differs from that entry.
//!
//! A configured provider links to the entry of its chain whose [`ProviderConfig::base_url`] has
//! the same host. Its config name plays no part. A `{}` in a base URL stands for exactly one host
//! label of `[A-Za-z0-9-]`, such as a QuickNode slug. When several entries match the host, an exact
//! host beats a `{}`, then the entry whose base path is the longest segment prefix of the
//! configured path wins, and among equals the lowest [`ProviderId`].
//!
//! ```
//! use mpc_node_config::foreign_chains::provider_identity::{
//!     ChainWhitelist, ConfiguredAuth, ConfiguredUrl,
//! };
//! use near_mpc_contract_interface::types::{ChainEntry, ProviderId};
//!
//! fn conforming_id<'w>(entry: &'w ChainEntry, rpc_url: &str) -> Option<&'w ProviderId> {
//!     let whitelist = ChainWhitelist::parse(entry);
//!     let url = ConfiguredUrl::parse(rpc_url).ok()?;
//!     let link = whitelist.link(&url, ConfiguredAuth::None)?;
//!     link.conforms().then(|| link.id())
//! }
//! ```

use std::cmp::Reverse;
use std::fmt;

use near_mpc_contract_interface::types::{
    AuthScheme, ChainEntry, ChainRouting, ProviderConfig, ProviderId,
};
use url::{Host, Url};

const WILDCARD: &str = "{}";
/// Parsed in place of [`WILDCARD`], which [`Url::parse`] may reject in a host.
const WILDCARD_STAND_IN: &str = "x-wildcard-x";

/// The whitelist entry of one chain, parsed for linking configured providers to it.
#[derive(Debug, Clone)]
pub struct ChainWhitelist<'w> {
    providers: Vec<WhitelistedProvider<'w>>,
    unparseable: Vec<UnparseableProvider<'w>>,
}

impl<'w> ChainWhitelist<'w> {
    pub fn parse(entry: &'w ChainEntry) -> Self {
        let mut providers = Vec::new();
        let mut unparseable = Vec::new();
        for (id, config) in entry.providers.iter() {
            match BaseUrl::parse(&config.base_url) {
                Ok(base_url) => providers.push(WhitelistedProvider {
                    id,
                    config,
                    base_url,
                }),
                Err(error) => unparseable.push(UnparseableProvider { id, config, error }),
            }
        }
        Self {
            providers,
            unparseable,
        }
    }

    /// Whitelisted providers no configured provider can link to.
    pub fn unparseable(&self) -> &[UnparseableProvider<'w>] {
        &self.unparseable
    }

    /// Links a configured provider to the whitelisted provider with its host, or returns [`None`]
    /// if there is none.
    pub fn link(&self, url: &ConfiguredUrl, auth: ConfiguredAuth<'_>) -> Option<WhitelistLink<'w>> {
        self.providers
            .iter()
            .filter(|provider| provider.base_url.has_host_of(url))
            // `min_by_key` keeps the first of equals, and providers are in `ProviderId` order.
            .min_by_key(|provider| Reverse(provider.base_url.specificity_for(url)))
            .map(|provider| provider.compare(url, auth))
    }
}

/// A whitelisted provider whose [`ProviderConfig::base_url`] does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnparseableProvider<'w> {
    pub id: &'w ProviderId,
    pub config: &'w ProviderConfig,
    pub error: BaseUrlError,
}

/// A configured provider linked to the whitelisted provider with its URL host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhitelistLink<'w> {
    id: &'w ProviderId,
    config: &'w ProviderConfig,
    mismatches: Vec<Mismatch>,
}

impl<'w> WhitelistLink<'w> {
    pub fn id(&self) -> &'w ProviderId {
        self.id
    }

    pub fn whitelisted(&self) -> &'w ProviderConfig {
        self.config
    }

    /// Every way the configured provider differs from [`Self::whitelisted`].
    pub fn mismatches(&self) -> &[Mismatch] {
        &self.mismatches
    }

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
    /// The whitelisted [`ChainRouting`] is a variant this binary does not know.
    UnknownChainRouting,
    AuthKind {
        configured: AuthKind,
        whitelisted: AuthKind,
    },
    /// The whitelisted [`AuthScheme`] is a variant this binary does not know.
    UnknownAuthScheme,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    None,
    Header,
    Path,
    Query,
}

impl AuthKind {
    fn of_whitelisted(scheme: &AuthScheme) -> Option<Self> {
        match scheme {
            AuthScheme::None => Some(Self::None),
            AuthScheme::Header { .. } => Some(Self::Header),
            AuthScheme::Path { .. } => Some(Self::Path),
            AuthScheme::Query { .. } => Some(Self::Query),
            _ => None,
        }
    }
}

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

impl ConfiguredAuth<'_> {
    fn kind(&self) -> AuthKind {
        match self {
            Self::None => AuthKind::None,
            Self::Header { .. } => AuthKind::Header,
            Self::Path { .. } => AuthKind::Path,
            Self::Query { .. } => AuthKind::Query,
        }
    }
}

/// The `rpc_url` of a configured provider, parsed for linking.
#[derive(Clone)]
pub struct ConfiguredUrl {
    url: Url,
    host: Option<Host<String>>,
    path: Vec<String>,
}

impl ConfiguredUrl {
    pub fn parse(rpc_url: &str) -> Result<Self, url::ParseError> {
        let url = Url::parse(rpc_url)?;
        Ok(Self {
            host: url.host().map(|host| host.to_owned()),
            path: path_segments(&url),
            url,
        })
    }

    fn has_single_query_pair(&self, name: &str, value: &str) -> bool {
        let mut values = self
            .url
            .query_pairs()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value);
        matches!((values.next(), values.next()), (Some(only), None) if only == value)
    }
}

/// Hides the URL, which can hold an API key or a slug.
impl fmt::Debug for ConfiguredUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfiguredUrl(..)")
    }
}

/// A whitelisted [`ProviderConfig::base_url`] in parsed form.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BaseUrl {
    scheme: String,
    host: HostPattern,
    port: Option<u16>,
    path: Vec<String>,
}

impl BaseUrl {
    fn parse(base_url: &str) -> Result<Self, BaseUrlError> {
        let (url, host) = match base_url.split_once(WILDCARD) {
            None => {
                let url = Url::parse(base_url)?;
                let host = url.host().ok_or(BaseUrlError::NoHost)?.to_owned();
                (url, HostPattern::Exact(host))
            }
            Some((before, after)) => {
                // A stand in already present would make the free label ambiguous.
                if after.contains(WILDCARD)
                    || base_url.to_ascii_lowercase().contains(WILDCARD_STAND_IN)
                {
                    return Err(BaseUrlError::Wildcard);
                }
                let url = Url::parse(&format!("{before}{WILDCARD_STAND_IN}{after}"))?;
                let host = HostPattern::with_free_label(url.host())?;
                (url, host)
            }
        };
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(BaseUrlError::UnexpectedComponent);
        }
        Ok(Self {
            scheme: url.scheme().to_owned(),
            host,
            port: url.port_or_known_default(),
            path: path_segments(&url),
        })
    }

    fn has_host_of(&self, url: &ConfiguredUrl) -> bool {
        url.host
            .as_ref()
            .is_some_and(|host| self.host.matches(host))
    }

    /// Ranks base URLs that share a host: an exact host beats a wildcard, then the longest base
    /// path prefix wins.
    fn specificity_for(&self, url: &ConfiguredUrl) -> (bool, Option<usize>) {
        let exact_host = matches!(self.host, HostPattern::Exact(_));
        let path_prefix_len = url.path.starts_with(&self.path).then_some(self.path.len());
        (exact_host, path_prefix_len)
    }
}

/// Why a [`ProviderConfig::base_url`] cannot be matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseUrlError {
    Url(url::ParseError),
    NoHost,
    UnexpectedComponent,
    Wildcard,
}

impl From<url::ParseError> for BaseUrlError {
    fn from(error: url::ParseError) -> Self {
        Self::Url(error)
    }
}

impl fmt::Display for BaseUrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url(error) => write!(f, "not a URL: {error}"),
            Self::NoHost => f.write_str("has no host"),
            Self::UnexpectedComponent => f.write_str("has user info, a query or a fragment"),
            Self::Wildcard => write!(f, "`{WILDCARD}` is not exactly one whole host label"),
        }
    }
}

impl std::error::Error for BaseUrlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Url(error) => Some(error),
            Self::NoHost | Self::UnexpectedComponent | Self::Wildcard => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostPattern {
    Exact(Host<String>),
    OneFreeLabel { labels: Vec<String>, free: usize },
}

impl HostPattern {
    fn with_free_label(host: Option<Host<&str>>) -> Result<Self, BaseUrlError> {
        let Some(Host::Domain(domain)) = host else {
            return Err(BaseUrlError::Wildcard);
        };
        let labels: Vec<String> = domain.split('.').map(str::to_owned).collect();
        let free = {
            let mut stand_ins = labels
                .iter()
                .enumerate()
                .filter(|(_, label)| *label == WILDCARD_STAND_IN)
                .map(|(index, _)| index);
            match (stand_ins.next(), stand_ins.next()) {
                (Some(free), None) => free,
                _ => return Err(BaseUrlError::Wildcard),
            }
        };
        Ok(Self::OneFreeLabel { labels, free })
    }

    fn matches(&self, host: &Host<String>) -> bool {
        match self {
            Self::Exact(expected) => expected == host,
            Self::OneFreeLabel { labels, free } => {
                let Host::Domain(domain) = host else {
                    return false;
                };
                let actual: Vec<&str> = domain.split('.').collect();
                actual.len() == labels.len()
                    && actual
                        .iter()
                        .zip(labels)
                        .enumerate()
                        .all(|(index, (actual, expected))| {
                            if index == *free {
                                is_host_label(actual)
                            } else {
                                *actual == expected.as_str()
                            }
                        })
            }
        }
    }
}

fn is_host_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[derive(Debug, Clone)]
struct WhitelistedProvider<'w> {
    id: &'w ProviderId,
    config: &'w ProviderConfig,
    base_url: BaseUrl,
}

impl<'w> WhitelistedProvider<'w> {
    fn compare(&self, url: &ConfiguredUrl, auth: ConfiguredAuth<'_>) -> WhitelistLink<'w> {
        let mut mismatches = Vec::new();
        let scheme = url.url.scheme();
        let port = url.url.port_or_known_default();
        if scheme != self.base_url.scheme {
            mismatches.push(Mismatch::Scheme {
                configured: scheme.to_owned(),
                whitelisted: self.base_url.scheme.clone(),
            });
        } else if port != self.base_url.port {
            mismatches.push(Mismatch::Port {
                configured: port,
                whitelisted: self.base_url.port,
            });
        }
        let after_base = url.path.strip_prefix(self.base_url.path.as_slice());
        if after_base.is_none() {
            mismatches.push(Mismatch::Path);
        }
        let token_position =
            compare_chain_routing(&self.config.chain_routing, url, after_base, &mut mismatches);
        compare_auth(
            auth,
            &self.config.auth_scheme,
            token_position,
            &mut mismatches,
        );
        WhitelistLink {
            id: self.id,
            config: self.config,
            mismatches,
        }
    }
}

/// Returns the path segments where a path auth token belongs, or [`None`] if the configured path
/// leaves that position undefined.
fn compare_chain_routing<'p>(
    routing: &ChainRouting,
    url: &ConfiguredUrl,
    after_base: Option<&'p [String]>,
    mismatches: &mut Vec<Mismatch>,
) -> Option<&'p [String]> {
    match routing {
        ChainRouting::Embedded => after_base,
        ChainRouting::PathSegment { segment } => {
            let after_routing = after_base.and_then(|rest| strip_segment(rest, segment));
            if after_base.is_some() && after_routing.is_none() {
                mismatches.push(Mismatch::ChainRouting);
            }
            after_routing
        }
        ChainRouting::QueryParam { name, value } => {
            if !url.has_single_query_pair(name, value) {
                mismatches.push(Mismatch::ChainRouting);
            }
            after_base
        }
        _ => {
            mismatches.push(Mismatch::UnknownChainRouting);
            None
        }
    }
}

fn compare_auth(
    configured: ConfiguredAuth<'_>,
    whitelisted: &AuthScheme,
    token_position: Option<&[String]>,
    mismatches: &mut Vec<Mismatch>,
) {
    match (configured, whitelisted) {
        (ConfiguredAuth::None, AuthScheme::None) => {}
        (
            ConfiguredAuth::Header { name, scheme },
            AuthScheme::Header {
                name: whitelisted_name,
                scheme: whitelisted_scheme,
            },
        ) => {
            if !name.eq_ignore_ascii_case(whitelisted_name) {
                mismatches.push(Mismatch::HeaderName {
                    configured: name.to_owned(),
                    whitelisted: whitelisted_name.clone(),
                });
            }
            let schemes_match = match (scheme, whitelisted_scheme.as_deref()) {
                (Some(configured), Some(whitelisted)) => {
                    configured.eq_ignore_ascii_case(whitelisted)
                }
                (None, None) => true,
                (Some(_), None) | (None, Some(_)) => false,
            };
            if !schemes_match {
                mismatches.push(Mismatch::HeaderScheme {
                    configured: scheme.map(str::to_owned),
                    whitelisted: whitelisted_scheme.clone(),
                });
            }
        }
        (ConfiguredAuth::Path { placeholder }, AuthScheme::Path { .. }) => {
            if let Some(token_position) = token_position
                && strip_segment(token_position, placeholder).is_none()
            {
                mismatches.push(Mismatch::PlaceholderPosition);
            }
        }
        (
            ConfiguredAuth::Query { name },
            AuthScheme::Query {
                name: whitelisted_name,
            },
        ) => {
            if name != whitelisted_name {
                mismatches.push(Mismatch::QueryName {
                    configured: name.to_owned(),
                    whitelisted: whitelisted_name.clone(),
                });
            }
        }
        (configured, whitelisted) => {
            mismatches.push(match AuthKind::of_whitelisted(whitelisted) {
                Some(whitelisted) => Mismatch::AuthKind {
                    configured: configured.kind(),
                    whitelisted,
                },
                None => Mismatch::UnknownAuthScheme,
            });
        }
    }
}

/// Strips `segment` off the front of `path`, comparing it the way [`Url`] encodes a path.
fn strip_segment<'p>(path: &'p [String], segment: &str) -> Option<&'p [String]> {
    let (first, rest) = path.split_first()?;
    let encoded = encode_path_segment(segment)?;
    (*first == encoded).then_some(rest)
}

/// [`None`] if `text` spans more than one path segment.
fn encode_path_segment(text: &str) -> Option<String> {
    let mut url = Url::parse("http://localhost").ok()?;
    url.set_path(text);
    let mut segments = url.path_segments()?;
    match (segments.next(), segments.next()) {
        (Some(segment), None) => Some(segment.to_owned()),
        _ => None,
    }
}

/// Trailing slashes carry no meaning here, so empty trailing segments are dropped.
fn path_segments(url: &Url) -> Vec<String> {
    let mut segments: Vec<String> = url
        .path_segments()
        .into_iter()
        .flatten()
        .map(str::to_owned)
        .collect();
    while segments.last().is_some_and(String::is_empty) {
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
        ProviderConfig {
            base_url: base_url.to_string(),
            auth_scheme: AuthScheme::None,
            chain_routing: ChainRouting::Embedded,
        }
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
        let url = ConfiguredUrl::parse(rpc_url).expect("a test rpc_url parses");
        ChainWhitelist::parse(entry)
            .link(&url, auth)
            .map(|link| (link.id().0.as_str(), link.mismatches().to_vec()))
    }

    #[test]
    fn link__should_ignore_host_letter_case() {
        // Given
        let entry = must_chain_entry(&[(
            "alchemy",
            whitelisted("https://ETH-Mainnet.G.Alchemy.com/v2/"),
        )]);

        // When
        let link = must_link(
            &entry,
            "https://eth-mainnet.g.alchemy.COM/v2/key",
            ConfiguredAuth::None,
        );

        // Then
        assert_eq!(link, Some(("alchemy", vec![])));
    }

    #[test]
    fn link__should_treat_an_explicit_default_port_as_absent() {
        // Given
        let entry = must_chain_entry(&[("alchemy", whitelisted("https://eth.alchemy.com/v2/"))]);

        // When
        let link = must_link(
            &entry,
            "https://eth.alchemy.com:443/v2/key",
            ConfiguredAuth::None,
        );

        // Then
        assert_eq!(link, Some(("alchemy", vec![])));
    }

    #[rstest]
    #[case::other_host("https://eth.alchemy.io/v2/key")]
    #[case::whitelisted_host_as_a_subdomain("https://eth.alchemy.com.evil.io/v2/key")]
    fn link__should_not_link_a_url_with_another_host(#[case] rpc_url: &str) {
        // Given
        let entry = must_chain_entry(&[("alchemy", whitelisted("https://eth.alchemy.com/v2/"))]);

        // When
        let link = must_link(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(link, None);
    }

    #[rstest]
    #[case::other_port(
        "https://eth.alchemy.com:8443/v2/key",
        Mismatch::Port { configured: Some(8443), whitelisted: Some(443) }
    )]
    #[case::other_scheme(
        "http://eth.alchemy.com/v2/key",
        Mismatch::Scheme { configured: "http".to_string(), whitelisted: "https".to_string() }
    )]
    #[case::websocket_scheme(
        "wss://eth.alchemy.com/v2/key",
        Mismatch::Scheme { configured: "wss".to_string(), whitelisted: "https".to_string() }
    )]
    fn link__should_link_by_host_and_report_a_different_scheme_or_port(
        #[case] rpc_url: &str,
        #[case] mismatch: Mismatch,
    ) {
        // Given
        let entry = must_chain_entry(&[("alchemy", whitelisted("https://eth.alchemy.com/v2/"))]);

        // When
        let link = must_link(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(link, Some(("alchemy", vec![mismatch])));
    }

    #[test]
    fn link__should_prefer_an_exact_host_over_a_wildcard() {
        // Given
        let entry = must_chain_entry(&[
            ("wild", whitelisted("https://{}.quiknode.pro")),
            ("exact", whitelisted("https://api.quiknode.pro/v1")),
        ]);

        // When
        let link = must_link(&entry, "https://api.quiknode.pro/", ConfiguredAuth::None);

        // Then
        assert_eq!(link, Some(("exact", vec![Mismatch::Path])));
    }

    #[test]
    fn link__should_match_one_host_label_for_a_wildcard() {
        // Given
        let entry = must_chain_entry(&[(
            "quicknode",
            whitelisted("https://{}.base-sepolia.quiknode.pro"),
        )]);

        // When
        let link = must_link(
            &entry,
            "https://Misty-Fabled-7.base-sepolia.quiknode.pro/key",
            ConfiguredAuth::None,
        );

        // Then
        assert_eq!(link, Some(("quicknode", vec![])));
    }

    #[rstest]
    #[case::two_labels("https://a.b.base-sepolia.quiknode.pro/key")]
    #[case::no_label("https://base-sepolia.quiknode.pro/key")]
    #[case::empty_label("https://.base-sepolia.quiknode.pro/key")]
    #[case::suffix_moved_into_the_path("https://evil.io/.base-sepolia.quiknode.pro/key")]
    #[case::suffix_extended("https://slug.base-sepolia.quiknode.pro.evil.io/key")]
    #[case::suffix_as_user_info("https://slug.base-sepolia.quiknode.pro@evil.io/key")]
    fn link__should_not_match_a_wildcard_against_anything_but_one_label(#[case] rpc_url: &str) {
        // Given
        let entry = must_chain_entry(&[(
            "quicknode",
            whitelisted("https://{}.base-sepolia.quiknode.pro"),
        )]);

        // When
        let link = must_link(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(link, None);
    }

    #[rstest]
    #[case::part_of_a_label("https://api-{}.example.com")]
    #[case::in_the_path("https://example.com/{}")]
    #[case::twice("https://{}.{}.example.com")]
    #[case::stand_in_already_in_the_host("https://x-wildcard-x.example.com/{}")]
    fn base_url_parse__should_reject_a_wildcard_that_is_not_one_host_label(#[case] base_url: &str) {
        // When
        let parsed = BaseUrl::parse(base_url);

        // Then
        assert_eq!(parsed, Err(BaseUrlError::Wildcard));
    }

    #[rstest]
    #[case::query("https://lb.drpc.org/ogrpc?network=ethereum")]
    #[case::fragment("https://lb.drpc.org/ogrpc#top")]
    #[case::user_info("https://user@lb.drpc.org/ogrpc")]
    fn base_url_parse__should_reject_components_a_base_url_does_not_carry(#[case] base_url: &str) {
        // When
        let parsed = BaseUrl::parse(base_url);

        // Then
        assert_eq!(parsed, Err(BaseUrlError::UnexpectedComponent));
    }

    #[test]
    fn chain_whitelist_parse__should_list_providers_whose_base_url_does_not_parse() {
        // Given
        let entry = must_chain_entry(&[
            ("broken", whitelisted("not a url")),
            ("public", whitelisted("https://rpc.example.com")),
        ]);

        // When
        let whitelist = ChainWhitelist::parse(&entry);

        // Then
        let unparseable: Vec<&str> = whitelist
            .unparseable()
            .iter()
            .map(|provider| provider.id.0.as_str())
            .collect();
        assert_eq!(unparseable, vec!["broken"]);
    }

    #[test]
    fn link__should_report_a_path_that_only_shares_a_string_prefix() {
        // Given
        let entry = must_chain_entry(&[("alchemy", whitelisted("https://eth.alchemy.com/v2"))]);

        // When
        let link = must_link(
            &entry,
            "https://eth.alchemy.com/v2-evil/key",
            ConfiguredAuth::None,
        );

        // Then
        assert_eq!(link, Some(("alchemy", vec![Mismatch::Path])));
    }

    #[rstest]
    #[case::on_the_base_url("https://eth.alchemy.com/v2/", "https://eth.alchemy.com/v2")]
    #[case::on_the_rpc_url("https://eth.alchemy.com/v2", "https://eth.alchemy.com/v2/")]
    fn link__should_ignore_trailing_slashes(#[case] base_url: &str, #[case] rpc_url: &str) {
        // Given
        let entry = must_chain_entry(&[("alchemy", whitelisted(base_url))]);

        // When
        let link = must_link(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(link, Some(("alchemy", vec![])));
    }

    #[rstest]
    #[case::longest_prefix("https://api.example.com/v1/beta/x", "beta")]
    #[case::shorter_prefix("https://api.example.com/v1/x", "stable")]
    fn link__should_pick_the_entry_with_the_longest_base_path_prefix(
        #[case] rpc_url: &str,
        #[case] expected: &str,
    ) {
        // Given
        let entry = must_chain_entry(&[
            ("beta", whitelisted("https://api.example.com/v1/beta")),
            ("stable", whitelisted("https://api.example.com/v1")),
        ]);

        // When
        let link = must_link(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(link, Some((expected, vec![])));
    }

    #[rstest]
    #[case::identical_entries("https://api.example.com/v1", "https://api.example.com/v1/x", vec![])]
    #[case::no_prefix_in_either("https://api.example.com/v1", "https://api.example.com/v3", vec![Mismatch::Path])]
    fn link__should_pick_the_lowest_provider_id_among_equal_candidates(
        #[case] other_base_url: &str,
        #[case] rpc_url: &str,
        #[case] expected_mismatches: Vec<Mismatch>,
    ) {
        // Given
        let entry = must_chain_entry(&[
            ("b", whitelisted(other_base_url)),
            ("a", whitelisted("https://api.example.com/v1")),
        ]);

        // When
        let link = must_link(&entry, rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(link, Some(("a", expected_mismatches)));
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
        let entry = must_chain_entry(&[(
            "ankr",
            whitelisted_with(
                "https://rpc.ankr.com",
                AuthScheme::None,
                ChainRouting::PathSegment {
                    segment: "eth".to_string(),
                },
            ),
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
        let entry = must_chain_entry(&[(
            "drpc",
            whitelisted_with(
                "https://lb.drpc.org/ogrpc",
                AuthScheme::None,
                ChainRouting::QueryParam {
                    name: "network".to_string(),
                    value: "ethereum".to_string(),
                },
            ),
        )]);
        let rpc_url = format!("https://lb.drpc.org/ogrpc{query}");

        // When
        let link = must_link(&entry, &rpc_url, ConfiguredAuth::None);

        // Then
        assert_eq!(link, Some(("drpc", expected_mismatches)));
    }

    #[test]
    fn link__should_accept_any_placeholder_text_in_the_segment_after_the_base_path() {
        // Given
        let entry = must_chain_entry(&[(
            "alchemy",
            whitelisted_with(
                "https://eth-mainnet.g.alchemy.com/v2/",
                AuthScheme::Path {
                    placeholder: "{API_KEY}".to_string(),
                },
                ChainRouting::Embedded,
            ),
        )]);

        // When
        let link = must_link(
            &entry,
            "https://eth-mainnet.g.alchemy.com/v2/{api_key}",
            API_KEY,
        );

        // Then
        assert_eq!(link, Some(("alchemy", vec![])));
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
        let entry = must_chain_entry(&[(
            "ankr",
            whitelisted_with(
                "https://rpc.ankr.com",
                AuthScheme::Path {
                    placeholder: "{api_key}".to_string(),
                },
                ChainRouting::PathSegment {
                    segment: "eth".to_string(),
                },
            ),
        )]);

        // When
        let link = must_link(&entry, rpc_url, API_KEY);

        // Then
        assert_eq!(link, Some(("ankr", expected_mismatches)));
    }

    #[rstest]
    #[case::wrong_segment("https://eth.alchemy.com/v2/x/{api_key}", "{api_key}")]
    #[case::part_of_the_segment("https://eth.alchemy.com/v2/key{api_key}", "{api_key}")]
    #[case::in_the_query("https://eth.alchemy.com/v2?key={api_key}", "{api_key}")]
    #[case::in_the_host("https://eth.alchemy.com/v2/key", "alchemy")]
    #[case::spanning_segments("https://eth.alchemy.com/v2/a/b", "a/b")]
    fn link__should_report_a_placeholder_that_is_not_the_token_segment(
        #[case] rpc_url: &str,
        #[case] placeholder: &str,
    ) {
        // Given
        let entry = must_chain_entry(&[(
            "alchemy",
            whitelisted_with(
                "https://eth.alchemy.com/v2/",
                AuthScheme::Path {
                    placeholder: "{API_KEY}".to_string(),
                },
                ChainRouting::Embedded,
            ),
        )]);

        // When
        let link = must_link(&entry, rpc_url, ConfiguredAuth::Path { placeholder });

        // Then
        assert_eq!(link, Some(("alchemy", vec![Mismatch::PlaceholderPosition])));
    }

    #[rstest]
    #[case::braces("https://eth.alchemy.com/v2/{api_key}/v1", "{api_key}")]
    #[case::space("https://eth.alchemy.com/v2/{api key}", "{api key}")]
    #[case::angle_brackets("https://eth.alchemy.com/v2/<KEY>", "<KEY>")]
    #[case::already_encoded("https://eth.alchemy.com/v2/%7Bkey%7D", "%7Bkey%7D")]
    fn link__should_compare_the_placeholder_as_the_url_encodes_it(
        #[case] rpc_url: &str,
        #[case] placeholder: &str,
    ) {
        // Given
        let entry = must_chain_entry(&[(
            "alchemy",
            whitelisted_with(
                "https://eth.alchemy.com/v2/",
                AuthScheme::Path {
                    placeholder: "{API_KEY}".to_string(),
                },
                ChainRouting::Embedded,
            ),
        )]);

        // When
        let link = must_link(&entry, rpc_url, ConfiguredAuth::Path { placeholder });

        // Then
        assert_eq!(link, Some(("alchemy", vec![])));
    }

    fn must_header_entry(name: &str, scheme: Option<&str>) -> ChainEntry {
        must_chain_entry(&[(
            "geomi",
            whitelisted_with(
                "https://api.mainnet.aptoslabs.com/v1",
                AuthScheme::Header {
                    name: name.to_string(),
                    scheme: scheme.map(str::to_string),
                },
                ChainRouting::Embedded,
            ),
        )])
    }

    const GEOMI_URL: &str = "https://api.mainnet.aptoslabs.com/v1";

    #[test]
    fn link__should_compare_header_name_and_scheme_without_letter_case() {
        // Given
        let entry = must_header_entry("Authorization", Some("Bearer"));
        let auth = ConfiguredAuth::Header {
            name: "authorization",
            scheme: Some("bearer"),
        };

        // When
        let link = must_link(&entry, GEOMI_URL, auth);

        // Then
        assert_eq!(link, Some(("geomi", vec![])));
    }

    #[test]
    fn link__should_report_a_different_header_name_and_scheme() {
        // Given
        let entry = must_header_entry("Authorization", Some("Bearer"));
        let auth = ConfiguredAuth::Header {
            name: "x-api-key",
            scheme: Some("Basic"),
        };

        // When
        let link = must_link(&entry, GEOMI_URL, auth);

        // Then
        let expected = vec![
            Mismatch::HeaderName {
                configured: "x-api-key".to_string(),
                whitelisted: "Authorization".to_string(),
            },
            Mismatch::HeaderScheme {
                configured: Some("Basic".to_string()),
                whitelisted: Some("Bearer".to_string()),
            },
        ];
        assert_eq!(link, Some(("geomi", expected)));
    }

    #[rstest]
    #[case::configured_without(None, Some("Bearer"))]
    #[case::whitelisted_without(Some("Bearer"), None)]
    fn link__should_report_a_header_scheme_on_one_side_only(
        #[case] configured: Option<&str>,
        #[case] whitelisted: Option<&str>,
    ) {
        // Given
        let entry = must_header_entry("x-token", whitelisted);
        let auth = ConfiguredAuth::Header {
            name: "x-token",
            scheme: configured,
        };

        // When
        let link = must_link(&entry, GEOMI_URL, auth);

        // Then
        let expected = vec![Mismatch::HeaderScheme {
            configured: configured.map(str::to_string),
            whitelisted: whitelisted.map(str::to_string),
        }];
        assert_eq!(link, Some(("geomi", expected)));
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
        let entry = must_chain_entry(&[(
            "drpc",
            whitelisted_with(
                "https://lb.drpc.org/ogrpc",
                AuthScheme::Query {
                    name: "apikey".to_string(),
                },
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

    #[test]
    fn link__should_report_a_different_auth_kind() {
        // Given
        let entry = must_header_entry("x-api-key", None);

        // When
        let link = must_link(&entry, GEOMI_URL, ConfiguredAuth::None);

        // Then
        let expected = vec![Mismatch::AuthKind {
            configured: AuthKind::None,
            whitelisted: AuthKind::Header,
        }];
        assert_eq!(link, Some(("geomi", expected)));
    }

    #[test]
    fn configured_url_debug__should_hide_the_url() {
        // Given
        let url = ConfiguredUrl::parse("https://slug.base-sepolia.quiknode.pro/key")
            .expect("a test rpc_url parses");

        // When
        let printed = format!("{url:?}");

        // Then
        assert!(!printed.contains("slug"), "{printed}");
        assert!(!printed.contains("key"), "{printed}");
    }
}
