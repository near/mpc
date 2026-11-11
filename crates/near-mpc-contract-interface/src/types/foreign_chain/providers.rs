use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use serde::{Deserialize, Serialize};

/// Stable label for an RPC provider entry (e.g. `"alchemy"`, `"ankr"`, `"drpc"`).
/// Unique within a chain in the on-chain foreign-chain RPC whitelist.
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Display,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ProviderId(pub String);
/// Where the operator's API key/token gets injected into the assembled RPC URL.
/// Lives on the contract (not in operator yaml) so the operator can't pick a custom
/// auth shape that lets them inject extra path or query components.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum AuthScheme {
    /// Token sent in an HTTP header (e.g. `Authorization: Bearer <token>`).
    Header {
        name: String,
        scheme: Option<String>,
    },
    /// Token substituted into a `{placeholder}` in the URL path.
    Path { placeholder: String },
    /// Token sent as a query parameter (`?<name>=<token>`).
    Query { name: String },
    /// Public endpoint, no auth.
    None,
}
/// How chain identity is encoded in the RPC URL. Exactly one of the three encodings,
/// modelled as an enum so a vote can't accidentally produce an "all three" shape.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum ChainRouting {
    /// Chain identity already encoded in `base_url` (subdomain or path prefix).
    /// E.g. Alchemy's `eth-mainnet.g.alchemy.com`, Infura's `mainnet.infura.io`, or
    /// any chain-dedicated endpoint.
    Embedded,
    /// Append `segment` after `base_url`'s path. E.g. Ankr Ethereum: `"eth"`.
    /// `segment` MUST NOT contain `/` (validated when a vote applies).
    PathSegment { segment: String },
    /// Merge a single chain-identifying query param into the URL. E.g. dRPC Ethereum:
    /// `{ name: "network", value: "ethereum" }`.
    /// When `AuthScheme::Query { name: auth_name }` is used, `name` here MUST differ
    /// from `auth_name` (validated when a vote applies).
    QueryParam { name: String, value: String },
}
/// One provider's per-chain configuration, stored as a value in `ChainEntry.providers`
/// (keyed by [`ProviderId`]). Read by nodes at startup to assemble the actual RPC URL
/// (`base_url` + `chain_routing` + operator-supplied token via `auth_scheme`).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ProviderConfig {
    /// Provider's stable base. When `chain_routing == Embedded`, the chain identifier
    /// is already inside `base_url` (subdomain or path prefix). Otherwise `base_url`
    /// is chain-agnostic and `chain_routing` carries the chain marker.
    ///
    /// A single `{}` allows per-operator slug (e.g. QuickNode's
    /// `https://{}.sui-testnet.quiknode.pro`); nodes match it against exactly one
    /// label of the local URL, keeping the rest of the host pinned.
    pub base_url: String,
    pub auth_scheme: AuthScheme,
    pub chain_routing: ChainRouting,
}
/// Stored state for one chain in the on-chain whitelist: a non-empty map from
/// [`ProviderId`] to that provider's per-chain configuration, plus the voted RPC
/// response quorum. Returned by the
/// `allowed_foreign_chain_providers` view fn. [`NonEmptyBTreeMap`] enforces a non-empty
/// provider set and at-most-one entry per [`ProviderId`] at deserialize time,
/// and the map iterates in [`ProviderId`] order — so the canonical hash matches across
/// voters without an explicit sort step.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ChainEntry {
    pub providers: NonEmptyBTreeMap<ProviderId, ProviderConfig>,
    /// How many whitelisted providers must agree before a node accepts a verdict.
    pub quorum: u64,
}
