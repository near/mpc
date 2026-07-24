//! Per-network reference transactions and the value an inspector must extract
//! from each. A mainnet transaction does not exist on testnet (and vice versa),
//! so the vectors are network-specific; `None` means the chain is skipped.

use anyhow::Context;

use crate::network::Network;

/// Hashes are hex, with or without a `0x` prefix.
#[derive(Clone, Copy)]
pub struct BlockHashVector {
    pub tx: &'static str,
    pub block_hash: &'static str,
}

#[derive(Clone, Copy)]
pub struct AptosVector {
    pub tx: &'static str,
    pub event_type_tag: &'static str,
    pub event_sequence_number: u64,
}

/// Unlike other chains, Sui is verified by chain identity rather than a pinned
/// reference transaction — see [`check_sui`](crate::checks::check_sui).
#[derive(Clone, Copy)]
pub struct SuiVector {
    /// Base58 of the 32-byte genesis checkpoint digest, exactly as `get_service_info`
    /// returns it (`sui.rpc.v2`: "the digest of the genesis checkpoint"). Its 4-byte
    /// prefix is the well-known Sui chain identifier — mainnet `0x35834a8a`, testnet
    /// `0x4c78adac` — which is the value to grep against Sui docs to verify these.
    pub chain_id: &'static str,
}

/// Like [`SuiVector`], a chain-identity reference (not a pinned transaction): a constant the
/// provider must report for its network, interpreted per chain — an EVM numeric `eth_chainId`
/// (e.g. `8453`) or a Starknet short-string felt (e.g. `0x534e5f4d41494e` = `SN_MAIN`; decode
/// the hex as ASCII to verify). See [`check_evm`](crate::checks::check_evm) and
/// [`check_starknet`](crate::checks::check_starknet).
#[derive(Clone, Copy)]
pub struct IdentityVector {
    pub identity: &'static str,
}

pub struct GoldenSet {
    pub base: Option<IdentityVector>,
    pub bnb: Option<IdentityVector>,
    pub arbitrum: Option<IdentityVector>,
    pub polygon: Option<IdentityVector>,
    pub hyper_evm: Option<IdentityVector>,
    pub abstract_chain: Option<IdentityVector>,
    pub bitcoin: Option<BlockHashVector>,
    pub starknet: Option<IdentityVector>,
    pub aptos: Option<AptosVector>,
    pub sui: Option<SuiVector>,
}

pub fn golden_set(network: Network) -> GoldenSet {
    match network {
        Network::Mainnet => MAINNET,
        Network::Testnet => TESTNET,
    }
}

const MAINNET: GoldenSet = GoldenSet {
    // EVM chain ids (decimal), verified against each chain's public RPC via `eth_chainId`
    // (2026-07-24), including `hyper_evm` and `abstract`.
    base: Some(IdentityVector { identity: "8453" }),
    bnb: Some(IdentityVector { identity: "56" }),
    arbitrum: Some(IdentityVector { identity: "42161" }),
    polygon: Some(IdentityVector { identity: "137" }),
    hyper_evm: Some(IdentityVector { identity: "999" }),
    abstract_chain: Some(IdentityVector { identity: "2741" }),
    bitcoin: Some(BlockHashVector {
        tx: "58ee376171bcc4e2cc040c13848d420b5eaf2f634872055b0a08c1fc2ec6453c",
        block_hash: "00000000000000000001fadaf3f8591e071c202762193cf78e389ea691f2ecab",
    }),
    starknet: Some(IdentityVector {
        identity: "0x534e5f4d41494e",
    }),
    aptos: Some(AptosVector {
        tx: "adc6b85a0931fc7f0d7e3839b52d63105e22cec1cb1cdee48aa2065773098c3c",
        event_type_tag: "0x1::block::NewBlockEvent",
        event_sequence_number: 822_198_006,
    }),
    sui: Some(SuiVector {
        chain_id: "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S",
    }),
};

const TESTNET: GoldenSet = GoldenSet {
    base: None,
    bnb: None,
    arbitrum: None,
    polygon: None,
    hyper_evm: None,
    abstract_chain: Some(IdentityVector { identity: "11124" }),
    bitcoin: Some(BlockHashVector {
        tx: "5acaa0890f8c1f1b2ac114c25b38d376f23beda1b59e9bcba33256d6e11d7e8e",
        block_hash: "000000000000021f43445ab447b3fc85e93eca26b56a4f23ef6c017682038ca2",
    }),
    starknet: Some(IdentityVector {
        identity: "0x534e5f5345504f4c4941",
    }),
    aptos: Some(AptosVector {
        tx: "b463d73b3a2e9c684caf9b27eb66a147348130c50fc8fa74a3f56e712c942773",
        event_type_tag: "0x1::block::NewBlockEvent",
        event_sequence_number: 302_761_912,
    }),
    sui: Some(SuiVector {
        chain_id: "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD",
    }),
};

/// Decode a 32-byte hash from hex, tolerating an optional `0x` prefix.
pub fn hex32(hex: &str) -> anyhow::Result<[u8; 32]> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(stripped).with_context(|| format!("invalid hex: {hex}"))?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}: {hex}", b.len()))
}

/// Parse an EVM chain id, accepting decimal (`8453`) or `0x`-hex (`0x2105`).
pub fn chain_id_u64(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    match s.strip_prefix("0x") {
        Some(hex) => {
            u64::from_str_radix(hex, 16).with_context(|| format!("invalid hex chain id: {s}"))
        }
        None => s.parse().with_context(|| format!("invalid chain id: {s}")),
    }
}

/// Decode a Starknet felt (`0x`-prefixed, possibly fewer than 64 hex digits) into
/// a left-zero-padded 32-byte array.
pub fn felt32(felt: &str) -> anyhow::Result<[u8; 32]> {
    let stripped = felt.strip_prefix("0x").unwrap_or(felt);
    anyhow::ensure!(stripped.len() <= 64, "felt too long: {felt}");
    hex32(&format!("{stripped:0>64}"))
}

/// Decode a base58-encoded 32-byte digest (the form Sui APIs use).
pub fn base58_32(digest: &str) -> anyhow::Result<[u8; 32]> {
    // 32 bytes encode to at most 44 base58 characters; rejecting longer inputs up front
    // also bounds `bs58`'s superlinear decode.
    anyhow::ensure!(
        digest.len() <= 44,
        "base58 digest too long: {} characters",
        digest.len()
    );
    let bytes = bs58::decode(digest)
        .into_vec()
        .with_context(|| format!("invalid base58: {digest}"))?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}: {digest}", b.len()))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn hex32__should_decode_with_and_without_prefix() {
        // Given / When / Then
        hex32("00").unwrap_err();
        assert_eq!(
            hex32("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap()
                [31],
            1
        );
    }

    #[test]
    fn felt32__should_left_pad_short_felts() {
        // Given
        let felt = "0x1";

        // When
        let bytes = felt32(felt).unwrap();

        // Then
        assert_eq!(bytes[31], 1);
        assert_eq!(bytes[..31], [0u8; 31]);
    }

    #[test]
    fn golden_sets__should_all_parse() {
        // Given / When / Then
        for network in [Network::Mainnet, Network::Testnet] {
            let set = golden_set(network);
            if let Some(v) = set.bitcoin {
                hex32(v.tx).unwrap();
                hex32(v.block_hash).unwrap();
            }
            for v in [
                set.base,
                set.bnb,
                set.arbitrum,
                set.polygon,
                set.hyper_evm,
                set.abstract_chain,
            ]
            .into_iter()
            .flatten()
            {
                chain_id_u64(v.identity).unwrap();
            }
            if let Some(v) = set.starknet {
                felt32(v.identity).unwrap();
            }
            if let Some(v) = set.aptos {
                hex32(v.tx).unwrap();
            }
            if let Some(v) = set.sui {
                base58_32(v.chain_id).unwrap();
            }
        }
    }

    #[test]
    fn base58_32__should_decode_sui_digest() {
        // Given
        let digest = "8eBMXpC8Np7RNDwwiGwSmeev1cSoc7w3fPXdikhH7RZo";

        // When
        let bytes = base58_32(digest).unwrap();

        // Then
        assert_eq!(
            hex::encode(bytes),
            "7188017648e8e95bfa6c0591988f3c7a6ec6caf3967e294f70d906a376d5e4fe"
        );
    }

    #[test]
    fn base58_32__should_reject_invalid_input() {
        // Contains characters outside the base58 alphabet (`0`, `O`, `I`, `l`): decode fails.
        base58_32("not-base58-0OIl").unwrap_err();
        // Valid base58, but decodes to fewer than 32 bytes.
        base58_32("abc").unwrap_err();
        // Longer than any 32-byte digest's base58 (max 44 chars); rejected on length up front,
        // before decoding, since `bs58`'s decode is superlinear in the input length.
        base58_32(&"1".repeat(45)).unwrap_err();
    }
}
