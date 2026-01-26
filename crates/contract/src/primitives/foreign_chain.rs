use crate::{
    crypto_shared::derive_tweak,
    primitives::{
        domain::DomainId,
        signature::{Payload, Tweak},
    },
};
use near_account_id::AccountId;
use near_sdk::{bs58, near};

/// Supported foreign chains - add new variants as support is implemented
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[near(serializers=[borsh, json])]
pub enum ForeignChain {
    Solana,
    // Future: Ethereum, Bitcoin, Polygon, etc.
}

impl std::fmt::Display for ForeignChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForeignChain::Solana => write!(f, "Solana"),
        }
    }
}

/// Finality level for foreign chain transaction verification
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[near(serializers=[borsh, json])]
pub enum FinalityLevel {
    /// Transaction included but may reorg (Solana: "confirmed")
    Optimistic,
    /// Sufficient confirmations for practical finality (Solana: "finalized")
    Final,
}

impl std::fmt::Display for FinalityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FinalityLevel::Optimistic => write!(f, "Optimistic"),
            FinalityLevel::Final => write!(f, "Final"),
        }
    }
}

/// A 64-byte Solana signature with custom serialization.
/// Borsh uses raw bytes, JSON uses hex encoding.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct SolanaSignature([u8; 64]);

impl SolanaSignature {
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl std::fmt::Debug for SolanaSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SolanaSignature")
            .field(&bs58::encode(&self.0).into_string())
            .finish()
    }
}

impl borsh::BorshSerialize for SolanaSignature {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0)
    }
}

impl borsh::BorshDeserialize for SolanaSignature {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; 64];
        reader.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl near_sdk::serde::Serialize for SolanaSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: near_sdk::serde::Serializer,
    {
        // Use base58 encoding for JSON (standard Solana encoding)
        bs58::encode(&self.0).into_string().serialize(serializer)
    }
}

impl<'de> near_sdk::serde::Deserialize<'de> for SolanaSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: near_sdk::serde::Deserializer<'de>,
    {
        use near_sdk::serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let bytes = bs58::decode(&s)
            .into_vec()
            .map_err(|e| D::Error::custom(format!("invalid base58: {}", e)))?;
        if bytes.len() != 64 {
            return Err(D::Error::custom(format!(
                "expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
impl schemars::JsonSchema for SolanaSignature {
    fn schema_name() -> String {
        "SolanaSignature".to_string()
    }

    fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            format: Some("base58".to_string()),
            ..Default::default()
        })
    }
}

/// Transaction identifier - varies by chain
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[near(serializers=[borsh, json])]
pub enum TransactionId {
    /// Solana transaction signature (64 bytes, base58 encoded in JSON)
    SolanaSignature(SolanaSignature),
    // Future: Hash32([u8; 32]) for Ethereum, BitcoinTxid, etc.
}

impl TransactionId {
    /// Create a new Solana transaction ID from raw bytes
    pub fn solana(bytes: [u8; 64]) -> Self {
        TransactionId::SolanaSignature(SolanaSignature::new(bytes))
    }

    /// Convert transaction ID to bytes for hashing
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TransactionId::SolanaSignature(sig) => sig.as_bytes().to_vec(),
        }
    }
}

impl std::fmt::Display for TransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionId::SolanaSignature(sig) => {
                // Use base58 for Solana signatures (standard Solana encoding)
                write!(f, "{}", bs58::encode(sig.as_bytes()).into_string())
            }
        }
    }
}

/// Block identifier - varies by chain
#[derive(Debug, Clone, Eq, PartialEq)]
#[near(serializers=[borsh, json])]
pub enum BlockId {
    /// Solana slot number
    SolanaSlot(u64),
    // Future: EthereumBlock(u64), BitcoinHeight(u64), etc.
}

impl std::fmt::Display for BlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockId::SolanaSlot(slot) => write!(f, "Solana slot {}", slot),
        }
    }
}

/// User-facing request arguments for foreign transaction verification
/// Note: The tx_id IS the payload - we sign the transaction hash after verification
#[derive(Debug, Clone)]
#[near(serializers=[json])]
pub struct VerifyForeignTxRequestArgs {
    pub chain: ForeignChain,
    pub tx_id: TransactionId,
    pub finality: FinalityLevel,
    /// Key derivation path
    pub path: String,
    pub domain_id: Option<DomainId>,
}

/// Internal storage representation for foreign transaction verification requests
/// The payload signed is derived from tx_id (hash of the transaction identifier)
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[near(serializers=[borsh, json])]
pub struct VerifyForeignTxRequest {
    pub chain: ForeignChain,
    pub tx_id: TransactionId,
    pub finality: FinalityLevel,
    pub tweak: Tweak,
    pub domain_id: DomainId,
}

impl VerifyForeignTxRequest {
    pub fn new(
        chain: ForeignChain,
        tx_id: TransactionId,
        finality: FinalityLevel,
        domain_id: DomainId,
        predecessor_id: &AccountId,
        path: &str,
    ) -> Self {
        let tweak = derive_tweak(predecessor_id, path);
        Self {
            chain,
            tx_id,
            finality,
            tweak,
            domain_id,
        }
    }

    /// Derive payload from tx_id - hash the transaction identifier to get 32 bytes for ECDSA signing
    pub fn payload(&self) -> Payload {
        use near_sdk::env;
        let hash = env::sha256(&self.tx_id.to_bytes());
        let hash_array: [u8; 32] = hash.try_into().expect("SHA256 produces 32 bytes");
        Payload::from_legacy_ecdsa(hash_array)
    }
}

/// Response includes verification proof and signature
#[derive(Debug, Clone)]
#[near(serializers=[json])]
pub struct VerifyForeignTxResponse {
    /// Block/slot where transaction was verified
    pub verified_at_block: BlockId,
    pub signature: crate::crypto_shared::types::SignatureResponse,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_signature_display() {
        // A sample Solana signature (64 bytes)
        let sig = [1u8; 64];
        let tx_id = TransactionId::solana(sig);
        let display = format!("{}", tx_id);
        // Should be base58 encoded
        assert!(!display.is_empty());
        assert!(!display.contains("0x")); // Not hex
    }

    #[test]
    fn test_tx_id_to_bytes() {
        let sig = [42u8; 64];
        let tx_id = TransactionId::solana(sig);
        let bytes = tx_id.to_bytes();
        assert_eq!(bytes.len(), 64);
        assert_eq!(bytes, sig.to_vec());
    }

    #[test]
    fn test_solana_signature_json_roundtrip() {
        let original = [42u8; 64];
        let sig = SolanaSignature::new(original);
        let json = serde_json::to_string(&sig).unwrap();
        let deserialized: SolanaSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, deserialized);
    }

    #[test]
    fn test_transaction_id_json_roundtrip() {
        let original = [42u8; 64];
        let tx_id = TransactionId::solana(original);
        let json = serde_json::to_string(&tx_id).unwrap();
        let deserialized: TransactionId = serde_json::from_str(&json).unwrap();
        assert_eq!(tx_id, deserialized);
    }
}
