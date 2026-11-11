use borsh::{BorshDeserialize, BorshSerialize};
use near_block_primitives::BlockHeight;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use super::{
    ExtractedValue, ForeignChainRpcRequest, ForeignTxVerificationOutcome, Hash256, YieldId,
};
use crate::types::SignatureResponse;
use crate::types::primitives::DomainId;

// Pending requests are stored in the contract. We need to cap the size of a request.
pub const MAX_EXTRACTORS_PER_REQUEST: usize = 32;

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
/// Serialized as a `u8` discriminant via `serde_repr` and `#[borsh(use_discriminant = true)]`.
/// The [`JsonSchema`](schemars::JsonSchema) impl below delegates to `u8` because schemars doesn't
/// understand `serde_repr`.
/// The schema and serialization need to be kept in sync so that our ABI snapshot test captures
/// breaking changes.
#[non_exhaustive]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum ForeignTxPayloadVersion {
    V1 = 1,
}

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
impl schemars::JsonSchema for ForeignTxPayloadVersion {
    fn schema_name() -> String {
        u8::schema_name()
    }

    fn is_referenceable() -> bool {
        false
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        u8::json_schema(generator)
    }
}

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
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct VerifyForeignTransactionRequestArgs {
    pub request: ForeignChainRpcRequest,
    pub domain_id: DomainId,
    pub payload_version: ForeignTxPayloadVersion,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_payload_hash: Option<Hash256>,
}

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
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct VerifyForeignTransactionRequest {
    pub request: ForeignChainRpcRequest,
    pub domain_id: DomainId,
    pub payload_version: ForeignTxPayloadVersion,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_payload_hash: Option<Hash256>,
}

/// Requests a [`ForeignTxSignPayload::V2`](super::ForeignTxSignPayload::V2) signature. Unlike V1 there is no
/// expected payload hash: the V2 payload covers the [`YieldId`] and
/// [`BlockHeight`] the contract assigns to the request, which the caller
/// only learns from the response.
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
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct VerifyForeignTransactionRequestV2 {
    pub request: ForeignChainRpcRequest,
    pub domain_id: DomainId,
    /// One value per extractor, in extractor order. A
    /// [`ForeignTxVerificationOutcome::Verified`] answer means the extracted
    /// values equal these.
    pub expected_values: Vec<ExtractedValue>,
}

impl VerifyForeignTransactionRequestV2 {
    /// SHA-256 of the Borsh encoded [`Self::expected_values`], as
    /// [`ForeignTxSignPayloadV2::expected_values_hash`](super::ForeignTxSignPayloadV2::expected_values_hash) carries it.
    pub fn expected_values_hash(&self) -> std::io::Result<Hash256> {
        extracted_values_hash(&self.expected_values)
    }
}

/// SHA-256 of the Borsh encoded `values`, the same hash
/// [`VerifyForeignTransactionRequestV2::expected_values_hash`] gives for equal values.
pub fn extracted_values_hash(values: &[ExtractedValue]) -> std::io::Result<Hash256> {
    let mut hasher = sha2::Sha256::new();
    borsh::BorshSerialize::serialize(values, &mut hasher)?;
    Ok(Hash256(hasher.finalize().into()))
}

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
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct VerifyForeignTransactionResponse {
    pub payload_hash: Hash256,
    pub signature: SignatureResponse,
}

/// Response to a [`VerifyForeignTransactionRequestV2`].
///
/// [`Self::payload_hash`] is the hash of the [`ForeignTxSignPayload::V2`](super::ForeignTxSignPayload::V2)
/// built from the request, the hash of its expected values,
/// [`Self::request_block_height`], [`Self::yield_id`] and [`Self::outcome`].
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
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct VerifyForeignTransactionResponseV2 {
    pub payload_hash: Hash256,
    pub signature: SignatureResponse,
    pub request_block_height: BlockHeight,
    pub yield_id: YieldId,
    pub outcome: ForeignTxVerificationOutcome,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;
    use std::assert_matches;

    #[test]
    fn extracted_values_hash__should_equal_the_expected_values_hash_of_the_same_values() {
        // Given
        let values = vec![ExtractedValue::EvmExtractedValue(
            crate::types::EvmExtractedValue::BlockHash(Hash256([0xef; 32])),
        )];
        let request = VerifyForeignTransactionRequestV2 {
            request: ForeignChainRpcRequest::Ethereum(crate::types::EvmRpcRequest {
                tx_id: crate::types::EvmTxId([0xab; 32]),
                extractors: [crate::types::EvmExtractor::BlockHash].into(),
                finality: crate::types::EvmFinality::Finalized,
            }),
            domain_id: DomainId(0),
            expected_values: values.clone(),
        };

        // When
        let hash = extracted_values_hash(&values).unwrap();

        // Then
        assert_eq!(hash, request.expected_values_hash().unwrap());
    }

    #[rstest]
    #[case(ForeignTxPayloadVersion::V1, 1)]
    fn foreign_tx_payload_version__serializes_as_u8(
        #[case] version: ForeignTxPayloadVersion,
        #[case] expected: u8,
    ) {
        assert_eq!(
            serde_json::to_value(version).unwrap(),
            serde_json::json!(expected)
        );
        assert_eq!(borsh::to_vec(&version).unwrap(), vec![expected]);
    }

    #[rstest]
    #[case(1, ForeignTxPayloadVersion::V1)]
    fn foreign_tx_payload_version__deserializes_from_u8(
        #[case] input: u8,
        #[case] expected: ForeignTxPayloadVersion,
    ) {
        let json: ForeignTxPayloadVersion =
            serde_json::from_value(serde_json::json!(input)).unwrap();
        let borsh: ForeignTxPayloadVersion = borsh::from_slice(&[input]).unwrap();
        assert_eq!(json, expected);
        assert_eq!(borsh, expected);
    }

    #[rstest]
    #[case(0)]
    #[case(2)]
    fn foreign_tx_payload_version__rejects_unknown_version(#[case] input: u8) {
        serde_json::from_value::<ForeignTxPayloadVersion>(serde_json::json!(input)).unwrap_err();
        borsh::from_slice::<ForeignTxPayloadVersion>(&[input]).unwrap_err();
    }

    fn hex_bytes(len: usize) -> String {
        "bb".repeat(len)
    }

    fn verify_foreign_transaction_args_json(
        mut request: serde_json::Value,
        extractor: serde_json::Value,
        extractor_count: usize,
    ) -> serde_json::Value {
        let fields = request
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap();
        fields["extractors"] = vec![extractor; extractor_count].into();
        json!({
            "request": request,
            "domain_id": 0,
            "payload_version": 1,
        })
    }

    #[rstest]
    #[case::evm(
        json!({"Ethereum": {"tx_id": hex_bytes(32), "finality": "Finalized"}}),
        json!("BlockHash")
    )]
    #[case::svm(
        json!({"Solana": {"tx_id": hex_bytes(64), "finality": "Finalized"}}),
        json!({"AccountState": {"pubkey": hex_bytes(32)}})
    )]
    #[case::bitcoin(
        json!({"Bitcoin": {"tx_id": hex_bytes(32), "confirmations": 6}}),
        json!("BlockHash")
    )]
    #[case::starknet(
        json!({"Starknet": {"tx_id": hex_bytes(32), "finality": "AcceptedOnL1"}}),
        json!("BlockHash")
    )]
    #[case::ton(
        json!({
            "Ton": {
                "tx_id": hex_bytes(32),
                "account": {"workchain": 0, "hash": hex_bytes(32)},
                "finality": "MasterchainIncluded",
            }
        }),
        json!({"Log": {"message_index": 0}})
    )]
    #[case::aptos(
        json!({"Aptos": {"tx_id": hex_bytes(32), "finality": "Committed"}}),
        json!({"Event": {"event_index": 0}})
    )]
    #[case::sui(
        json!({"Sui": {"tx_id": hex_bytes(32), "finality": "Checkpointed"}}),
        json!({"Event": {"event_index": 0}})
    )]
    fn verify_foreign_transaction_request_args__should_bound_extractors_at_the_cap(
        #[case] request: serde_json::Value,
        #[case] extractor: serde_json::Value,
    ) {
        // Given
        let at_cap = verify_foreign_transaction_args_json(
            request.clone(),
            extractor.clone(),
            MAX_EXTRACTORS_PER_REQUEST,
        );
        let above_cap = verify_foreign_transaction_args_json(
            request,
            extractor,
            MAX_EXTRACTORS_PER_REQUEST + 1,
        );

        // When
        let accepted =
            serde_json::from_value::<VerifyForeignTransactionRequestArgs>(at_cap.clone()).unwrap();
        let rejected = serde_json::from_value::<VerifyForeignTransactionRequestArgs>(above_cap);

        // Then
        assert_eq!(
            serde_json::to_value(accepted.request).unwrap(),
            at_cap["request"]
        );
        assert_matches!(rejected, Err(_));
    }
}
