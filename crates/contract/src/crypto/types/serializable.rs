//! Module that adds implementation of [`BorshSerialize`] and [`BorshDeserialize`] for
//! [`super::PublicKeyExtended`].

use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek::EdwardsPoint;
#[cfg(any(test, feature = "test-utils"))]
use k256::elliptic_curve::Group as _;
use k256::elliptic_curve::{group::GroupEncoding, subtle::CtOption};
use serde::{Deserialize, Serialize};

#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(::near_sdk::schemars::JsonSchema),
    derive(::borsh::BorshSchema)
)]
#[derive(
    Debug,
    PartialEq,
    Serialize,
    Deserialize,
    Eq,
    Clone,
    Copy,
    derive_more::From,
    derive_more::AsRef,
    derive_more::Deref,
)]
pub struct SerializableEdwardsPoint(
    #[cfg_attr(
        all(feature = "abi", not(target_arch = "wasm32")),
        schemars(with = "[u8; 32]"),
        borsh(schema(with_funcs(
            declaration = "<[u8; 32] as ::borsh::BorshSchema>::declaration",
            definitions = "<[u8; 32] as ::borsh::BorshSchema>::add_definitions_recursively"
        ),))
    )]
    EdwardsPoint,
);

impl GroupEncoding for SerializableEdwardsPoint {
    type Repr = [u8; 32];

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        EdwardsPoint::from_bytes(bytes).map(Into::into)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        self.compress().to_bytes()
    }
}

impl BorshSerialize for SerializableEdwardsPoint {
    fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let bytes = self.0.to_bytes();
        BorshSerialize::serialize(&bytes, writer)
    }
}

impl BorshDeserialize for SerializableEdwardsPoint {
    fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
        let bytes: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;

        SerializableEdwardsPoint::from_bytes(&bytes)
            .into_option()
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "The provided bytes is not a valid edwards point.",
            ))
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl SerializableEdwardsPoint {
    pub fn random(rng: impl rand::RngCore) -> Self {
        Self(EdwardsPoint::random(rng))
    }
}
