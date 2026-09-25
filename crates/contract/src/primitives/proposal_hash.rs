//! Proposal identity: any type can serve as a proposal by implementing
//! [`ToProposalHash`], picking a [`SerializeProposal`] encoding and a
//! [`HashProposal`] digest for its [`ProposalHash`]:
//!
//! ```ignore
//! impl ToProposalHash for MyProposal {
//!     type Serializer = Borsh;
//!     type Hasher = Sha256;
//! }
//!
//! // A proposal that already is a 32-byte digest identifies itself.
//! impl ToProposalHash for MyDigest {
//!     type Serializer = Identity;
//!     type Hasher = Identity;
//! }
//! ```
//!
//! Further encodings join as strategy types.

use borsh::BorshSerialize;
use near_sdk::serde::Serialize;

pub(crate) use mpc_primitives::hash::{PROPOSAL_HASH_BYTES, ProposalHash};

pub(crate) trait SerializeProposal<T> {
    type Output;

    fn serialize(value: &T) -> Self::Output;
}

pub(crate) trait HashProposal<B> {
    fn hash(bytes: B) -> ProposalHash;
}

pub(crate) struct Borsh;

impl<T: BorshSerialize> SerializeProposal<T> for Borsh {
    type Output = Vec<u8>;

    fn serialize(value: &T) -> Vec<u8> {
        borsh::to_vec(value).expect("borsh serialization must succeed")
    }
}

pub(crate) struct Json;

impl<T: Serialize> SerializeProposal<T> for Json {
    type Output = Vec<u8>;

    fn serialize(value: &T) -> Vec<u8> {
        serde_json::to_vec(value).expect("JSON serialization must succeed")
    }
}

pub(crate) struct Sha256;

impl<B: AsRef<[u8]>> HashProposal<B> for Sha256 {
    fn hash(bytes: B) -> ProposalHash {
        ProposalHash::new(near_sdk::env::sha256_array(bytes.as_ref()))
    }
}

pub(crate) struct Identity;

impl<T: AsRef<[u8; PROPOSAL_HASH_BYTES]>> SerializeProposal<T> for Identity {
    type Output = [u8; PROPOSAL_HASH_BYTES];

    fn serialize(value: &T) -> [u8; PROPOSAL_HASH_BYTES] {
        *value.as_ref()
    }
}

impl HashProposal<[u8; PROPOSAL_HASH_BYTES]> for Identity {
    fn hash(bytes: [u8; PROPOSAL_HASH_BYTES]) -> ProposalHash {
        ProposalHash::new(bytes)
    }
}

pub(crate) trait ToProposalHash: Sized {
    type Serializer: SerializeProposal<Self>;
    type Hasher: HashProposal<<Self::Serializer as SerializeProposal<Self>>::Output>;

    fn to_proposal_hash(&self) -> ProposalHash {
        Self::Hasher::hash(Self::Serializer::serialize(self))
    }
}

#[cfg(test)]
mod tests {
    use super::{Borsh, Identity, Json, PROPOSAL_HASH_BYTES, Sha256, ToProposalHash};
    use borsh::BorshSerialize;
    use near_sdk::serde::Serialize;

    struct TestDigest([u8; PROPOSAL_HASH_BYTES]);

    impl AsRef<[u8; PROPOSAL_HASH_BYTES]> for TestDigest {
        fn as_ref(&self) -> &[u8; PROPOSAL_HASH_BYTES] {
            &self.0
        }
    }

    impl ToProposalHash for TestDigest {
        type Serializer = Identity;
        type Hasher = Identity;
    }

    #[derive(BorshSerialize)]
    struct TestProposal(u64);

    impl ToProposalHash for TestProposal {
        type Serializer = Borsh;
        type Hasher = Sha256;
    }

    #[derive(Serialize)]
    #[serde(crate = "near_sdk::serde")]
    struct TestJsonProposal {
        value: u64,
    }

    impl ToProposalHash for TestJsonProposal {
        type Serializer = Json;
        type Hasher = Sha256;
    }

    #[test]
    #[expect(non_snake_case)]
    fn to_proposal_hash__should_be_sha256_of_json_bytes() {
        // Given
        let proposal = TestJsonProposal { value: 42 };

        // When
        let hash = proposal.to_proposal_hash();

        // Then: sha256 of `{"value":42}`
        assert_eq!(
            hash,
            "dc60e632a90329ccfd34fbe904d94704dbbb6669575185e26389854ff64139c3"
                .parse()
                .unwrap()
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn to_proposal_hash__should_be_sha256_of_borsh_bytes() {
        // Given
        let proposal = TestProposal(42);

        // When
        let hash = proposal.to_proposal_hash();

        // Then
        assert_eq!(
            hash,
            "ed049108bc18f2c64369e8d0ea42850bdd1a7d1dd340cfde716315579702a76c"
                .parse()
                .unwrap()
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn to_proposal_hash__should_pass_an_identity_digest_through_unhashed() {
        // Given
        let digest = TestDigest([0xAB; PROPOSAL_HASH_BYTES]);

        // When
        let hash = digest.to_proposal_hash();

        // Then
        assert_eq!(hash, [0xAB; PROPOSAL_HASH_BYTES].into());
    }
}
