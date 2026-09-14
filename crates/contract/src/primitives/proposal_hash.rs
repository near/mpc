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
//! New encodings (e.g. JSON) join as further strategy types.

use borsh::BorshSerialize;

pub(crate) use mpc_primitives::hash::{PROPOSAL_HASH_BYTES, ProposalHash};

pub(crate) trait SerializeProposal<T> {
    fn serialize(value: &T) -> Vec<u8>;
}

pub(crate) trait HashProposal {
    fn hash(bytes: &[u8]) -> ProposalHash;
}

pub(crate) struct Borsh;

impl<T: BorshSerialize> SerializeProposal<T> for Borsh {
    fn serialize(value: &T) -> Vec<u8> {
        borsh::to_vec(value).expect("borsh serialization must succeed")
    }
}

pub(crate) struct Sha256;

impl HashProposal for Sha256 {
    fn hash(bytes: &[u8]) -> ProposalHash {
        ProposalHash::new(near_sdk::env::sha256_array(bytes))
    }
}

pub(crate) struct Identity;

impl<T: AsRef<[u8; PROPOSAL_HASH_BYTES]>> SerializeProposal<T> for Identity {
    fn serialize(value: &T) -> Vec<u8> {
        value.as_ref().to_vec()
    }
}

impl HashProposal for Identity {
    fn hash(bytes: &[u8]) -> ProposalHash {
        ProposalHash::new(
            bytes
                .try_into()
                .unwrap_or_else(|_| panic!("identity digest must be {PROPOSAL_HASH_BYTES} bytes")),
        )
    }
}

pub(crate) trait ToProposalHash: Sized {
    type Serializer: SerializeProposal<Self>;
    type Hasher: HashProposal;

    fn to_proposal_hash(&self) -> ProposalHash {
        Self::Hasher::hash(&Self::Serializer::serialize(self))
    }
}

#[cfg(test)]
mod tests {
    use super::{Borsh, Identity, PROPOSAL_HASH_BYTES, Sha256, ToProposalHash};
    use borsh::BorshSerialize;

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
