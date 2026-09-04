//! Proposal identity: any type can serve as a proposal by implementing
//! [`ToProposalHash`], picking a [`SerializeProposal`] encoding and a
//! [`HashProposal`] digest for its [`ProposalHash`]:
//!
//! ```ignore
//! impl ToProposalHash for MyProposal {
//!     type Serializer = Borsh;
//!     type Hasher = Sha256;
//! }
//! ```
//!
//! New encodings (e.g. JSON) join as further strategy types.

use borsh::BorshSerialize;

pub(crate) use mpc_primitives::hash::ProposalHash;

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

pub(crate) trait ToProposalHash: Sized {
    type Serializer: SerializeProposal<Self>;
    type Hasher: HashProposal;

    fn to_proposal_hash(&self) -> ProposalHash {
        Self::Hasher::hash(&Self::Serializer::serialize(self))
    }
}

#[cfg(test)]
mod tests {
    use super::{Borsh, Sha256, ToProposalHash};
    use borsh::BorshSerialize;

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
}
