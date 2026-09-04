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
        let hash: [u8; PROPOSAL_HASH_BYTES] = near_sdk::env::sha256(bytes)
            .try_into()
            .expect("sha256 digest length matches PROPOSAL_HASH_BYTES");
        ProposalHash::new(hash)
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

    impl ToProposalHash for u64 {
        type Serializer = Borsh;
        type Hasher = Sha256;
    }

    #[test]
    #[expect(non_snake_case)]
    fn to_proposal_hash__should_be_the_digest_of_the_canonical_encoding() {
        assert_eq!(
            42u64.to_proposal_hash(),
            "ed049108bc18f2c64369e8d0ea42850bdd1a7d1dd340cfde716315579702a76c"
                .parse()
                .unwrap()
        );
    }
}
