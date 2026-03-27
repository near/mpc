pub use ethereum_types;

use crate::hash::hash_newtype;

pub mod inspector;

hash_newtype!(AbstractBlockHash);
hash_newtype!(AbstractTransactionHash);
