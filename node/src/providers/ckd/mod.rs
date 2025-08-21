use borsh::{BorshDeserialize, BorshSerialize};

use crate::{ckd_request::CKDId, primitives::MpcTaskId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum CKDTaskId {
    Ckd { id: CKDId },
}

impl From<CKDTaskId> for MpcTaskId {
    fn from(value: CKDTaskId) -> Self {
        MpcTaskId::CKDTaskId(value)
    }
}
