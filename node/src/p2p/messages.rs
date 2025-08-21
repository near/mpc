use borsh::{BorshDeserialize, BorshSerialize};

use crate::primitives::{IndexerHeightMessage, MpcMessage};

#[derive(BorshSerialize, BorshDeserialize)]
pub(crate) enum Packet {
    Ping,
    MpcMessage(MpcMessage),
    IndexerHeight(IndexerHeightMessage),
}
