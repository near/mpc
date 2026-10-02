use crate::BlockHeight;

/// A value read from a contract together with the height it was observed at.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedState<T> {
    pub observed_at: BlockHeight,
    pub value: T,
}

pub type SerializedObservation = ObservedState<Vec<u8>>;
