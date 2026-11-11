use std::collections::BTreeMap;

use near_block_primitives::BlockHeight;
use near_mpc_bounded_collections::{NonEmptyBTreeMap, NonEmptyBTreeSet};

use crate::network::view::graph::UnknownNodeError;

/// Every participant's indexer height as that participant itself last reported it: its own entry
/// in its [`ConnectedPeersInfo`](crate::primitives::ConnectedPeersInfo), or its legacy
/// `IndexerHeight` message.
pub struct FirstHandIndexerHeights<N> {
    heights: NonEmptyBTreeMap<N, ReportedIndexerHeight>,
}

impl<N> FirstHandIndexerHeights<N>
where
    N: Ord + Clone,
{
    pub fn new(participants: &NonEmptyBTreeSet<N>) -> Self {
        Self {
            heights: participants
                .iter()
                .map(|p| (p.clone(), ReportedIndexerHeight::Unknown))
                .collect::<BTreeMap<_, _>>()
                .try_into()
                .expect("a non-empty participant set yields a non-empty map"),
        }
    }

    pub fn set(
        &mut self,
        participant: N,
        height: ReportedIndexerHeight,
    ) -> Result<(), UnknownNodeError<N>>
    where
        N: std::fmt::Display,
    {
        let Some(&previous) = self.heights.get(&participant) else {
            return Err(UnknownNodeError(participant));
        };
        if height < previous {
            tracing::warn!(
                %participant,
                ?previous,
                ?height,
                "indexer height moved backwards. This is unexpected, because the indexer \
                 processes blocks in order."
            );
        }
        self.heights.insert(participant, height);
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&N, &ReportedIndexerHeight)> {
        self.heights.iter()
    }

    // pub fn snapshot(&self) -> BTreeMap<ParticipantId, ReportedIndexerHeight> {
    //     self.heights.clone().into()
    // }
}

// todo: place these in primitives or somewhere
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReportedIndexerHeight {
    Unknown,
    Known(BlockHeight),
}

impl ReportedIndexerHeight {
    /// Decodes the wire format, where `0` means `Unknown`.
    pub fn from_wire(wire: u64) -> Self {
        match wire {
            0 => Self::Unknown,
            wire => Self::Known(wire.into()),
        }
    }

    /// Encodes to the wire format, where `0` means `Unknown`.
    pub fn to_wire(self) -> u64 {
        match self {
            Self::Unknown => 0,
            Self::Known(height) => height.into(),
        }
    }
}
