use std::collections::BTreeMap;

use near_block_primitives::BlockHeight;
use near_mpc_bounded_collections::{NonEmptyBTreeMap, NonEmptyBTreeSet};

use crate::{network::view::view_manager::NetworkViewUpdateError, primitives::ParticipantId};

/// Every participant's indexer height as that participant itself last reported it: its own entry
/// in its [`ConnectedPeersInfo`](crate::primitives::ConnectedPeersInfo), or its legacy
/// `IndexerHeight` message.
pub struct FirstHandIndexerHeights {
    heights: NonEmptyBTreeMap<ParticipantId, FirstHandHeight>,
}

/// `Unknown` until the participant's first message, then whatever it last reported.
/// The wire format encodes `Unknown` as `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstHandHeight {
    Unknown,
    Known(BlockHeight),
}

impl From<u64> for FirstHandHeight {
    fn from(wire: u64) -> Self {
        parse_height(wire).map_or(Self::Unknown, Self::Known)
    }
}

impl From<FirstHandHeight> for u64 {
    fn from(height: FirstHandHeight) -> Self {
        match height {
            FirstHandHeight::Unknown => 0,
            FirstHandHeight::Known(height) => height.into(),
        }
    }
}

pub(super) fn parse_height(wire: u64) -> Option<BlockHeight> {
    (wire != 0).then(|| BlockHeight::from(wire))
}

impl FirstHandIndexerHeights {
    pub fn new(participants: &NonEmptyBTreeSet<ParticipantId>) -> Self {
        Self {
            heights: participants
                .iter()
                .map(|&p| (p, FirstHandHeight::Unknown))
                .collect::<BTreeMap<_, _>>()
                .try_into()
                .expect("a non-empty participant set yields a non-empty map"),
        }
    }

    /// Records what `participant` reported for itself. Errors if it is not a participant, so the
    /// set never grows; `Unknown` leaves the record untouched.
    pub fn record(
        &mut self,
        participant: ParticipantId,
        height: u64,
    ) -> Result<(), NetworkViewUpdateError> {
        if !self.heights.contains_key(&participant) {
            return Err(NetworkViewUpdateError::UnknownParticipant(participant));
        }
        let FirstHandHeight::Known(height) = FirstHandHeight::from(height) else {
            return Ok(());
        };
        let previous = self
            .heights
            .insert(participant, FirstHandHeight::Known(height));
        if let Some(FirstHandHeight::Known(previous)) = previous
            && height < previous
        {
            tracing::warn!(
                %participant,
                %previous,
                %height,
                "indexer height moved backwards. This is unexpected, because the indexer \
                 processes blocks in order."
            );
        }
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ParticipantId, &FirstHandHeight)> {
        self.heights.iter()
    }

    pub fn snapshot(&self) -> BTreeMap<ParticipantId, FirstHandHeight> {
        self.heights.clone().into()
    }
}
