use crate::{
    network::view::primitives::{
        measured_network_link::{InferLinkStatus, LinkObservation, LinkStatus, RecentObservations},
        network_view::NetworkView,
    },
    primitives::ParticipantId,
};

pub struct NetworkBlockLatency(
    NetworkView<ParticipantId, MovingAverageBlockHeightLatency, BlockHeightLatency>,
);

/// todo: not sure about all these derives
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, derive_more::Deref, Debug)]
pub struct BlockHeightLatency(u64);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, derive_more::Deref, Debug)]
pub struct MovingAverageBlockHeightLatency(u64);

impl BlockHeightLatency {
    pub const fn new(blocks: u64) -> Self {
        Self(blocks)
    }
}

/// Trailing average over the latest present obvservations.
impl InferLinkStatus<BlockHeightLatency> for BlockHeightLatency {
    fn infer_link_status(obs: &RecentObservations<BlockHeightLatency>) -> LinkStatus<Self> {
        match obs.newest() {
            None => LinkStatus::Unknown,
            Some(LinkObservation::Absent) => LinkStatus::Absent,
            Some(LinkObservation::Present(first)) => {
                let mut summed = helper::SummedLatencies::new(*first);
                for latency in obs
                    .newest_first()
                    .skip(1)
                    .map_while(LinkObservation::present)
                {
                    summed.add(*latency);
                }
                LinkStatus::Present(summed.average_latency())
            }
        }
    }
}

mod helper {
    use crate::network::view::network_link_latency::BlockHeightLatency;

    pub(crate) struct SummedLatencies {
        count: u128,
        sum: u128,
    }

    impl SummedLatencies {
        pub(super) fn new(init_latency: BlockHeightLatency) -> Self {
            Self {
                count: 1,
                sum: u128::from(*init_latency),
            }
        }

        pub(super) fn add(&mut self, latency: BlockHeightLatency) {
            self.count = self.count.saturating_add(1);
            self.sum = self.sum.saturating_add(u128::from(*latency));
        }
        pub(super) fn average_latency(&self) -> BlockHeightLatency {
            let avg = self.sum.checked_div(self.count).unwrap_or(0);
            BlockHeightLatency(u64::try_from(avg).unwrap_or(u64::MAX))
        }
    }
}

// todo tests
