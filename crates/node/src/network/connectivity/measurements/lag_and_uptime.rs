use std::collections::VecDeque;

use near_block_primitives::BlockCount;
use near_time::{Duration, Instant};
use time::ext::InstantExt as _;

use crate::{
    network::connectivity::{
        health::{
            CheckComputationSupport, ComputationSupported, InferConnection, InferredConnection,
            LinkStatusChange, ReportLinkStatus, UpdateLinkStatus,
        },
        measurements::constants::{
            AT_RISK_ROUND_TRIP_LAG, HALF_MINUTE_COMPUTATION_LENGTH, MAX_ROUND_TRIP_LAG,
            RECENT_DELAY_SAMPLES, RECENT_UPTIMES, REQUIRED_CHANCE_TO_STAY_UP,
            SECONDS_COMPUTATION_LENGTH,
        },
        reports::IndexerHeightLag,
    },
    providers::participant_selection::ComputationDuration,
};

/// What has been measured about one directed link: how far the heights it carries lag behind, and
/// when it was up.
#[derive(Default)]
pub struct LagsAndUptimeHistory {
    lags: BlockHeightLags,
    uptime_history: UptimeHistory,
}

impl UpdateLinkStatus<IndexerHeightLag> for LagsAndUptimeHistory {
    fn update_with_observation(
        &mut self,
        observation: IndexerHeightLag,
        at: Instant,
    ) -> LinkStatusChange<LinkLagAndUptime> {
        let previous = self.link_status();
        match observation {
            IndexerHeightLag::Present(lag) => {
                self.uptime_history.record_up(at);
                self.lags.record(lag);
            }
            IndexerHeightLag::Absent => {
                self.uptime_history.record_down(at);
                self.lags.clear();
            }
        }
        let status = self.link_status();
        if status == previous {
            LinkStatusChange::Unchanged
        } else {
            LinkStatusChange::Changed(status)
        }
    }
}

impl ReportLinkStatus for LagsAndUptimeHistory {
    type LinkStatus = LinkLagAndUptime;

    fn link_status(&self) -> LinkLagAndUptime {
        match self.uptime_history.summary() {
            Some(uptime) => LinkLagAndUptime::Up(UpLink {
                mean_lag: self.lags.mean(),
                uptime,
            }),
            None => LinkLagAndUptime::Down,
        }
    }
}

/// The newest lags of a link, at most [`RECENT_DELAY_SAMPLES`].
#[derive(Default)]
struct BlockHeightLags {
    lags: VecDeque<BlockCount>,
}

impl BlockHeightLags {
    fn record(&mut self, lag: BlockCount) {
        if self.lags.len() == RECENT_DELAY_SAMPLES.get() {
            self.lags.pop_front();
        }
        self.lags.push_back(lag);
    }

    fn clear(&mut self) {
        self.lags.clear();
    }

    /// Zero while there are no lags.
    fn mean(&self) -> BlockCount {
        let sum: u128 = self
            .lags
            .iter()
            .map(|lag| u128::from(u64::from(*lag)))
            .sum();
        let count = u128::try_from(self.lags.len()).unwrap_or(u128::MAX);
        let mean = sum.checked_div(count).unwrap_or(0);
        BlockCount::new(u64::try_from(mean).unwrap_or(u64::MAX))
    }
}

/// When a link was up: its last [`RECENT_UPTIMES`] finished up periods and the running one.
#[derive(Default)]
struct UptimeHistory {
    /// How long each finished up period lasted. Each one ended in a disconnect.
    finished_uptimes: VecDeque<Duration>,
    /// `None` while the link is down.
    up_since: Option<Instant>,
}

impl UptimeHistory {
    fn record_up(&mut self, at: Instant) {
        self.up_since.get_or_insert(at);
    }

    fn record_down(&mut self, at: Instant) {
        let Some(up_since) = self.up_since.take() else {
            return;
        };
        if self.finished_uptimes.len() == RECENT_UPTIMES.get() {
            self.finished_uptimes.pop_front();
        }
        self.finished_uptimes
            .push_back(at.signed_duration_since(up_since));
    }

    /// `None` while the link is down.
    fn summary(&self) -> Option<UptimeSummary> {
        let up_since = self.up_since?;
        Some(UptimeSummary {
            up_since,
            disconnects: u32::try_from(self.finished_uptimes.len()).unwrap_or(u32::MAX),
            finished_uptime: self.finished_uptimes.iter().sum(),
        })
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum LinkLagAndUptime {
    Down,
    Up(UpLink),
}

impl InferConnection for LinkLagAndUptime {
    type ConnectionStatus = ConnectionLagAndUptime;

    fn infer_connection(
        a: Option<Self>,
        b: Option<Self>,
    ) -> InferredConnection<ConnectionLagAndUptime> {
        let (Some(Self::Up(a)), Some(Self::Up(b))) = (a, b) else {
            return InferredConnection::NotEstablished;
        };
        match ConnectionLagAndUptime::new(a, b) {
            Some(connection) => InferredConnection::Established(connection),
            None => InferredConnection::NotEstablished,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub struct UpLink {
    mean_lag: BlockCount,
    uptime: UptimeSummary,
}

#[derive(Clone, PartialEq)]
pub struct ConnectionLagAndUptime {
    round_trip_lag: RoundTripLag,
    /// One per link, each judged on its own. Sorted, so that the status does not depend on which
    /// link changed last.
    uptimes: [UptimeSummary; 2],
}

impl ConnectionLagAndUptime {
    /// `None` if the round trip lag of the two links is too high for a connection.
    fn new(a: UpLink, b: UpLink) -> Option<Self> {
        let round_trip_lag = RoundTripLag::new(a.mean_lag, b.mean_lag)?;
        let mut uptimes = [a.uptime, b.uptime];
        uptimes.sort();
        Some(Self {
            round_trip_lag,
            uptimes,
        })
    }
}

impl CheckComputationSupport for ConnectionLagAndUptime {
    fn connection_supports(
        &self,
        duration: ComputationDuration,
        now: Instant,
    ) -> ComputationSupported {
        let length = match duration {
            ComputationDuration::Any => return ComputationSupported::Yes,
            ComputationDuration::Seconds => SECONDS_COMPUTATION_LENGTH,
            ComputationDuration::HalfMinute if self.round_trip_lag == RoundTripLag::AtRisk => {
                return ComputationSupported::No;
            }
            ComputationDuration::HalfMinute => HALF_MINUTE_COMPUTATION_LENGTH,
        };
        let stays_up = |uptime: &UptimeSummary| {
            uptime.disconnect_rate(now).chance_to_stay_up(length) >= REQUIRED_CHANCE_TO_STAY_UP
        };
        if self.uptimes.iter().all(stays_up) {
            ComputationSupported::Yes
        } else {
            ComputationSupported::No
        }
    }
}

/// The mean lags of the two links of a connection, added up.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RoundTripLag {
    Good,
    /// Above [`AT_RISK_ROUND_TRIP_LAG`]: the connection may be about to break.
    AtRisk,
}

impl RoundTripLag {
    /// `None` above [`MAX_ROUND_TRIP_LAG`]: the connection counts as broken.
    fn new(a: BlockCount, b: BlockCount) -> Option<Self> {
        let round_trip = BlockCount::new(u64::from(a).saturating_add(u64::from(b)));
        if round_trip > MAX_ROUND_TRIP_LAG {
            None
        } else if round_trip > AT_RISK_ROUND_TRIP_LAG {
            Some(Self::AtRisk)
        } else {
            Some(Self::Good)
        }
    }
}

/// What a link's [`UptimeHistory`] adds up to while the link is up.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UptimeSummary {
    /// When the running up period started.
    up_since: Instant,
    /// Finished up periods in the history. Each one ended in a disconnect.
    disconnects: u32,
    /// The total length of those finished up periods.
    finished_uptime: Duration,
}

impl UptimeSummary {
    /// Zero for a link that was never seen to disconnect.
    fn disconnect_rate(&self, now: Instant) -> DisconnectRate {
        if self.disconnects == 0 {
            return DisconnectRate(0.0);
        }
        let uptime = self.finished_uptime + now.signed_duration_since(self.up_since);
        DisconnectRate(f64::from(self.disconnects) / uptime.as_seconds_f64())
    }
}

/// Disconnects per second of up time: the parameter of the exponential distribution assumed for
/// the time until a link's next disconnect.
struct DisconnectRate(f64);

impl DisconnectRate {
    /// `exp(-rate * length)`
    fn chance_to_stay_up(&self, length: Duration) -> f64 {
        (-self.0 * length.as_seconds_f64()).exp()
    }
}
