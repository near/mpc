use std::num::NonZeroUsize;

use near_block_primitives::BlockCount;
use near_time::Duration;

/// Lags kept per link direction for the mean lag. One arrives per received report, so at one per
/// [`CONNECTED_PEERS_BROADCAST_INTERVAL`](crate::network::constants::CONNECTED_PEERS_BROADCAST_INTERVAL)
/// the mean spans a minute.
pub(super) const RECENT_DELAY_SAMPLES: NonZeroUsize =
    NonZeroUsize::new(60).expect("literal must be non-zero");
/// Finished up periods kept per link, for its disconnect rate.
pub(super) const RECENT_UPTIMES: NonZeroUsize =
    NonZeroUsize::new(16).expect("literal must be non-zero");
// todo: calibrate the two round trip lags on localnet with injected delay (tc netem): how much of
// a delay shows up as lag, how the path-difference error smears it, and how fast the mean over
// `RECENT_DELAY_SAMPLES` reacts
/// Round trip lag above which a connection counts as broken.
pub(super) const MAX_ROUND_TRIP_LAG: BlockCount = BlockCount::new(40);
/// Round trip lag above which a connection is not used for `HalfMinute` computations.
pub(super) const AT_RISK_ROUND_TRIP_LAG: BlockCount = BlockCount::new(20);
// todo: calibrate the two computation lengths and the required chance. If the required chance is
// raised, an old bad period can count against a link for hours: then forget everything before a
// disconnect-free hour.
/// How long a `Seconds` computation is taken to run, for the chance that a link stays up
/// throughout.
pub(super) const SECONDS_COMPUTATION_LENGTH: Duration = Duration::seconds(5);
/// The same for a `HalfMinute` computation.
pub(super) const HALF_MINUTE_COMPUTATION_LENGTH: Duration = Duration::seconds(30);
/// A link is used for a computation only if its chance to stay up throughout is at least this.
pub(super) const REQUIRED_CHANCE_TO_STAY_UP: f64 = 0.8;
