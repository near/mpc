//! Reports the owned-triple gauges (`mpc_owned_num_triples_*`).
//!
//! There is one triple store per reconstruction threshold, and each store gets its own series
//! (labelled by threshold).

use crate::assets::DistributedAssetStorage;
use crate::metrics;
use serde::{Serialize, de::DeserializeOwned};
use std::sync::LazyLock;
use std::time::Duration;

pub const ASSET_METRICS_REPORTING_INTERVAL: Duration = Duration::from_millis(100);

/// One store's owned counts, see [`DistributedAssetStorage::owned_asset_counts`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnedAssetCounts {
    /// Owned assets not known to have an offline participant.
    pub available: usize,
    /// Owned assets whose participants are all confirmed alive.
    pub online: usize,
    /// Owned assets known to have an offline participant.
    pub offline: usize,
}

/// The three gauges an asset type is reported on.
pub struct OwnedAssetGauges {
    available: &'static LazyLock<prometheus::IntGaugeVec>,
    online: &'static LazyLock<prometheus::IntGaugeVec>,
    offline: &'static LazyLock<prometheus::IntGaugeVec>,
}

/// Triple gauges, labelled by reconstruction threshold.
pub static TRIPLE_GAUGES: OwnedAssetGauges = OwnedAssetGauges {
    available: &metrics::MPC_OWNED_NUM_TRIPLES_AVAILABLE,
    online: &metrics::MPC_OWNED_NUM_TRIPLES_ONLINE,
    offline: &metrics::MPC_OWNED_NUM_TRIPLES_WITH_OFFLINE_PARTICIPANT,
};

impl OwnedAssetGauges {
    fn reset(&self) {
        self.available.reset();
        self.online.reset();
        self.offline.reset();
    }
}

pub struct ClearOwnedAssetGaugesOnDrop;

impl Drop for ClearOwnedAssetGaugesOnDrop {
    fn drop(&mut self) {
        TRIPLE_GAUGES.reset();
    }
}

fn to_gauge_value(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

/// Sets the series `label` of `gauges` to `counts`.
pub fn set_owned_asset_gauges(
    gauges: &OwnedAssetGauges,
    label: &str,
    counts: OwnedAssetCounts,
) -> Result<(), prometheus::Error> {
    let label = [label];
    gauges
        .available
        .get_metric_with_label_values(&label)?
        .set(to_gauge_value(counts.available));
    gauges
        .online
        .get_metric_with_label_values(&label)?
        .set(to_gauge_value(counts.online));
    gauges
        .offline
        .get_metric_with_label_values(&label)?
        .set(to_gauge_value(counts.offline));
    Ok(())
}

/// Sets the series `label` of `gauges` from a fresh read of `store`.
pub fn report_store<T>(
    gauges: &OwnedAssetGauges,
    label: impl ToString,
    store: &DistributedAssetStorage<T>,
) -> anyhow::Result<(), prometheus::Error>
where
    T: Serialize + DeserializeOwned + Send + 'static,
{
    set_owned_asset_gauges(
        gauges,
        &label.to_string(),
        store
            .owned_asset_counts()
            .map_err(|e| prometheus::Error::Msg(e.to_string()))?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::test_utils::{TestContext, make_triple};
    use crate::db::DBCol;
    use crate::primitives::ParticipantId;
    use crate::providers::ecdsa::triple::PairedTriple;
    use serial_test::serial;
    use std::sync::{Arc, Mutex};

    fn counts(available: usize, online: usize, offline: usize) -> OwnedAssetCounts {
        OwnedAssetCounts {
            available,
            online,
            offline,
        }
    }

    fn series_count(gauges: &OwnedAssetGauges) -> usize {
        [gauges.available, gauges.online, gauges.offline]
            .into_iter()
            .map(|gauge| metrics::series_count(&**gauge))
            .sum()
    }

    fn read(
        gauges: &OwnedAssetGauges,
        label: &str,
    ) -> anyhow::Result<OwnedAssetCounts, prometheus::Error> {
        let label = [label];
        let available = gauges
            .available
            .get_metric_with_label_values(&label)?
            .get()
            .try_into()
            .map_err(|e| prometheus::Error::Msg(format!("{e}")))?;
        let online = gauges
            .online
            .get_metric_with_label_values(&label)?
            .get()
            .try_into()
            .map_err(|e| prometheus::Error::Msg(format!("{e}")))?;
        let offline = gauges
            .offline
            .get_metric_with_label_values(&label)?
            .get()
            .try_into()
            .map_err(|e| prometheus::Error::Msg(format!("{e}")))?;
        Ok(counts(available, online, offline))
    }

    #[test]
    #[serial(asset_gauges)]
    #[expect(non_snake_case)]
    fn set_owned_asset_gauges__should_keep_series_apart_by_label() {
        // Given, When
        set_owned_asset_gauges(&TRIPLE_GAUGES, "test-t2", counts(10, 7, 2)).unwrap();
        set_owned_asset_gauges(&TRIPLE_GAUGES, "test-t3", counts(5, 1, 3)).unwrap();

        // Then
        assert_eq!(read(&TRIPLE_GAUGES, "test-t2").unwrap(), counts(10, 7, 2));
        assert_eq!(read(&TRIPLE_GAUGES, "test-t3").unwrap(), counts(5, 1, 3));
    }

    #[test]
    #[serial(asset_gauges)]
    #[expect(non_snake_case)]
    fn set_owned_asset_gauges__should_overwrite_previous_values() {
        // Given
        set_owned_asset_gauges(&TRIPLE_GAUGES, "test-overwrite", counts(42, 40, 2)).unwrap();

        // When
        set_owned_asset_gauges(&TRIPLE_GAUGES, "test-overwrite", counts(0, 0, 0)).unwrap();

        // Then
        assert_eq!(
            read(&TRIPLE_GAUGES, "test-overwrite").unwrap(),
            counts(0, 0, 0)
        );
    }
    #[tokio::test]
    #[serial(asset_gauges)]
    #[expect(non_snake_case)]
    async fn report_store__should_follow_the_store_after_take_owned() {
        // Given
        let participants: Vec<ParticipantId> = (0..3).map(ParticipantId::from_raw).collect();
        let ctx = TestContext::new(participants[0], Arc::new(Mutex::new(participants.clone())));
        let store = ctx.new_store::<PairedTriple>(DBCol::TripleV2, Vec::new());
        for _ in 0..2 {
            store
                .add_owned(
                    store.generate_and_reserve_id().unwrap(),
                    make_triple(&participants),
                )
                .unwrap();
        }
        report_store(&TRIPLE_GAUGES, "test-take-owned", &store).unwrap();
        assert_eq!(
            read(&TRIPLE_GAUGES, "test-take-owned").unwrap().available,
            2
        );

        // When
        store.take_owned().await.unwrap();
        report_store(&TRIPLE_GAUGES, "test-take-owned", &store).unwrap();

        // Then
        assert_eq!(
            read(&TRIPLE_GAUGES, "test-take-owned").unwrap().available,
            1
        );
    }
    #[test]
    #[serial(asset_gauges)]
    #[expect(non_snake_case)]
    fn clear_owned_asset_gauges_on_drop__should_remove_every_series() {
        // Given: a reported store, and the guard the reporter task holds.
        let guard = ClearOwnedAssetGaugesOnDrop;
        set_owned_asset_gauges(&TRIPLE_GAUGES, "test-cleared", counts(3, 2, 1)).unwrap();
        assert_eq!(series_count(&TRIPLE_GAUGES), 3);

        // When: the reporter task ends with its job.
        drop(guard);

        // Then: no series is left behind for a store that no longer exists.
        assert_eq!(series_count(&TRIPLE_GAUGES), 0);
    }
}
