//! Reports the owned-asset gauges (`mpc_owned_num_{triples,presignatures}_*`).
//!
//! There is one triple store per reconstruction threshold and one presignature
//! store per ECDSA domain. Each store gets its own series (labelled by threshold or domain).

use crate::assets::DistributedAssetStorage;
use crate::metrics;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::LazyLock;
use std::time::Duration;

pub const ASSET_METRICS_REPORTING_INTERVAL: Duration = Duration::from_secs(1);

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

/// Presignature gauges, labelled by domain id.
pub static PRESIGNATURE_GAUGES: OwnedAssetGauges = OwnedAssetGauges {
    available: &metrics::MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE,
    online: &metrics::MPC_OWNED_NUM_PRESIGNATURES_ONLINE,
    offline: &metrics::MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT,
};

fn to_gauge_value(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

/// Sets the series `label` of `gauges` to `counts`.
pub fn set_owned_asset_gauges(gauges: &OwnedAssetGauges, label: &str, counts: OwnedAssetCounts) {
    let label = [label];
    gauges
        .available
        .with_label_values(&label)
        .set(to_gauge_value(counts.available));
    gauges
        .online
        .with_label_values(&label)
        .set(to_gauge_value(counts.online));
    gauges
        .offline
        .with_label_values(&label)
        .set(to_gauge_value(counts.offline));
}

/// Sets the series `label` of `gauges` from a fresh read of `store`.
pub fn report_store<T>(
    gauges: &OwnedAssetGauges,
    label: impl ToString,
    store: &DistributedAssetStorage<T>,
) where
    T: Serialize + DeserializeOwned + Send + 'static,
{
    set_owned_asset_gauges(gauges, &label.to_string(), store.owned_asset_counts());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::test_utils::{TestContext, make_presign};
    use crate::db::DBCol;
    use crate::primitives::ParticipantId;
    use crate::providers::ecdsa::presign::PresignOutputWithParticipants;
    use std::sync::{Arc, Mutex};

    fn counts(available: usize, online: usize, offline: usize) -> OwnedAssetCounts {
        OwnedAssetCounts {
            available,
            online,
            offline,
        }
    }

    fn read(gauges: &OwnedAssetGauges, label: &str) -> OwnedAssetCounts {
        let label = [label];
        counts(
            gauges.available.with_label_values(&label).get() as usize,
            gauges.online.with_label_values(&label).get() as usize,
            gauges.offline.with_label_values(&label).get() as usize,
        )
    }

    #[test]
    #[expect(non_snake_case)]
    fn set_owned_asset_gauges__should_keep_series_apart_by_label() {
        // Given, When
        set_owned_asset_gauges(&TRIPLE_GAUGES, "test-t2", counts(10, 7, 2));
        set_owned_asset_gauges(&TRIPLE_GAUGES, "test-t3", counts(5, 1, 3));
        set_owned_asset_gauges(&PRESIGNATURE_GAUGES, "test-d0", counts(20, 20, 0));
        set_owned_asset_gauges(&PRESIGNATURE_GAUGES, "test-d1", counts(4, 0, 1));

        // Then
        assert_eq!(read(&TRIPLE_GAUGES, "test-t2"), counts(10, 7, 2));
        assert_eq!(read(&TRIPLE_GAUGES, "test-t3"), counts(5, 1, 3));
        assert_eq!(read(&PRESIGNATURE_GAUGES, "test-d0"), counts(20, 20, 0));
        assert_eq!(read(&PRESIGNATURE_GAUGES, "test-d1"), counts(4, 0, 1));
    }

    #[test]
    #[expect(non_snake_case)]
    fn set_owned_asset_gauges__should_overwrite_previous_values() {
        // Given
        set_owned_asset_gauges(&PRESIGNATURE_GAUGES, "test-overwrite", counts(42, 40, 2));

        // When
        set_owned_asset_gauges(&PRESIGNATURE_GAUGES, "test-overwrite", counts(0, 0, 0));

        // Then
        assert_eq!(
            read(&PRESIGNATURE_GAUGES, "test-overwrite"),
            counts(0, 0, 0)
        );
    }
    #[tokio::test]
    #[expect(non_snake_case)]
    async fn report_store__should_follow_the_store_after_take_owned() {
        // Given
        let participants: Vec<ParticipantId> = (0..3).map(ParticipantId::from_raw).collect();
        let ctx = TestContext::new(participants[0], Arc::new(Mutex::new(participants.clone())));
        let store = ctx.new_store::<PresignOutputWithParticipants>(DBCol::Presignature, Vec::new());
        for _ in 0..2 {
            store.add_owned(store.generate_and_reserve_id(), make_presign(&participants));
        }
        report_store(&PRESIGNATURE_GAUGES, "test-take-owned", &store);
        assert_eq!(read(&PRESIGNATURE_GAUGES, "test-take-owned").available, 2);

        // When
        store.take_owned().await;
        report_store(&PRESIGNATURE_GAUGES, "test-take-owned", &store);

        // Then
        assert_eq!(read(&PRESIGNATURE_GAUGES, "test-take-owned").available, 1);
    }
}
