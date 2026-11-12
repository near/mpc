use std::collections::BTreeSet;

use futures::FutureExt;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::time::{Duration, timeout};

use crate::assets::DistributedAssetStorage;
use crate::primitives::{ParticipantId, UniqueId};

/// An owned asset this node took for an attempt it leads.
pub(crate) struct OwnedAsset<T> {
    pub(crate) id: UniqueId,
    pub(crate) asset: T,
}

/// Takes an owned asset whose participants are all among `candidates`. A free asset without any
/// of `avoid` comes first. Returns `None` when no asset frees up within `wait`.
pub(crate) async fn take_owned_avoiding<T>(
    store: &DistributedAssetStorage<T>,
    candidates: Vec<ParticipantId>,
    avoid: &BTreeSet<ParticipantId>,
    wait: Duration,
) -> Option<OwnedAsset<T>>
where
    T: Serialize + DeserializeOwned + Send + 'static,
{
    let preferred = candidates
        .iter()
        .filter(|participant| !avoid.contains(participant))
        .copied()
        .collect();
    let (id, asset) = match store.take_owned_matching(preferred).now_or_never() {
        Some(taken) => taken,
        None => timeout(wait, store.take_owned_matching(candidates))
            .await
            .ok()?,
    };
    Some(OwnedAsset { id, asset })
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::db::{DBCol, SecretDB};
    use near_time::FakeClock;
    use std::sync::Arc;

    const LEADER: ParticipantId = ParticipantId::from_raw(1);
    const FOLLOWER: ParticipantId = ParticipantId::from_raw(2);
    const FAILED_FOLLOWER: ParticipantId = ParticipantId::from_raw(3);

    fn all_participants() -> Vec<ParticipantId> {
        vec![LEADER, FOLLOWER, FAILED_FOLLOWER]
    }

    fn store(db: Arc<SecretDB>) -> DistributedAssetStorage<Vec<ParticipantId>> {
        DistributedAssetStorage::new(
            FakeClock::default().clock(),
            db,
            DBCol::TripleV2,
            vec![],
            LEADER,
            |eligible, participants: &Vec<ParticipantId>| {
                participants.iter().all(|p| eligible.contains(p))
            },
            Arc::new(all_participants),
        )
        .unwrap()
    }

    fn asset_id(counter: u32) -> UniqueId {
        UniqueId::new(LEADER, 1_700_000_000, counter)
    }

    #[tokio::test]
    async fn take_owned_avoiding__should_prefer_a_free_asset_without_the_avoided_participants() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let store = store(SecretDB::new(dir.path(), [1; 16]).unwrap());
        store.add_owned(asset_id(0), vec![LEADER, FAILED_FOLLOWER]);
        store.add_owned(asset_id(1), vec![LEADER, FOLLOWER]);

        // When
        let taken = take_owned_avoiding(
            &store,
            all_participants(),
            &BTreeSet::from([FAILED_FOLLOWER]),
            Duration::ZERO,
        )
        .await
        .unwrap();

        // Then
        assert_eq!(taken.id, asset_id(1));
        assert_eq!(taken.asset, vec![LEADER, FOLLOWER]);
    }

    #[tokio::test]
    async fn take_owned_avoiding__should_take_an_asset_with_an_avoided_participant_when_no_other_is_free()
     {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let store = store(SecretDB::new(dir.path(), [1; 16]).unwrap());
        store.add_owned(asset_id(0), vec![LEADER, FAILED_FOLLOWER]);

        // When
        let taken = take_owned_avoiding(
            &store,
            all_participants(),
            &BTreeSet::from([FAILED_FOLLOWER]),
            Duration::ZERO,
        )
        .await
        .unwrap();

        // Then
        assert_eq!(taken.id, asset_id(0));
    }

    #[tokio::test(start_paused = true)]
    async fn take_owned_avoiding__should_take_no_asset_with_a_participant_outside_the_candidates() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let store = store(SecretDB::new(dir.path(), [1; 16]).unwrap());
        store.add_owned(asset_id(0), vec![LEADER, FAILED_FOLLOWER]);

        // When
        let taken = take_owned_avoiding(
            &store,
            vec![LEADER, FOLLOWER],
            &BTreeSet::new(),
            Duration::from_secs(1),
        )
        .await;

        // Then
        assert!(taken.is_none());
        assert_eq!(store.num_owned(), 1);
    }
}
