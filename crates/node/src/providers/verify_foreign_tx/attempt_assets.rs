use std::collections::BTreeSet;

use futures::FutureExt;
use near_contract_transport::{BlockCount, BlockHeight};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::time::{Duration, timeout};

use crate::assets::DistributedAssetStorage;
use crate::primitives::{ParticipantId, UniqueId};

/// The number of blocks a participant's indexer may lag behind the leader's and still join a
/// V2 attempt. A follower waits for a request about this many blocks after a Start.
const INDEXER_MARGIN: BlockCount = BlockCount::new(5);

/// An owned asset this node took for an attempt it leads.
pub(crate) struct OwnedAsset<T> {
    pub(crate) id: UniqueId,
    pub(crate) asset: T,
}

/// Returns true when a participant whose indexer reached `participant_height` may join a V2
/// attempt of a leader whose indexer reached `leader_height`.
pub(crate) fn is_within_indexer_margin(
    leader_height: BlockHeight,
    participant_height: BlockHeight,
) -> bool {
    participant_height.saturating_add(INDEXER_MARGIN) >= leader_height
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
    use rstest::rstest;
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

    #[rstest]
    #[case::level(100, true)]
    #[case::at_the_margin(95, true)]
    #[case::ahead(110, true)]
    #[case::beyond_the_margin(94, false)]
    fn is_within_indexer_margin__should_admit_a_participant_at_most_five_blocks_behind(
        #[case] participant_height: u64,
        #[case] admitted: bool,
    ) {
        // Given
        let leader_height = BlockHeight::new(100);

        // When
        let within = is_within_indexer_margin(leader_height, BlockHeight::new(participant_height));

        // Then
        assert_eq!(within, admitted);
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
