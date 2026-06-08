use crate::assets::clean_db;
use crate::config::ParticipantsConfig;
use crate::db::{DBCol, EPOCH_ID_KEY, SecretDB};
use crate::primitives;
use crate::providers::ecdsa::presign::PresignOutputWithParticipants;
use crate::providers::ecdsa::triple::PairedTriple;
use mpc_primitives::{EpochId, ReconstructionThreshold, domain::DomainId};
use serde::{self, Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct EpochData {
    pub epoch_id: EpochId,
    pub participants: ParticipantsConfig,
}

// This function compares the `current_epoch_data` with the epoch data stored in the database.
// If the epoch id changed, then all assets (triples & presignatures) are deleted.
// If the epoch id did not change, then the node will discard all owned assets (triples &
// presignatures) involving any nodes that changed their TLS key.
pub fn delete_stale_triples_and_presignatures(
    db: &Arc<SecretDB>,
    current_epoch_data: EpochData,
    my_participant_id: primitives::ParticipantId,
    ecdsa_domain_ds: Vec<DomainId>,
    triple_thresholds: Vec<ReconstructionThreshold>,
) -> anyhow::Result<()> {
    let asset_cleanup: AssetCleanup = match get_epoch_data(db)? {
        None => AssetCleanup::Keep,
        Some(previous_epoch_data) => cleanup_behavior(&previous_epoch_data, &current_epoch_data),
    };

    // All cleanup work + the EpochData marker bump are staged on a single
    // `SecretDBUpdate` so they commit as one atomic RocksDB batch. If the
    // process dies before the commit, none of the deletes or the marker are
    // persisted, and the next startup re-runs the full cleanup unchanged.
    let mut update_writer = db.update();
    match asset_cleanup {
        AssetCleanup::Keep => {}
        AssetCleanup::DeleteAll => {
            update_writer.delete_all(DBCol::Presignature)?;
            update_writer.delete_all(DBCol::TripleV2)?;
        }
        AssetCleanup::KeepOnly(persitent_participants) => {
            // Triples — `TripleV2` uses a `[t as u64 BE]` prefix per store.
            for t in &triple_thresholds {
                clean_db::<PairedTriple>(
                    db,
                    &mut update_writer,
                    DBCol::TripleV2,
                    &persitent_participants,
                    my_participant_id,
                    &t.inner().to_be_bytes(),
                )?;
            }
            // Presignatures (per-domain, unchanged).
            for domain_id in &ecdsa_domain_ds {
                clean_db::<PresignOutputWithParticipants>(
                    db,
                    &mut update_writer,
                    DBCol::Presignature,
                    &persitent_participants,
                    my_participant_id,
                    &domain_id.0.to_be_bytes(),
                )?;
            }
        }
    }

    tracing::info!("Updating epoch data: {:?}.", current_epoch_data);
    let current_epoch_data_ser = serde_json::to_vec(&current_epoch_data)?;
    update_writer.put(DBCol::EpochData, EPOCH_ID_KEY, &current_epoch_data_ser);
    update_writer.commit()?;
    tracing::info!("Updated epoch id entry");
    Ok(())
}

/* database helpers */
fn get_epoch_data(db: &Arc<SecretDB>) -> anyhow::Result<Option<EpochData>> {
    let Some(db_res): Option<Vec<u8>> = db.get(DBCol::EpochData, EPOCH_ID_KEY)? else {
        return Ok(None);
    };
    let epoch_data = serde_json::from_slice::<EpochData>(&db_res)
        .map_err(|e| anyhow::anyhow!("Can't deserialize EPOCH_ID entry: {:?}: {e}", db_res))?;
    Ok(Some(epoch_data))
}

enum AssetCleanup {
    Keep,
    DeleteAll,
    KeepOnly(Vec<primitives::ParticipantId>),
}

fn cleanup_behavior(
    previous_epoch_data: &EpochData,
    current_epoch_data: &EpochData,
) -> AssetCleanup {
    if previous_epoch_data.epoch_id != current_epoch_data.epoch_id {
        tracing::info!(
            "Deleting presignatures and triples. NEW EPOCH: {:?}, OLD EPOCH {:?}.",
            current_epoch_data.epoch_id,
            previous_epoch_data.epoch_id
        );
        return AssetCleanup::DeleteAll;
    }
    tracing::info!("Same Epoch Id.");

    let persitent_participants: Vec<primitives::ParticipantId> = current_epoch_data
        .participants
        .participants
        .iter()
        .filter_map(
            |current| match previous_epoch_data.participants.get_info(current.id) {
                None => Some(current.id),
                Some(prev) => (current.p2p_public_key == prev.p2p_public_key).then_some(prev.id),
            },
        )
        .collect();

    let tls_key_changed: bool =
        persitent_participants.len() != current_epoch_data.participants.participants.len();
    if tls_key_changed {
        AssetCleanup::KeepOnly(persitent_participants)
    } else {
        AssetCleanup::Keep
    }
}

#[cfg(test)]
mod tests {
    use crate::assets::cleanup::EpochData;
    use crate::assets::cleanup::{delete_stale_triples_and_presignatures, get_epoch_data};
    use crate::assets::test_utils;
    use crate::assets::test_utils::TestContext;
    use crate::assets::test_utils::get_participant_ids;
    use crate::assets::test_utils::make_triple;
    use crate::assets::test_utils::random_verifying_key;
    use crate::assets::test_utils::triple_v2_key;
    use crate::db::EPOCH_ID_KEY;
    use crate::db::{DBCol, SecretDB};
    use crate::primitives::UniqueId;
    use crate::providers::ecdsa::triple::TripleStorage;
    use mpc_primitives::domain::DomainId;
    use near_time::FakeClock;
    use std::sync::{Arc, Mutex};

    fn assert_epoch_data_in_db_matches(ctx: &TestContext, expected: &EpochData) {
        let found = get_epoch_data(&ctx.db).unwrap().unwrap();
        assert_eq!(found, *expected);
    }

    #[test]
    #[expect(non_snake_case)]
    fn get_epoch_data__should_bail_on_legacy_8_byte_entry() {
        // Given a DB whose EpochData entry is the legacy raw 8-byte epoch id.
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let mut writer = db.update();
        writer.put(DBCol::EpochData, EPOCH_ID_KEY, &7u64.to_be_bytes());
        writer.commit().unwrap();

        // When/Then it fails closed rather than parsing the legacy format.
        get_epoch_data(&db).unwrap_err();
    }

    #[test]
    fn test_delete_triples_and_presignatures() {
        // setup
        let (mut start_data, my_participant_id, threshold) = test_utils::gen_four_participants();
        let all_participants = get_participant_ids(start_data.clone());
        let subset: Vec<_> = all_participants.iter().take(3).cloned().collect();
        let alive_participants = Arc::new(Mutex::new(all_participants.clone()));
        let ctx = TestContext::new(my_participant_id, alive_participants);

        // we start with no data
        ctx.assert_owned(0);
        assert!(get_epoch_data(&ctx.db).unwrap().is_none());

        // we store two assets
        ctx.populate(&all_participants);
        ctx.populate(&subset);
        ctx.assert_owned(2);

        // no changes in participant set and epoch should lead to no changes in assets
        delete_stale_triples_and_presignatures(
            &ctx.db,
            start_data.clone(),
            my_participant_id,
            [DomainId(0), DomainId(1)].to_vec(),
            vec![threshold],
        )
        .unwrap();
        ctx.assert_owned(2);
        assert_epoch_data_in_db_matches(&ctx, &start_data);

        // changing the details of the last participant should remove one of the assets.
        start_data
            .participants
            .participants
            .last_mut()
            .unwrap()
            .p2p_public_key = random_verifying_key();
        delete_stale_triples_and_presignatures(
            &ctx.db,
            start_data.clone(),
            my_participant_id,
            [DomainId(0), DomainId(1)].to_vec(),
            vec![threshold],
        )
        .unwrap();
        ctx.assert_owned(1);
        assert_epoch_data_in_db_matches(&ctx, &start_data);

        // change epoch id
        let mut end_data = start_data.clone();
        end_data.epoch_id = end_data.epoch_id.next();
        delete_stale_triples_and_presignatures(
            &ctx.db,
            end_data.clone(),
            my_participant_id,
            [DomainId(0), DomainId(1)].to_vec(),
            vec![threshold],
        )
        .unwrap();

        ctx.assert_owned(0);
        assert_epoch_data_in_db_matches(&ctx, &end_data);
    }

    /// End-to-end check that a triple written via `TripleStorage::add_owned`
    /// (into `DBCol::TripleV2` under `[t]`) is removed when the participant set
    /// changes. The other cleanup tests populate `TripleV2` via a local helper;
    /// this one exercises the realistic post-`add_owned` state.
    #[test]
    #[expect(non_snake_case)]
    fn delete_stale_triples_and_presignatures__should_clean_stale_triple_in_v2_column() {
        // Given a node has written a stale triple via TripleStorage.
        let (mut start_data, my_participant_id, threshold) = test_utils::gen_four_participants();
        let all_participants = get_participant_ids(start_data.clone());
        let alive_participants = Arc::new(Mutex::new(all_participants.clone()));
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let triple_store = TripleStorage::new(
            FakeClock::default().clock(),
            db.clone(),
            my_participant_id,
            {
                let alive = alive_participants.clone();
                Arc::new(move || alive.lock().unwrap().clone())
            },
            threshold,
        )
        .unwrap();
        let id = triple_store.generate_and_reserve_id();
        triple_store.add_owned(id, make_triple(&all_participants));
        let v2_key = triple_v2_key(threshold, id);
        // Sanity: the row really is in the TripleV2 column.
        assert!(db.get(DBCol::TripleV2, &v2_key).unwrap().is_some());

        // Seed the persisted epoch_data so the next call enters the
        // `KeepOnly` branch (same epoch_id, persistent set shrinks).
        delete_stale_triples_and_presignatures(
            &db,
            start_data.clone(),
            my_participant_id,
            vec![DomainId(0)],
            vec![threshold],
        )
        .unwrap();
        assert!(db.get(DBCol::TripleV2, &v2_key).unwrap().is_some());

        // When one participant's TLS key changes — the triple's participant
        // set is no longer fully persistent.
        start_data
            .participants
            .participants
            .last_mut()
            .unwrap()
            .p2p_public_key = random_verifying_key();

        delete_stale_triples_and_presignatures(
            &db,
            start_data.clone(),
            my_participant_id,
            vec![DomainId(0)],
            vec![threshold],
        )
        .unwrap();

        // Then the row is gone from the TripleV2 column.
        assert!(db.get(DBCol::TripleV2, &v2_key).unwrap().is_none());
    }

    /// Counterpart to the stale-cleaned test: a triple whose participants are
    /// all in the persistent set must survive the cleanup.
    #[test]
    #[expect(non_snake_case)]
    fn delete_stale_triples_and_presignatures__should_keep_active_triple() {
        let (mut start_data, my_participant_id, threshold) = test_utils::gen_four_participants();
        let all_participants = get_participant_ids(start_data.clone());
        // Triple uses everyone EXCEPT the last participant (whose TLS we'll change
        // below), so the participant set stays fully within the persistent set.
        let active_subset: Vec<_> = all_participants
            .iter()
            .take(all_participants.len() - 1)
            .copied()
            .collect();
        let alive_participants = Arc::new(Mutex::new(all_participants.clone()));
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let triple_store = TripleStorage::new(
            FakeClock::default().clock(),
            db.clone(),
            my_participant_id,
            {
                let alive = alive_participants.clone();
                Arc::new(move || alive.lock().unwrap().clone())
            },
            threshold,
        )
        .unwrap();
        let id = triple_store.generate_and_reserve_id();
        triple_store.add_owned(id, make_triple(&active_subset));
        let v2_key = triple_v2_key(threshold, id);

        // Seed epoch_data, then run cleanup with one participant's TLS rotated
        // (the one our triple does not depend on).
        delete_stale_triples_and_presignatures(
            &db,
            start_data.clone(),
            my_participant_id,
            vec![DomainId(0)],
            vec![threshold],
        )
        .unwrap();
        start_data
            .participants
            .participants
            .last_mut()
            .unwrap()
            .p2p_public_key = random_verifying_key();
        delete_stale_triples_and_presignatures(
            &db,
            start_data.clone(),
            my_participant_id,
            vec![DomainId(0)],
            vec![threshold],
        )
        .unwrap();

        assert!(db.get(DBCol::TripleV2, &v2_key).unwrap().is_some());
    }

    /// A triple authored by a peer (received locally via `add_unowned`) must
    /// not be touched by *our* cleanup — each node only cleans the triples it
    /// owns.
    #[test]
    #[expect(non_snake_case)]
    fn delete_stale_triples_and_presignatures__should_keep_peer_owned_triple() {
        let (mut start_data, my_participant_id, threshold) = test_utils::gen_four_participants();
        let all_participants = get_participant_ids(start_data.clone());
        let peer = *all_participants
            .iter()
            .find(|p| **p != my_participant_id)
            .unwrap();
        let alive_participants = Arc::new(Mutex::new(all_participants.clone()));
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let triple_store = TripleStorage::new(
            FakeClock::default().clock(),
            db.clone(),
            my_participant_id,
            {
                let alive = alive_participants.clone();
                Arc::new(move || alive.lock().unwrap().clone())
            },
            threshold,
        )
        .unwrap();
        // Even an outright-stale peer-owned triple stays put — the peer cleans
        // its own.
        let peer_id = UniqueId::new(peer, 100, 0);
        triple_store.add_unowned(peer_id, make_triple(&all_participants));
        let v2_key = triple_v2_key(threshold, peer_id);

        delete_stale_triples_and_presignatures(
            &db,
            start_data.clone(),
            my_participant_id,
            vec![DomainId(0)],
            vec![threshold],
        )
        .unwrap();
        start_data
            .participants
            .participants
            .last_mut()
            .unwrap()
            .p2p_public_key = random_verifying_key();
        delete_stale_triples_and_presignatures(
            &db,
            start_data.clone(),
            my_participant_id,
            vec![DomainId(0)],
            vec![threshold],
        )
        .unwrap();

        assert!(db.get(DBCol::TripleV2, &v2_key).unwrap().is_some());
    }
}
