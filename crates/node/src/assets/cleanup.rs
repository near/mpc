use crate::assets::clean_db;
use crate::config::ParticipantsConfig;
use crate::db::{DBCol, SecretDB, EPOCH_ID_KEY};
use crate::primitives;
use crate::providers::ecdsa::presign::PresignOutputWithParticipants;
use crate::providers::ecdsa::triple::{PairedTriple, TRIPLE_STORE_DOMAIN_ID};
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::key_state::EpochId;
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
) -> anyhow::Result<()> {
    let current_epoch_id = current_epoch_data.epoch_id;
    let asset_cleanup: AssetCleanup = match get_epoch_data(db)? {
        None => AssetCleanup::Keep,
        Some(previous_epoch_data) => match previous_epoch_data {
            EpochDataWrapper::Legacy(previous_epoch_id) => {
                cleanup_behavior_during_update(previous_epoch_id, current_epoch_id)
            }
            EpochDataWrapper::Current(previous_epoch_data) => {
                cleanup_behavior(&previous_epoch_data, &current_epoch_data)
            }
        },
    };

    match asset_cleanup {
        AssetCleanup::Keep => {}
        AssetCleanup::DeleteAll => {
            let mut update_writer = db.update();
            let _ = update_writer.delete_all(DBCol::Presignature);
            let _ = update_writer.delete_all(DBCol::Triple);
            update_writer.commit()?;
        }
        AssetCleanup::KeepOnly(persitent_participants) => {
            // cleanup triples:
            clean_db::<PairedTriple>(
                db,
                DBCol::Triple,
                &persitent_participants,
                my_participant_id,
                TRIPLE_STORE_DOMAIN_ID,
            )?;
            // cleanup presignatures:
            for domain_id in &ecdsa_domain_ds {
                clean_db::<PresignOutputWithParticipants>(
                    db,
                    DBCol::Presignature,
                    &persitent_participants,
                    my_participant_id,
                    Some(*domain_id),
                )?;
            }
        }
    }

    let mut update_writer = db.update();
    tracing::info!("Updating epoch data: {:?}.", current_epoch_data);
    let current_epoch_data_ser = serde_json::to_vec(&current_epoch_data)?;
    update_writer.put(DBCol::EpochData, EPOCH_ID_KEY, &current_epoch_data_ser);
    tracing::info!("Updated epoch id entry");
    update_writer.commit()?;
    Ok(())
}

/* database helpers */
enum EpochDataWrapper {
    Legacy(EpochId),
    Current(EpochData),
}

fn get_epoch_data(db: &Arc<SecretDB>) -> anyhow::Result<Option<EpochDataWrapper>> {
    let Some(db_res): Option<Vec<u8>> = db.get(DBCol::EpochData, EPOCH_ID_KEY)? else {
        return Ok(None);
    };
    if let Ok(epoch_data) = serde_json::from_slice::<EpochData>(&db_res) {
        return Ok(Some(EpochDataWrapper::Current(epoch_data)));
    }

    if db_res.len() == 8 {
        let bytes_array: [u8; 8] = db_res
            .as_slice()
            .try_into()
            .inspect_err(|bytes| tracing::error!("PREVIOUS EPOCH_ID ENTRY NOT u64: {:?}", bytes))?;
        let epoch_id_number = u64::from_be_bytes(bytes_array);
        let epoch_id = EpochId::new(epoch_id_number);
        return Ok(Some(EpochDataWrapper::Legacy(epoch_id)));
    };
    anyhow::bail!("Can't deserialize EPOCH_ID entry: {db_res:?}");
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

fn cleanup_behavior_during_update(
    previous_epoch_id: EpochId,
    current_epoch_id: EpochId,
) -> AssetCleanup {
    tracing::info!("Updating from legacy node");
    if previous_epoch_id != current_epoch_id {
        tracing::info!(
            "We should not be updating during a resharing, but we will try our best. Current epoch id: {:?}, old epoch id {:?}.",
            current_epoch_id, previous_epoch_id
        );
        AssetCleanup::DeleteAll
    } else {
        AssetCleanup::Keep
    }
}

#[cfg(test)]
mod tests {
    use crate::assets::cleanup::EpochData;
    use crate::assets::cleanup::EpochDataWrapper;
    use crate::assets::cleanup::{delete_stale_triples_and_presignatures, get_epoch_data};
    use crate::assets::test_utils;
    use crate::assets::test_utils::get_participant_ids;
    use crate::assets::test_utils::random_verifying_key;
    use crate::assets::test_utils::TestContext;
    use mpc_contract::primitives::domain::DomainId;
    use std::sync::{Arc, Mutex};

    fn assert_epoch_data_in_db_matches(ctx: &TestContext, expected: &EpochData) {
        let found = get_epoch_data(&ctx.db).unwrap().unwrap();
        match found {
            EpochDataWrapper::Current(current) => {
                assert_eq!(current, *expected);
            }
            _ => {
                panic!("Expected to find current epoch data.");
            }
        }
    }
    #[test]
    fn test_delete_triples_and_presignatures() {
        // setup
        let (mut start_data, my_participant_id) = test_utils::gen_four_participants();
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
        )
        .unwrap();

        ctx.assert_owned(0);
        assert_epoch_data_in_db_matches(&ctx, &end_data);
    }
}
