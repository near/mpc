use crate::assets::DistributedAssetStorage;
use crate::config::ParticipantsConfig;
use crate::db::{DBCol, SecretDB, EPOCH_ID_KEY};
use crate::primitives;
use crate::providers::ecdsa::presign::PresignOutputWithParticipants;
use crate::providers::ecdsa::triple::PairedTriple;
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::key_state::EpochId;
use serde::{self, Deserialize, Serialize};
use std::sync::Arc;
use tracing;

pub enum EpochData {
    Legacy(EpochId),
    Current(EpochWithParticipants),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EpochWithParticipants {
    pub epoch_id: EpochId,
    pub participants: ParticipantsConfig,
}

fn get_epoch_data(db: &Arc<SecretDB>) -> anyhow::Result<Option<EpochData>> {
    let Some(db_res): Option<Vec<u8>> = db.get(DBCol::Epoch, EPOCH_ID_KEY)? else {
        return Ok(None);
    };
    if let Ok(epoch_data) = bincode::deserialize::<EpochWithParticipants>(&db_res) {
        return Ok(Some(EpochData::Current(epoch_data)));
    }

    if db_res.len() == 8 {
        let bytes_array: [u8; 8] = db_res
            .as_slice()
            .try_into()
            .inspect_err(|bytes| tracing::error!("PREVIOUS EPOCH_ID ENTRY NOT u64: {:?}", bytes))?;
        let epoch_id_number = u64::from_be_bytes(bytes_array);
        let epoch_id = EpochId::new(epoch_id_number);
        return Ok(Some(EpochData::Legacy(epoch_id)));
    };
    anyhow::bail!("Can't deserialize EPOCH_ID entry: {:?}", db_res);
}

fn get_participants_with_assets(
    previous_config: &ParticipantsConfig,
    current_config: &ParticipantsConfig,
) -> Vec<primitives::ParticipantId> {
    // note: if thersholds are different, do not keep any assets.
    let mut res = Vec::new();
    for current_participant_info in &current_config.participants {
        match previous_config.get_info(current_participant_info.id) {
            None => {
                // this was not a participant in the previous epoch. We can safely keep whatever assets
                // that particpiant had.
                res.push(current_participant_info.id);
            }
            Some(previous_participant_info) => {
                if current_participant_info.p2p_public_key
                    == previous_participant_info.p2p_public_key
                {
                    // only keep them if the p2p key matches
                    res.push(previous_participant_info.id);
                }
            }
        }
    }
    return res;
}

pub enum AssetCleanup {
    Keep,
    DeleteAll,
    KeepOnly(Vec<primitives::ParticipantId>),
}

pub fn get_current_behavior(
    previous_epoch_data: &EpochWithParticipants,
    current_epoch_data: &EpochWithParticipants,
    my_participant_id: primitives::ParticipantId,
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

    let active_participants = get_participants_with_assets(
        &previous_epoch_data.participants,
        &current_epoch_data.participants,
    );

    if active_participants.len() != current_epoch_data.participants.participants.len() {
        if !active_participants.contains(&my_participant_id) {
            tracing::info!("My node operator recently recovered. I must either be the new node, in which case I don't have any assets yet, or I am the old node, in which case all the participants will remove me from their set. Either way, it is safe to delete everything.");
            AssetCleanup::DeleteAll
        } else {
            AssetCleanup::KeepOnly(active_participants)
        }
    } else {
        AssetCleanup::Keep
    }
}

pub fn update_behavior(previous_epoch_id: EpochId, current_epoch_id: EpochId) -> AssetCleanup {
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

// We  need to reliably check if any of the participants have changed their TLS key.
// This would not be necessary, if we incremented the participant id during a recovery process.
// Buut, that might create other issuess? Namely, now, a single participant can just randomly
// increment the participant id via transactions (granted, that costs quite a bit of money, so we
// might be good on that front.)
// This might also create problems with voting, since, we often use ParticipantId as a key.
// So better not.
pub fn delete_stale_triples_and_presignatures(
    db: &Arc<SecretDB>,
    current_epoch_data: EpochWithParticipants,
    my_participant_id: primitives::ParticipantId,
    ecdsa_domain_ds: Vec<DomainId>,
) -> anyhow::Result<()> {
    let current_epoch_id = current_epoch_data.epoch_id;
    let asset_cleanup: AssetCleanup = match get_epoch_data(db)? {
        None => AssetCleanup::Keep,
        Some(previous_epoch_data) => match previous_epoch_data {
            EpochData::Legacy(previous_epoch_id) => {
                update_behavior(previous_epoch_id, current_epoch_id)
            }
            EpochData::Current(previous_epoch_data) => {
                get_current_behavior(&previous_epoch_data, &current_epoch_data, my_participant_id)
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
        AssetCleanup::KeepOnly(active_participants) => {
            DistributedAssetStorage::<PairedTriple>::clean_db(
                db,
                &active_participants,
                my_participant_id,
                None,
            )?;

            for domain_id in ecdsa_domain_ds {
                DistributedAssetStorage::<PresignOutputWithParticipants>::clean_db(
                    db,
                    &active_participants,
                    my_participant_id,
                    Some(domain_id),
                )?;
            }
        }
    }
    let mut update_writer = db.update();
    tracing::info!("Updating epoch data. NEW EPOCH: {:?}.", current_epoch_data);
    let bytes = bincode::serialize(&current_epoch_data)?;
    update_writer.put(DBCol::Epoch, EPOCH_ID_KEY, &bytes);
    tracing::info!("Updated epoch id entry");
    update_writer.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::db::SecretDB;

    pub fn prepare(secret_db: std::sync::Arc<SecretDB>) {
        // 1. make a secret db
        //let secret_b = SecretDB::new(path, cer);
        //
        // 2. store some secret shares that you own
        // 3. store some secret shares of a different participant
        // 4. ensure they are there.
        // 5. now, calle the cleanup mechanism
        // 6. ensure that they are gone / there / partially there.
        //
        // let update_writer = secret.writer
        //secret_db.put()
        // need to implement the trait for participantId, but that should be simple. Basically, the
        // value is a vector of participants.
    }
}
