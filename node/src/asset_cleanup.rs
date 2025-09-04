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

/* database helpers */
enum EpochDataWrapper {
    Legacy(EpochId),
    Current(EpochData),
}

fn get_epoch_data(db: &Arc<SecretDB>) -> anyhow::Result<Option<EpochDataWrapper>> {
    let Some(db_res): Option<Vec<u8>> = db.get(DBCol::EpochData, EPOCH_ID_KEY)? else {
        return Ok(None);
    };
    if let Ok(epoch_data) = bincode::deserialize::<EpochData>(&db_res) {
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
    anyhow::bail!("Can't deserialize EPOCH_ID entry: {:?}", db_res);
}

enum AssetCleanup {
    Keep,
    DeleteAll,
    KeepOnly(Vec<primitives::ParticipantId>),
}

fn get_cleanup_behavior(
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

fn get_cleanup_behavior_during_update(
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
                get_cleanup_behavior_during_update(previous_epoch_id, current_epoch_id)
            }
            EpochDataWrapper::Current(previous_epoch_data) => {
                get_cleanup_behavior(&previous_epoch_data, &current_epoch_data)
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
    let bytes = bincode::serialize(&current_epoch_data)?;
    update_writer.put(DBCol::EpochData, EPOCH_ID_KEY, &bytes);
    tracing::info!("Updated epoch id entry");
    update_writer.commit()?;
    Ok(())
}

#[cfg(test)]
mod test_utils {
    use crate::asset_cleanup::EpochData;
    use crate::assets::DistributedAssetStorage;
    use crate::config::ParticipantsConfig;
    use crate::db::SecretDB;
    use crate::indexer::participants::convert_participant_infos;
    use crate::providers::ecdsa::presign::PresignOutputWithParticipants;
    use crate::providers::ecdsa::triple::{PairedTriple, TRIPLE_STORE_DOMAIN_ID};
    use crate::providers::HasParticipants;
    use crate::{db::DBCol, primitives::ParticipantId};
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use k256::ProjectivePoint;
    use mpc_contract::primitives::domain::DomainId;
    use mpc_contract::primitives::key_state::EpochId;
    use mpc_contract::primitives::test_utils::gen_participants;
    use mpc_contract::primitives::thresholds::{Threshold, ThresholdParameters};
    use near_time::FakeClock;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use std::sync::{Arc, Mutex};
    use threshold_signatures::ecdsa::ot_based_ecdsa::triples::{
        TripleGenerationOutput, TriplePub, TripleShare,
    };
    use threshold_signatures::ecdsa::ot_based_ecdsa::PresignOutput;
    use threshold_signatures::ecdsa::Polynomial;

    pub fn random_verifying_key() -> VerifyingKey {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        signing_key.verifying_key()
    }

    pub fn gen_four_participants() -> (EpochData, ParticipantId) {
        let epoch_id = EpochId::new(rand::thread_rng().next_u64());
        let parameters = ThresholdParameters::new(gen_participants(4), Threshold::new(3)).unwrap();
        let participants: ParticipantsConfig = convert_participant_infos(parameters, None).unwrap();
        let epoch_data = EpochData {
            epoch_id,
            participants,
        };
        let my_participant_id = epoch_data.participants.participants.first().unwrap().id;
        (epoch_data, my_participant_id)
    }

    pub fn get_participant_ids(epoch_data: EpochData) -> Vec<ParticipantId> {
        epoch_data
            .participants
            .participants
            .iter()
            .map(|p_info| p_info.id)
            .collect()
    }

    pub struct TestContext {
        pub db: Arc<SecretDB>,
        pub clock: FakeClock,
        pub my_participant_id: ParticipantId,
        pub alive_participants: Arc<Mutex<Vec<ParticipantId>>>,
        pub presign_domain_ids: Vec<DomainId>,
    }

    pub fn make_triple(participants: &[ParticipantId]) -> PairedTriple {
        let g = Polynomial::generate_polynomial(None, 2 - 1, &mut OsRng).unwrap();
        let scalar = g.eval_at_zero().unwrap().0;
        let affine_point = (ProjectivePoint::GENERATOR * scalar.invert().unwrap()).to_affine();
        let cait_sith_participants: Vec<threshold_signatures::protocol::Participant> =
            participants.iter().map(|p| p.raw().into()).collect();
        let triple_pub = TriplePub {
            big_a: affine_point,
            big_b: affine_point,
            big_c: affine_point,
            participants: cait_sith_participants,
            threshold: 3,
        };
        let triple_share = TripleShare {
            a: scalar,
            b: scalar,
            c: scalar,
        };

        let triple_gen_output: TripleGenerationOutput = (triple_share, triple_pub);
        (triple_gen_output.clone(), triple_gen_output.clone())
    }

    pub fn make_presign(participants: &[ParticipantId]) -> PresignOutputWithParticipants {
        let g = Polynomial::generate_polynomial(None, 2 - 1, &mut OsRng).unwrap();
        let scalar = g.eval_at_zero().unwrap().0;
        let affine_point = (ProjectivePoint::GENERATOR * scalar.invert().unwrap()).to_affine();
        let presignature = PresignOutput {
            big_r: affine_point,
            k: scalar,
            sigma: scalar,
        };
        PresignOutputWithParticipants {
            presignature: presignature.clone(),
            participants: participants.to_owned(),
        }
    }

    impl TestContext {
        pub fn new(
            my_participant_id: ParticipantId,
            alive_participants: Arc<Mutex<Vec<ParticipantId>>>,
        ) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let db = crate::db::SecretDB::new(dir.path(), [1; 16]).unwrap();
            Self {
                db,
                clock: FakeClock::default(),
                my_participant_id,
                alive_participants,
                presign_domain_ids: [DomainId(0), DomainId(1)].to_vec(),
            }
        }

        pub fn new_store<T>(
            &self,
            db_col: DBCol,
            domain_id: Option<DomainId>,
        ) -> DistributedAssetStorage<T>
        where
            T: Serialize + DeserializeOwned + Send + 'static + HasParticipants,
        {
            DistributedAssetStorage::<T>::new(
                self.clock.clock(),
                self.db.clone(),
                db_col,
                domain_id,
                self.my_participant_id,
                |cond, val| val.is_subset_of_active_participants(cond),
                {
                    let alive = self.alive_participants.clone();
                    Arc::new(move || alive.lock().unwrap().clone())
                },
            )
            .unwrap()
        }

        pub fn populate(&self, participants: &[ParticipantId]) {
            {
                let store = self.new_store::<PairedTriple>(DBCol::Triple, TRIPLE_STORE_DOMAIN_ID);
                let id = store.generate_and_reserve_id();
                store.add_owned(id, make_triple(participants));
            }
            {
                for &d in &self.presign_domain_ids {
                    let store = self
                        .new_store::<PresignOutputWithParticipants>(DBCol::Presignature, Some(d));
                    let id = store.generate_and_reserve_id();
                    store.add_owned(id, make_presign(participants));
                }
            }
        }

        pub fn assert_owned(&self, expected: usize) {
            let store = self.new_store::<PairedTriple>(DBCol::Triple, TRIPLE_STORE_DOMAIN_ID);
            assert_eq!(store.num_owned(), expected);

            for &d in &self.presign_domain_ids {
                let store =
                    self.new_store::<PresignOutputWithParticipants>(DBCol::Presignature, Some(d));
                assert_eq!(store.num_owned(), expected);
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::asset_cleanup::test_utils;
    use crate::asset_cleanup::test_utils::get_participant_ids;
    use crate::asset_cleanup::test_utils::random_verifying_key;
    use crate::asset_cleanup::test_utils::TestContext;
    use crate::asset_cleanup::EpochDataWrapper;
    use crate::asset_cleanup::{delete_stale_triples_and_presignatures, get_epoch_data};
    use mpc_contract::primitives::domain::DomainId;
    use std::sync::{Arc, Mutex};

    use super::EpochData;

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
