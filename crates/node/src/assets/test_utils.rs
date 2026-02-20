use crate::assets::cleanup::EpochData;
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
    let dto_params: contract_interface::types::ThresholdParameters =
        serde_json::from_value(serde_json::to_value(&parameters).unwrap()).unwrap();
    let participants: ParticipantsConfig = convert_participant_infos(&dto_params, None).unwrap();
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
    let cait_sith_participants: Vec<threshold_signatures::participants::Participant> =
        participants.iter().map(|p| p.raw().into()).collect();
    let triple_pub = TriplePub {
        big_a: affine_point,
        big_b: affine_point,
        big_c: affine_point,
        participants: cait_sith_participants,
        threshold: 3.into(),
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
                let store =
                    self.new_store::<PresignOutputWithParticipants>(DBCol::Presignature, Some(d));
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
