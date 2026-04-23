use super::participants::{ParticipantId, ParticipantInfo, Participants};
use crate::errors::{Error, InvalidCandidateSet, InvalidThreshold};
use near_account_id::AccountId;
use near_sdk::near;
use std::collections::BTreeMap;

pub use near_mpc_contract_interface::types::Threshold;

/// Minimum absolute threshold required.
const MIN_THRESHOLD_ABSOLUTE: u64 = 2;

/// Stores information about the threshold key parameters:
/// - owners of key shares
/// - cryptographic threshold
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ThresholdParameters {
    participants: Participants,
    threshold: Threshold,
}

impl ThresholdParameters {
    /// Constructs Threshold parameters from `participants` and `threshold` if the
    /// threshold meets the absolute and relative validation criteria.
    pub fn new(participants: Participants, threshold: Threshold) -> Result<Self, Error> {
        match Self::validate_threshold(participants.len() as u64, threshold) {
            Ok(_) => Ok(ThresholdParameters {
                participants,
                threshold,
            }),
            Err(err) => Err(err),
        }
    }

    /// Ensures that the threshold `k` is sensible and meets the absolute and minimum requirements.
    /// That is:
    /// - threshold must be at least `MIN_THRESHOLD_ABSOLUTE`
    /// - threshold can not exceed the number of shares `n_shares`.
    /// - threshold must be at least 60% of the number of shares (rounded upwards).
    pub fn validate_threshold(n_shares: u64, k: Threshold) -> Result<(), Error> {
        if *k > n_shares {
            return Err(InvalidThreshold::MaxRequirementFailed {
                max: n_shares,
                found: *k,
            }
            .into());
        }
        if *k < MIN_THRESHOLD_ABSOLUTE {
            return Err(InvalidThreshold::MinAbsRequirementFailed.into());
        }
        let percentage_bound = (3 * n_shares).div_ceil(5); // minimum 60%
        if *k < percentage_bound {
            return Err(InvalidThreshold::MinRelRequirementFailed {
                required: percentage_bound,
                found: *k,
            }
            .into());
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), Error> {
        Self::validate_threshold(self.participants.len() as u64, self.threshold())?;
        self.participants.validate()
    }

    /// Validates the incoming proposal against the current one, ensuring it's allowed based on the
    /// current participants and threshold settings. Also verifies the TEE quote of the participant
    /// who submitted the proposal.
    pub fn validate_incoming_proposal(&self, proposal: &ThresholdParameters) -> Result<(), Error> {
        // ensure the proposed threshold parameters are valid:
        // if performance issue, inline and merge with loop below
        proposal.validate()?;
        let mut old_by_id: BTreeMap<ParticipantId, AccountId> = BTreeMap::new();
        let mut old_by_acc: BTreeMap<AccountId, (ParticipantId, ParticipantInfo)> = BTreeMap::new();
        for (acc, id, info) in self.participants().participants() {
            old_by_id.insert(*id, acc.clone());
            old_by_acc.insert(acc.clone(), (*id, info.clone()));
        }
        let new_participants = proposal.participants().participants();
        let mut new_min_id = u32::MAX;
        let mut new_max_id = 0u32;
        let mut n_old = 0u64;
        for (new_account, new_id, new_info) in new_participants {
            match old_by_acc.get(new_account) {
                Some((old_id, old_info)) => {
                    if new_id != old_id {
                        return Err(InvalidCandidateSet::ParticipantIdChanged {
                            account_id: new_account.clone(),
                            old_id: **old_id,
                            new_id: **new_id,
                        }
                        .into());
                    }
                    if *new_info != *old_info {
                        return Err(InvalidCandidateSet::ParticipantInfoChanged {
                            account_id: new_account.clone(),
                        }
                        .into());
                    }
                    n_old += 1;
                }
                None => {
                    if let Some(existing_account) = old_by_id.get(new_id) {
                        return Err(InvalidCandidateSet::NewParticipantReusesOldId {
                            account_id: new_account.clone(),
                            new_id: **new_id,
                            existing_account_id: existing_account.clone(),
                        }
                        .into());
                    }
                    new_min_id = std::cmp::min(new_min_id, **new_id);
                    new_max_id = std::cmp::max(new_max_id, **new_id);
                }
            }
        }
        // assert there are enough old participants
        if n_old < *self.threshold() {
            return Err(InvalidCandidateSet::InsufficientOldParticipants.into());
        }
        // ensure the new ids are contiguous and unique
        let n_new = proposal.participants().len() as u64 - n_old;
        if n_new > 0 {
            if n_new - 1 != (new_max_id - new_min_id) as u64 {
                return Err(InvalidCandidateSet::NewParticipantIdsNotContiguous.into());
            }
            if new_min_id != *self.participants().next_id() {
                return Err(InvalidCandidateSet::NewParticipantIdsNotContiguous.into());
            }
            if new_max_id + 1 != *proposal.participants().next_id() {
                return Err(InvalidCandidateSet::NewParticipantIdsTooHigh.into());
            }
        }
        Ok(())
    }

    pub fn threshold(&self) -> Threshold {
        self.threshold
    }
    /// Returns the map of Participants.
    pub fn participants(&self) -> &Participants {
        &self.participants
    }

    /// For integration testing.
    pub fn new_unvalidated(participants: Participants, threshold: Threshold) -> Self {
        ThresholdParameters {
            participants,
            threshold,
        }
    }

    pub fn update_info(
        &mut self,
        account_id: AccountId,
        new_info: ParticipantInfo,
    ) -> Result<(), Error> {
        self.participants.update_info(account_id, new_info)
    }

    /// Returns mutable reference to Participants for benchmarking.
    #[cfg(feature = "bench-contract-methods")]
    pub fn participants_mut(&mut self) -> &mut Participants {
        &mut self.participants
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        errors::{Error, InvalidCandidateSet},
        primitives::{
            participants::{ParticipantId, Participants},
            test_utils::{gen_participant, gen_participants, gen_threshold_params},
            thresholds::{Threshold, ThresholdParameters},
        },
        state::test_utils::gen_valid_params_proposal,
    };
    use assert_matches::assert_matches;
    use rand::Rng;

    #[test]
    fn test_threshold() {
        for _ in 0..20 {
            let v = rand::thread_rng().gen::<u64>();
            let x = Threshold::from(v);
            assert_eq!(v, *x);
        }
    }

    #[test]
    fn test_validate_threshold() {
        let n = rand::thread_rng().gen_range(2..600) as u64;
        let min_threshold = ((n as f64) * 0.6).ceil() as u64;
        for k in 0..min_threshold {
            let _ = ThresholdParameters::validate_threshold(n, Threshold::from(k)).unwrap_err();
        }
        for k in min_threshold..(n + 1) {
            ThresholdParameters::validate_threshold(n, Threshold::from(k)).unwrap();
        }
        let _ = ThresholdParameters::validate_threshold(n, Threshold::from(n + 1)).unwrap_err();
    }

    #[test]
    fn test_threshold_parameters_constructor() {
        let n: usize = rand::thread_rng().gen_range(2..600);
        let min_threshold = ((n as f64) * 0.6).ceil() as usize;

        let participants = gen_participants(n);
        for k in 1..min_threshold {
            let invalid_threshold = Threshold::from(k as u64);
            let _ = ThresholdParameters::new(participants.clone(), invalid_threshold).unwrap_err();
        }
        let _ = ThresholdParameters::new(participants.clone(), Threshold::from((n + 1) as u64))
            .unwrap_err();
        for k in min_threshold..(n + 1) {
            let threshold = Threshold::from(k as u64);
            let tp = ThresholdParameters::new(participants.clone(), threshold);
            let tp = tp.expect("Threshold parameters should be valid for the given threshold");
            tp.validate().expect("Threshold parameters should validate");
            assert_eq!(tp.threshold(), threshold);
            assert_eq!(tp.participants.len(), participants.len());
            assert_eq!(participants, *tp.participants());
            // probably overkill to test below
            for (account_id, _, _) in participants.participants() {
                assert!(tp.participants.is_participant_given_account_id(account_id));
                let expected_id = participants.id(account_id).unwrap();
                assert_eq!(expected_id, tp.participants.id(account_id).unwrap());
                assert_eq!(
                    tp.participants.account_id(&expected_id).unwrap(),
                    *account_id
                );
            }
        }
    }

    #[test]
    fn test_validate_incoming_proposal() {
        // Valid proposals should validate.
        let params = gen_threshold_params(10);
        let proposal = gen_valid_params_proposal(&params);
        params
            .validate_incoming_proposal(&proposal)
            .expect("Valid proposal should validate");

        // Random proposals should not validate.
        let proposal = gen_threshold_params(10);
        let _ = params.validate_incoming_proposal(&proposal).unwrap_err();

        // Proposal with threshold number of shared participants should be allowed.
        let mut new_participants = params.participants.subset(0..*params.threshold as usize);
        new_participants.add_random_participants_till_n(params.participants.len());
        let proposal = ThresholdParameters::new_unvalidated(new_participants, params.threshold);

        assert_matches!(
            params.validate_incoming_proposal(&proposal),
            Ok(_),
            "{:?} -> {:?}",
            params,
            proposal
        );

        // Proposal with less than threshold number of shared participants should not be allowed.
        // Use a fixed-size set to ensure the threshold arithmetic is predictable.
        let large_params =
            ThresholdParameters::new(gen_participants(10), Threshold::from(6)).unwrap();
        let mut new_participants = large_params.participants.subset(0..5); // 5 < threshold of 6
        new_participants.add_random_participants_till_n(10);
        let proposal =
            ThresholdParameters::new_unvalidated(new_participants, large_params.threshold);
        assert_eq!(
            large_params
                .validate_incoming_proposal(&proposal)
                .unwrap_err(),
            Error::from(InvalidCandidateSet::InsufficientOldParticipants)
        );

        // Proposal with the new threshold being invalid should not be allowed.
        let mut new_participants = params.participants.subset(0..*params.threshold as usize);
        new_participants.add_random_participants_till_n(50);
        let proposal = ThresholdParameters::new_unvalidated(new_participants, params.threshold);
        let _ = params.validate_incoming_proposal(&proposal).unwrap_err();
    }

    #[test]
    fn test_proposal_participant_id_changed() {
        let params = ThresholdParameters::new(gen_participants(5), Threshold::from(3)).unwrap();

        // Take an existing participant and change their ID
        let (account, old_id, info) = params.participants.participants()[0].clone();
        let wrong_id = ParticipantId::from(*old_id + 100);

        let mut new_participants_vec: Vec<_> = params
            .participants
            .participants()
            .iter()
            .skip(1)
            .cloned()
            .collect();
        new_participants_vec.push((account.clone(), wrong_id, info));

        let proposal = ThresholdParameters::new_unvalidated(
            Participants::init(ParticipantId::from(*wrong_id + 1), new_participants_vec),
            params.threshold,
        );
        assert_eq!(
            params.validate_incoming_proposal(&proposal).unwrap_err(),
            Error::from(InvalidCandidateSet::ParticipantIdChanged {
                account_id: account,
                old_id: *old_id,
                new_id: *wrong_id,
            })
        );
    }

    #[test]
    fn test_proposal_participant_info_changed() {
        let params = ThresholdParameters::new(gen_participants(5), Threshold::from(3)).unwrap();

        // Take an existing participant and change their info
        let (account, id, _) = params.participants.participants()[0].clone();
        let (_, changed_info) = gen_participant(999);

        let mut new_participants_vec: Vec<_> = params
            .participants
            .participants()
            .iter()
            .skip(1)
            .cloned()
            .collect();
        new_participants_vec.push((account.clone(), id, changed_info));

        let proposal = ThresholdParameters::new_unvalidated(
            Participants::init(params.participants.next_id(), new_participants_vec),
            params.threshold,
        );
        assert_eq!(
            params.validate_incoming_proposal(&proposal).unwrap_err(),
            Error::from(InvalidCandidateSet::ParticipantInfoChanged {
                account_id: account,
            })
        );
    }

    #[test]
    fn test_proposal_new_participant_reuses_old_id() {
        let params = ThresholdParameters::new(gen_participants(5), Threshold::from(3)).unwrap();

        // Remove one old participant and add a new one that reuses their ID.
        // This way the proposal passes basic validate() (no duplicates), but
        // validate_incoming_proposal detects the ID reuse.
        let (existing_account, reused_id, _) = params.participants.participants()[0].clone();
        let (new_account, new_info) = gen_participant(999);

        // Keep participants 1..5 (skip participant 0), then add new account with reused id 0
        let mut new_participants_vec: Vec<_> = params
            .participants
            .participants()
            .iter()
            .skip(1)
            .cloned()
            .collect();
        new_participants_vec.push((new_account.clone(), reused_id, new_info));

        let proposal = ThresholdParameters::new_unvalidated(
            Participants::init(params.participants.next_id(), new_participants_vec),
            params.threshold,
        );
        assert_eq!(
            params.validate_incoming_proposal(&proposal).unwrap_err(),
            Error::from(InvalidCandidateSet::NewParticipantReusesOldId {
                account_id: new_account,
                new_id: *reused_id,
                existing_account_id: existing_account,
            })
        );
    }

    #[test]
    fn test_proposal_non_contiguous_new_ids_fail() {
        // Test that the lowest new id equals to the `next_id` of the previous set.
        // Use a high threshold so adding one participant doesn't violate the 60% rule.
        let params = ThresholdParameters::new(gen_participants(5), Threshold::from(5)).unwrap();

        let wrong_id = *params.participants.next_id() + 1;

        let (account_id, participant_info) = gen_participant(wrong_id as usize);

        let mut tampered_participants = params.participants.clone();
        tampered_participants
            .insert_with_id(account_id, participant_info, ParticipantId::from(wrong_id))
            .unwrap();

        let tampered_params = ThresholdParameters {
            participants: tampered_participants,
            threshold: params.threshold,
        };

        assert_eq!(
            params
                .validate_incoming_proposal(&tampered_params)
                .unwrap_err(),
            Error::from(InvalidCandidateSet::NewParticipantIdsNotContiguous)
        );
    }

    #[test]
    fn test_proposal_non_unique_ids() {
        let params = ThresholdParameters::new(gen_participants(5), Threshold::from(5)).unwrap();

        // Create proposal with duplicate participants (doubled list)
        let tampered_participants = Participants::init(
            params.participants.next_id(),
            params
                .participants
                .participants()
                .iter()
                .chain(params.participants.participants().iter())
                .cloned()
                .collect(),
        );
        // Use a valid threshold for the doubled size so validate_threshold passes
        // and the duplicate check in participants.validate() is reached.
        let tampered_params = ThresholdParameters::new_unvalidated(
            tampered_participants,
            Threshold::from(6), // 60% of 10 = 6
        );
        assert_eq!(
            params
                .validate_incoming_proposal(&tampered_params)
                .unwrap_err(),
            Error::from(InvalidCandidateSet::DuplicateParticipantIds)
        );
    }

    #[test]
    fn test_remove_only() {
        let params = ThresholdParameters::new(gen_participants(5), Threshold::from(3)).unwrap();

        let new_participants = params.participants.subset(0..*params.threshold as usize);

        let new_params = ThresholdParameters::new(new_participants, params.threshold).unwrap();

        let result = params.validate_incoming_proposal(&new_params);
        result.unwrap();
    }

    #[test]
    fn test_simultaneous_remove_and_insert() {
        let n = 5;
        let params = ThresholdParameters::new(gen_participants(n), Threshold::from(3)).unwrap();

        let mut new_participants = params.participants.clone();
        new_participants.add_random_participants_till_n(n + 2);
        let new_participants = new_participants.subset(2..n + 2);

        let new_params = ThresholdParameters::new(new_participants, params.threshold).unwrap();

        let result = params.validate_incoming_proposal(&new_params);
        result.unwrap();
    }

    #[test]
    fn test_new_participant_id_too_high() {
        // When proposal's next_id is higher than max_id + 1, it should fail with
        // NewParticipantIdsTooHigh.
        let params = ThresholdParameters::new(gen_participants(5), Threshold::from(5)).unwrap();
        let next_id = params.participants.next_id();

        // Add one new participant with the correct next_id, but set the proposal's
        // next_id too high (skipping an ID).
        let (new_account, new_info) = gen_participant(999);
        let mut new_participants_vec: Vec<_> = params.participants.participants().to_vec();
        new_participants_vec.push((new_account, next_id, new_info));

        // 6 participants with threshold 5: validate_threshold passes (60% of 6 = 4 <= 5 <= 6)
        let proposal = ThresholdParameters::new_unvalidated(
            Participants::init(
                ParticipantId::from(*next_id + 2), // too high: should be next_id + 1
                new_participants_vec,
            ),
            Threshold::from(5),
        );
        assert_eq!(
            params.validate_incoming_proposal(&proposal).unwrap_err(),
            Error::from(InvalidCandidateSet::NewParticipantIdsTooHigh)
        );
    }
}
