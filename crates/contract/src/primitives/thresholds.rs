use super::participants::{ParticipantId, ParticipantInfo, Participants};
use crate::errors::{Error, InvalidCandidateSet, InvalidThreshold};
use near_account_id::AccountId;
use near_mpc_contract_interface::types::{DomainId, ReconstructionThreshold};
use near_sdk::near;
use std::collections::BTreeMap;

pub use near_mpc_contract_interface::types::GovernanceThreshold;

/// Minimum absolute threshold required.
const MIN_THRESHOLD_ABSOLUTE: u64 = 2;

/// Lower bound on the GovernanceThreshold for `n` participants: 60% rounded up.
/// Single source of truth shared by validation and test fixtures.
pub(crate) fn governance_threshold_lower_relative_bound(n: u64) -> u64 {
    3_u64.saturating_mul(n).div_ceil(5)
}

/// Upper bound on the GovernanceThreshold for `n` participants:
/// Currently set to 100% of participants but would be a discussion subject
/// to drop this upper bound down not to have problems with smart contract
/// being locked if t = n and if an operator stops voting
pub(crate) fn governance_threshold_upper_relative_bound(n: u64) -> u64 {
    n
}

/// Stores the governance parameters: the current `participants` and the
/// governance `threshold` (the number of participants that must agree to
/// approve a governance action). This is the stored, always-current shape.
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct GovernanceThresholdParameters {
    participants: Participants,
    threshold: GovernanceThreshold,
}

impl GovernanceThresholdParameters {
    /// Constructs GovernanceThreshold parameters from `participants` and `threshold` if the
    /// threshold meets the absolute and relative validation criteria.
    pub fn new(
        participants: Participants,
        governance_threshold: GovernanceThreshold,
    ) -> Result<Self, Error> {
        match Self::validate_governance_threshold(participants.len() as u64, governance_threshold) {
            Ok(_) => Ok(GovernanceThresholdParameters {
                participants,
                threshold: governance_threshold,
            }),
            Err(err) => Err(err),
        }
    }

    /// Ensures that the threshold `k` is sensible and meets the absolute and relative requirements.
    /// That is:
    /// - threshold must be at least `MIN_THRESHOLD_ABSOLUTE`
    /// - threshold can not exceed the number of shares `n_shares`.
    /// - threshold must be at least 60% of the number of shares (rounded upwards).
    /// - threshold must not exceed the upper bound (now set to 100%)
    fn validate_governance_threshold(n_shares: u64, k: GovernanceThreshold) -> Result<(), Error> {
        if k.value() > n_shares {
            return Err(InvalidThreshold::MaxRequirementFailed {
                max: n_shares,
                found: k.value(),
            }
            .into());
        }
        if k.value() < MIN_THRESHOLD_ABSOLUTE {
            return Err(InvalidThreshold::MinAbsRequirementFailed.into());
        }
        let lower_relative_bound = governance_threshold_lower_relative_bound(n_shares);
        if k.value() < lower_relative_bound {
            return Err(InvalidThreshold::MinRelRequirementFailed {
                required: lower_relative_bound,
                found: k.value(),
            }
            .into());
        }
        let upper_relative_bound = governance_threshold_upper_relative_bound(n_shares);
        if k.value() > upper_relative_bound {
            return Err(InvalidThreshold::MaxRelRequirementFailed {
                max: upper_relative_bound,
                found: k.value(),
            }
            .into());
        }
        Ok(())
    }

    /// Validates the GovernanceThreshold `k` against both the participant count and the
    /// largest ReconstructionThreshold across all domains. Layers the cross-domain rule
    /// `GovernanceThreshold >= max(ReconstructionThreshold)` on top of `validate_governance_threshold`:
    /// the network must never be able to govern with fewer parties than are required to
    /// reconstruct any domain's key. Call this at every point where the GovernanceThreshold,
    /// a ReconstructionThreshold, or the participant set changes.
    pub fn validate_governance_against_reconstruction(
        num_participants: u64,
        governance: GovernanceThreshold,
        max_reconstruction_threshold: Option<ReconstructionThreshold>,
    ) -> Result<(), Error> {
        Self::validate_governance_threshold(num_participants, governance)?;
        if let Some(max_reconstruction_threshold) = max_reconstruction_threshold
            && governance.value() < max_reconstruction_threshold.inner()
        {
            return Err(InvalidThreshold::BelowReconstructionThreshold {
                reconstruction_threshold: max_reconstruction_threshold.inner(),
                governance_threshold: governance.value(),
            }
            .into());
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), Error> {
        Self::validate_governance_threshold(self.participants.len() as u64, self.threshold())?;
        self.participants.validate()
    }

    /// Validates the incoming proposal against the current one, ensuring it's allowed based on the
    /// current participants and threshold settings. Also verifies the TEE quote of the participant
    /// who submitted the proposal.
    pub fn validate_incoming_proposal(
        &self,
        proposal: &GovernanceThresholdParameters,
    ) -> Result<(), Error> {
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
                            old_id: old_id.get(),
                            new_id: new_id.get(),
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
                            new_id: new_id.get(),
                            existing_account_id: existing_account.clone(),
                        }
                        .into());
                    }
                    new_min_id = std::cmp::min(new_min_id, new_id.get());
                    new_max_id = std::cmp::max(new_max_id, new_id.get());
                }
            }
        }
        // assert there are enough old participants
        if n_old < self.threshold().value() {
            return Err(InvalidCandidateSet::InsufficientOldParticipants.into());
        }
        // ensure the new ids are contiguous and unique
        let n_new = proposal.participants().len() as u64 - n_old;
        if n_new > 0 {
            if n_new - 1 != (new_max_id - new_min_id) as u64 {
                return Err(InvalidCandidateSet::NewParticipantIdsNotContiguous.into());
            }
            if new_min_id != self.participants().next_id().get() {
                return Err(InvalidCandidateSet::NewParticipantIdsNotContiguous.into());
            }
            if new_max_id + 1 != proposal.participants().next_id().get() {
                return Err(InvalidCandidateSet::NewParticipantIdsTooHigh.into());
            }
        }
        Ok(())
    }

    pub fn threshold(&self) -> GovernanceThreshold {
        self.threshold
    }
    /// Returns the map of Participants.
    pub fn participants(&self) -> &Participants {
        &self.participants
    }

    /// Test-only: builds parameters without threshold validation.
    #[cfg(feature = "test-utils")]
    pub fn new_unvalidated(
        participants: Participants,
        governance_threshold: GovernanceThreshold,
    ) -> Self {
        GovernanceThresholdParameters {
            participants,
            threshold: governance_threshold,
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

/// A proposal submitted to `vote_new_parameters`: the new [`GovernanceThresholdParameters`]
/// plus per-domain `ReconstructionThreshold` updates applied to the
/// [`super::domain::DomainRegistry`] when resharing completes. An empty map keeps
/// the current thresholds; a populated map must reference only existing domains
/// (validated in `RunningContractState::process_new_parameters_proposal`).
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ProposedGovernanceThresholdParameters {
    parameters: GovernanceThresholdParameters,
    #[serde(default)]
    per_domain_thresholds: BTreeMap<DomainId, ReconstructionThreshold>,
}

impl ProposedGovernanceThresholdParameters {
    pub fn new(
        parameters: GovernanceThresholdParameters,
        per_domain_thresholds: BTreeMap<DomainId, ReconstructionThreshold>,
    ) -> Self {
        ProposedGovernanceThresholdParameters {
            parameters,
            per_domain_thresholds,
        }
    }

    /// Builder-style helper: replace the per-domain reconstruction-threshold
    /// updates. Convenient for constructing proposals (notably in tests).
    #[cfg(test)]
    pub fn with_per_domain_thresholds(
        mut self,
        per_domain_thresholds: BTreeMap<DomainId, ReconstructionThreshold>,
    ) -> Self {
        self.per_domain_thresholds = per_domain_thresholds;
        self
    }

    /// The proposed stored parameters (participants + threshold).
    pub fn parameters(&self) -> &GovernanceThresholdParameters {
        &self.parameters
    }

    /// The proposed per-domain reconstruction-threshold updates.
    pub fn per_domain_thresholds(&self) -> &BTreeMap<DomainId, ReconstructionThreshold> {
        &self.per_domain_thresholds
    }

    /// Delegates to the proposed parameters' participants.
    pub fn participants(&self) -> &Participants {
        self.parameters.participants()
    }

    /// Delegates to the proposed parameters' threshold.
    pub fn threshold(&self) -> GovernanceThreshold {
        self.parameters.threshold()
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use crate::{
        errors::{Error, InvalidCandidateSet, InvalidThreshold},
        primitives::{
            participants::{ParticipantId, Participants},
            test_utils::{gen_participant, gen_participants, gen_threshold_params},
            thresholds::{
                GovernanceThreshold, GovernanceThresholdParameters,
                ProposedGovernanceThresholdParameters, governance_threshold_lower_relative_bound,
                governance_threshold_upper_relative_bound,
            },
        },
        state::test_utils::gen_valid_params_proposal,
    };
    use assert_matches::assert_matches;
    use near_mpc_contract_interface::types::{DomainId, ReconstructionThreshold};
    use rand::Rng;
    use std::collections::BTreeMap;

    #[test]
    fn test_threshold() {
        for _ in 0..20 {
            let v = rand::thread_rng().r#gen::<u64>();
            let x = GovernanceThreshold::new(v);
            assert_eq!(v, x.value());
        }
    }

    #[test]
    fn test_validate_governance_threshold() {
        let n = rand::thread_rng().gen_range(2..600) as u64;
        let min_threshold = governance_threshold_lower_relative_bound(n);
        let max_threshold = governance_threshold_upper_relative_bound(n);
        for k in 0..min_threshold {
            let _ = GovernanceThresholdParameters::validate_governance_threshold(
                n,
                GovernanceThreshold::new(k),
            )
            .unwrap_err();
        }
        for k in min_threshold..=max_threshold {
            GovernanceThresholdParameters::validate_governance_threshold(
                n,
                GovernanceThreshold::new(k),
            )
            .unwrap();
        }
        // Anything above the upper cap (up to and beyond n) must be rejected.
        for k in (max_threshold + 1)..=(n + 1) {
            let _ = GovernanceThresholdParameters::validate_governance_threshold(
                n,
                GovernanceThreshold::new(k),
            )
            .unwrap_err();
        }
    }

    #[test]
    fn test_threshold_parameters_constructor() {
        let n: usize = rand::thread_rng().gen_range(2..600);
        let min_threshold = governance_threshold_lower_relative_bound(n as u64) as usize;
        let max_threshold = governance_threshold_upper_relative_bound(n as u64) as usize;

        let participants = gen_participants(n);
        for k in 1..min_threshold {
            let invalid_threshold = GovernanceThreshold::new(k as u64);
            let _ = GovernanceThresholdParameters::new(participants.clone(), invalid_threshold)
                .unwrap_err();
        }
        // Thresholds above the upper cap (including up to n and beyond) are rejected.
        for k in (max_threshold + 1)..=(n + 1) {
            let invalid_threshold = GovernanceThreshold::new(k as u64);
            let _ = GovernanceThresholdParameters::new(participants.clone(), invalid_threshold)
                .unwrap_err();
        }
        for k in min_threshold..=max_threshold {
            let threshold = GovernanceThreshold::new(k as u64);
            let tp = GovernanceThresholdParameters::new(participants.clone(), threshold);
            let tp =
                tp.expect("GovernanceThreshold parameters should be valid for the given threshold");
            tp.validate()
                .expect("GovernanceThreshold parameters should validate");
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
    fn validate_governance_threshold__should_not_produce_empty_window_for_small_n() {
        // The relative upper cap is clamped up to the ceil(0.6n) lower bound, so the
        // feasible window must always hold at least one valid threshold.
        for n in 2..=12u64 {
            let lower = governance_threshold_lower_relative_bound(n);
            let upper = governance_threshold_upper_relative_bound(n);
            assert!(upper >= lower, "empty window at n={n}: [{lower}, {upper}]");
            // The clamped boundary value must validate.
            GovernanceThresholdParameters::validate_governance_threshold(
                n,
                GovernanceThreshold::new(upper),
            )
            .unwrap();
        }
    }

    #[test]
    fn validate_governance_against_reconstruction__should_reject_governance_below_max_reconstruction()
     {
        // Given 10 participants and a governance threshold of 6 (a valid value on its own).
        let n = 10;
        let governance = GovernanceThreshold::new(6);
        // When the largest reconstruction threshold is 7 (above governance).
        // Then the relation is rejected.
        assert_matches!(
            GovernanceThresholdParameters::validate_governance_against_reconstruction(
                n,
                governance,
                Some(ReconstructionThreshold::new(7))
            ),
            Err(Error::InvalidThreshold(
                InvalidThreshold::BelowReconstructionThreshold {
                    reconstruction_threshold: 7,
                    governance_threshold: 6,
                }
            ))
        );
        // ...but is accepted when governance meets or exceeds the max reconstruction threshold.
        GovernanceThresholdParameters::validate_governance_against_reconstruction(
            n,
            governance,
            Some(ReconstructionThreshold::new(6)),
        )
        .unwrap();
        GovernanceThresholdParameters::validate_governance_against_reconstruction(
            n,
            governance,
            Some(ReconstructionThreshold::new(5)),
        )
        .unwrap();
    }

    #[test]
    fn test_validate_incoming_proposal() {
        // Valid proposals should validate.
        let params = gen_threshold_params(10);
        let proposal = gen_valid_params_proposal(&params);
        params
            .validate_incoming_proposal(proposal.parameters())
            .expect("Valid proposal should validate");

        // Random proposals should not validate.
        let proposal = gen_threshold_params(10);
        let _ = params.validate_incoming_proposal(&proposal).unwrap_err();

        // Proposal with threshold number of shared participants should be allowed.
        let mut new_participants = params
            .participants
            .subset(0..params.threshold.value() as usize);
        new_participants.add_random_participants_till_n(params.participants.len());
        let proposal =
            GovernanceThresholdParameters::new_unvalidated(new_participants, params.threshold);

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
            GovernanceThresholdParameters::new(gen_participants(10), GovernanceThreshold::new(6))
                .unwrap();
        let mut new_participants = large_params.participants.subset(0..5); // 5 < threshold of 6
        new_participants.add_random_participants_till_n(10);
        let proposal = GovernanceThresholdParameters::new_unvalidated(
            new_participants,
            large_params.threshold,
        );
        assert_eq!(
            large_params
                .validate_incoming_proposal(&proposal)
                .unwrap_err(),
            Error::from(InvalidCandidateSet::InsufficientOldParticipants)
        );

        // Proposal with the new threshold being invalid should not be allowed.
        let mut new_participants = params
            .participants
            .subset(0..params.threshold.value() as usize);
        new_participants.add_random_participants_till_n(50);
        let proposal =
            GovernanceThresholdParameters::new_unvalidated(new_participants, params.threshold);
        let _ = params.validate_incoming_proposal(&proposal).unwrap_err();
    }

    #[test]
    fn test_proposal_participant_id_changed() {
        let params =
            GovernanceThresholdParameters::new(gen_participants(5), GovernanceThreshold::new(3))
                .unwrap();

        // Take an existing participant and change their ID
        let (account, old_id, info) = params.participants.participants()[0].clone();
        let wrong_id = ParticipantId(old_id.get() + 100);

        let mut new_participants_vec: Vec<_> = params
            .participants
            .participants()
            .iter()
            .skip(1)
            .cloned()
            .collect();
        new_participants_vec.push((account.clone(), wrong_id, info));

        let proposal = GovernanceThresholdParameters::new_unvalidated(
            Participants::init(ParticipantId(wrong_id.get() + 1), new_participants_vec),
            params.threshold,
        );
        assert_eq!(
            params.validate_incoming_proposal(&proposal).unwrap_err(),
            Error::from(InvalidCandidateSet::ParticipantIdChanged {
                account_id: account,
                old_id: old_id.get(),
                new_id: wrong_id.get(),
            })
        );
    }

    #[test]
    fn test_proposal_participant_info_changed() {
        let params =
            GovernanceThresholdParameters::new(gen_participants(5), GovernanceThreshold::new(3))
                .unwrap();

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

        let proposal = GovernanceThresholdParameters::new_unvalidated(
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
        let params =
            GovernanceThresholdParameters::new(gen_participants(5), GovernanceThreshold::new(3))
                .unwrap();

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

        let proposal = GovernanceThresholdParameters::new_unvalidated(
            Participants::init(params.participants.next_id(), new_participants_vec),
            params.threshold,
        );
        assert_eq!(
            params.validate_incoming_proposal(&proposal).unwrap_err(),
            Error::from(InvalidCandidateSet::NewParticipantReusesOldId {
                account_id: new_account,
                new_id: reused_id.get(),
                existing_account_id: existing_account,
            })
        );
    }

    #[test]
    fn test_proposal_non_contiguous_new_ids_fail() {
        // Test that the lowest new id equals to the `next_id` of the previous set.
        // Use a high threshold so adding one participant doesn't violate the 60% rule.
        let params =
            GovernanceThresholdParameters::new(gen_participants(5), GovernanceThreshold::new(5))
                .unwrap();

        let wrong_id = params.participants.next_id().0 + 1;

        let (account_id, participant_info) = gen_participant(wrong_id as usize);

        let mut tampered_participants = params.participants.clone();
        tampered_participants
            .insert_with_id(account_id, participant_info, ParticipantId(wrong_id))
            .unwrap();

        let tampered_params =
            GovernanceThresholdParameters::new_unvalidated(tampered_participants, params.threshold);

        assert_eq!(
            params
                .validate_incoming_proposal(&tampered_params)
                .unwrap_err(),
            Error::from(InvalidCandidateSet::NewParticipantIdsNotContiguous)
        );
    }

    #[test]
    fn test_proposal_non_unique_ids() {
        let params =
            GovernanceThresholdParameters::new(gen_participants(5), GovernanceThreshold::new(5))
                .unwrap();

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
        // Use a valid threshold for the doubled size so validate_governance_threshold passes
        // and the duplicate check in participants.validate() is reached.
        let tampered_params = GovernanceThresholdParameters::new_unvalidated(
            tampered_participants,
            GovernanceThreshold::new(6), // 60% of 10 = 6
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
        let params =
            GovernanceThresholdParameters::new(gen_participants(5), GovernanceThreshold::new(3))
                .unwrap();

        let new_participants = params
            .participants
            .subset(0..params.threshold.value() as usize);

        let new_params =
            GovernanceThresholdParameters::new(new_participants, params.threshold).unwrap();

        let result = params.validate_incoming_proposal(&new_params);
        result.unwrap();
    }

    #[test]
    fn test_simultaneous_remove_and_insert() {
        let n = 5;
        let params =
            GovernanceThresholdParameters::new(gen_participants(n), GovernanceThreshold::new(3))
                .unwrap();

        let mut new_participants = params.participants.clone();
        new_participants.add_random_participants_till_n(n + 2);
        let new_participants = new_participants.subset(2..n + 2);

        let new_params =
            GovernanceThresholdParameters::new(new_participants, params.threshold).unwrap();

        let result = params.validate_incoming_proposal(&new_params);
        result.unwrap();
    }

    #[test]
    fn test_new_participant_id_too_high() {
        // When proposal's next_id is higher than max_id + 1, it should fail with
        // NewParticipantIdsTooHigh.
        let params =
            GovernanceThresholdParameters::new(gen_participants(5), GovernanceThreshold::new(5))
                .unwrap();
        let next_id = params.participants.next_id();

        // Add one new participant with the correct next_id, but set the proposal's
        // next_id too high (skipping an ID).
        let (new_account, new_info) = gen_participant(999);
        let mut new_participants_vec: Vec<_> = params.participants.participants().to_vec();
        new_participants_vec.push((new_account, next_id, new_info));

        // 6 participants with threshold 5
        let proposal = GovernanceThresholdParameters::new_unvalidated(
            Participants::init(
                ParticipantId(next_id.get() + 2), // too high: should be next_id + 1
                new_participants_vec,
            ),
            GovernanceThreshold::new(5),
        );
        assert_eq!(
            params.validate_incoming_proposal(&proposal).unwrap_err(),
            Error::from(InvalidCandidateSet::NewParticipantIdsTooHigh)
        );
    }

    #[test]
    fn proposed_threshold_parameters__should_expose_parameters_threshold_and_updates() {
        // Given a proposal carrying per-domain reconstruction-threshold updates
        let params = gen_threshold_params(10);
        let mut updates = BTreeMap::new();
        updates.insert(DomainId(0), ReconstructionThreshold::new(3));
        updates.insert(DomainId(2), ReconstructionThreshold::new(4));
        let proposal = ProposedGovernanceThresholdParameters::new(params.clone(), updates.clone());

        // When / Then the accessors expose the wrapped parameters and the updates,
        // and the participants/threshold delegates match the wrapped parameters.
        assert_eq!(proposal.parameters(), &params);
        assert_eq!(proposal.participants(), params.participants());
        assert_eq!(proposal.threshold(), params.threshold());
        assert_eq!(proposal.per_domain_thresholds(), &updates);
    }

    #[test]
    fn proposed_threshold_parameters__should_default_per_domain_thresholds_when_field_absent_in_json()
     {
        // Given a serialized proposal with the `per_domain_thresholds` field
        // stripped out — the shape an older client predating per-domain
        // reconstruction thresholds would submit to `vote_new_parameters`.
        let params = gen_threshold_params(10);
        let proposal = ProposedGovernanceThresholdParameters::new(params, BTreeMap::new());
        let mut json = serde_json::to_value(&proposal).unwrap();
        json.as_object_mut()
            .unwrap()
            .remove("per_domain_thresholds")
            .expect("empty map should still serialize as a field");

        // When deserializing the field-less JSON
        let parsed: ProposedGovernanceThresholdParameters = serde_json::from_value(json).unwrap();

        // Then the missing field defaults to an empty (no-change) map and the
        // rest of the proposal is preserved.
        assert!(parsed.per_domain_thresholds().is_empty());
        assert_eq!(parsed.parameters(), proposal.parameters());
    }

    #[test]
    fn proposed_threshold_parameters__should_round_trip_per_domain_thresholds_through_json() {
        // Given a proposal with a populated per-domain threshold map
        let params = gen_threshold_params(10);
        let mut updates = BTreeMap::new();
        updates.insert(DomainId(0), ReconstructionThreshold::new(3));
        updates.insert(DomainId(2), ReconstructionThreshold::new(4));
        let proposal = ProposedGovernanceThresholdParameters::new(params, updates);

        // When serializing to JSON and back
        let json = serde_json::to_string(&proposal).unwrap();
        let parsed: ProposedGovernanceThresholdParameters = serde_json::from_str(&json).unwrap();

        // Then the proposal round-trips unchanged
        assert_eq!(parsed, proposal);
    }

    #[test]
    fn proposed_threshold_parameters__should_round_trip_per_domain_thresholds_through_borsh() {
        // Given a proposal with a populated per-domain threshold map
        let params = gen_threshold_params(10);
        let mut updates = BTreeMap::new();
        updates.insert(DomainId(0), ReconstructionThreshold::new(3));
        updates.insert(DomainId(2), ReconstructionThreshold::new(4));
        let proposal = ProposedGovernanceThresholdParameters::new(params, updates);

        // When serializing to borsh and back
        let bytes = borsh::to_vec(&proposal).unwrap();
        let parsed: ProposedGovernanceThresholdParameters = borsh::from_slice(&bytes).unwrap();

        // Then the proposal round-trips unchanged
        assert_eq!(parsed, proposal);
    }
}
