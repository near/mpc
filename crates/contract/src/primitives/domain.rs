use super::key_state::AuthenticatedParticipantId;
use crate::errors::{DomainError, Error};
use crate::primitives::participants::Participants;
use near_mpc_contract_interface::types::{
    Curve, DomainConfig, DomainId, DomainPurpose, Protocol, ReconstructionThreshold,
};
use near_sdk::{log, near};
use std::collections::BTreeMap;

/// Lower bound on a domain's reconstruction threshold. `t = 1` would mean a
/// single share is sufficient to reconstruct the secret, defeating the point
/// of threshold cryptography.
pub const MIN_RECONSTRUCTION_THRESHOLD: u64 = 2;

/// Returns whether the given protocol is valid for the given purpose.
pub fn is_valid_protocol_for_purpose(purpose: DomainPurpose, protocol: Protocol) -> bool {
    matches!(
        (purpose, protocol),
        (DomainPurpose::Sign, Protocol::CaitSith)
            | (DomainPurpose::Sign, Protocol::DamgardEtAl)
            | (DomainPurpose::Sign, Protocol::Frost)
            | (DomainPurpose::ForeignTx, Protocol::CaitSith)
            | (DomainPurpose::CKD, Protocol::ConfidentialKeyDerivation)
    )
}

/// Validates that `protocol` is allowed for the requested `purpose`.
pub fn validate_domain_purpose(domain: &DomainConfig) -> Result<(), Error> {
    if !is_valid_protocol_for_purpose(domain.purpose, domain.protocol) {
        return Err(DomainError::InvalidProtocolPurposeCombination {
            protocol: domain.protocol,
            purpose: domain.purpose,
        }
        .into());
    }
    Ok(())
}

/// Validates the per-domain reconstruction threshold against the participant
/// count. Universal bound `2 <= t <= n` plus, for `DamgardEtAl`, the
/// honest-majority bound `2t - 1 <= n`.
pub fn validate_domain_threshold(
    domain: &DomainConfig,
    num_participants: u64,
) -> Result<(), Error> {
    let t = domain.reconstruction_threshold.inner();
    if t < MIN_RECONSTRUCTION_THRESHOLD {
        return Err(DomainError::ReconstructionThresholdTooLow.into());
    }
    if t > num_participants {
        return Err(DomainError::ReconstructionThresholdExceedsParticipants {
            threshold: t,
            participants: num_participants,
        }
        .into());
    }
    if domain.protocol == Protocol::DamgardEtAl {
        let required = t
            .checked_mul(2)
            .and_then(|x| x.checked_sub(1))
            .ok_or(DomainError::ReconstructionThresholdOverflow { threshold: t })?;
        if required > num_participants {
            return Err(DomainError::InsufficientParticipantsForProtocol {
                protocol: domain.protocol,
                required,
                participants: num_participants,
            }
            .into());
        }
    }
    Ok(())
}

/// The largest `ReconstructionThreshold` across `domains`, or `None` if there are none
/// (an empty set imposes no cross-domain lower bound on the GovernanceThreshold).
/// Feeds [`ThresholdParameters::validate_governance_against_reconstruction`](crate::primitives::thresholds::ThresholdParameters::validate_governance_against_reconstruction).
pub fn max_reconstruction_threshold(domains: &[DomainConfig]) -> Option<ReconstructionThreshold> {
    domains
        .iter()
        .map(|domain| domain.reconstruction_threshold)
        .max()
}

/// All the domains present in the contract, as well as the next domain ID which is kept to ensure
/// that we never reuse domain IDs. (Domains may be deleted in only one case: when we decided to
/// add domains but ultimately canceled that process.)
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainRegistry {
    domains: Vec<DomainConfig>,
    next_domain_id: u64,
}

impl DomainRegistry {
    pub fn domains(&self) -> &[DomainConfig] {
        &self.domains
    }

    #[cfg(test)]
    pub fn domains_mut(&mut self) -> &mut [DomainConfig] {
        &mut self.domains
    }

    /// Append `domain` at `next_domain_id`, returning its assigned DomainId.
    /// The caller's `domain.id` is ignored; the registry assigns the id
    /// monotonically. The caller is responsible for any validation
    /// (protocol/purpose compatibility, threshold bounds, etc.); this
    /// helper does no checks.
    fn add_domain(&mut self, domain: DomainConfig) -> DomainId {
        let assigned = DomainConfig {
            id: DomainId(self.next_domain_id),
            ..domain
        };
        self.next_domain_id += 1;
        let id = assigned.id;
        self.domains.push(assigned);
        id
    }

    /// Processes the addition of the given domains, returning a new DomainRegistry.
    /// This stringently requires that the domains specified have sorted and contiguous IDs starting
    /// from next_domain_id, returning an error otherwise.
    pub fn add_domains(&self, domains: Vec<DomainConfig>) -> Result<DomainRegistry, Error> {
        let mut new_registry = self.clone();
        for domain in domains {
            validate_domain_purpose(&domain)?;
            let expected_id = domain.id;
            let new_domain_id = new_registry.add_domain(domain);
            if new_domain_id != expected_id {
                return Err(DomainError::NewDomainIdsNotContiguous {
                    expected_id: new_domain_id,
                }
                .into());
            }
        }
        Ok(new_registry)
    }

    /// Retain a prefix of the given number of domains. This is used for cancelling key generation,
    /// where we would delete whatever domains we failed to generate a key for.
    pub fn retain_domains(&mut self, num_domains: usize) {
        self.domains.truncate(num_domains);
    }

    /// Returns the given domain by the index, not the DomainId.
    pub fn get_domain_by_index(&self, index: usize) -> Option<&DomainConfig> {
        self.domains.get(index)
    }

    /// Returns the given domain by the DomainId.
    pub fn get_domain_by_domain_id(&self, id: DomainId) -> Option<&DomainConfig> {
        self.domains.iter().find(|domain| domain.id == id)
    }

    /// Returns the most recently added domain for the given curve, or None
    /// if no such domain exists. The curve is derived from each domain's
    /// `protocol`.
    pub fn most_recent_domain_for_curve(&self, curve: Curve) -> Option<DomainId> {
        self.domains
            .iter()
            .rev()
            .find(|domain| Curve::from(domain.protocol) == curve)
            .map(|domain| domain.id)
    }

    /// Constructs a DomainRegistry from its raw fields, but performing basic
    /// validation that the fields could've been produced by a valid
    /// sequence of add_domains and retain_domains calls. This is used for
    /// init_running and testing only.
    pub fn from_raw_validated(
        domains: Vec<DomainConfig>,
        next_domain_id: u64,
    ) -> Result<Self, Error> {
        let registry = Self {
            domains,
            next_domain_id,
        };
        for domain in &registry.domains {
            validate_domain_purpose(domain)?;
        }
        for (left, right) in registry.domains.iter().zip(registry.domains.iter().skip(1)) {
            if left.id.0 >= right.id.0 {
                return Err(DomainError::InvalidDomains.into());
            }
        }
        if let Some(largest_domain_id) = registry.domains.last().map(|domain| domain.id.0)
            && largest_domain_id >= registry.next_domain_id
        {
            return Err(DomainError::InvalidDomains.into());
        }
        Ok(registry)
    }

    pub fn next_domain_id(&self) -> u64 {
        self.next_domain_id
    }

    /// Returns a new registry whose domains have their
    /// `reconstruction_threshold` rewritten from `threshold_updates`, a sparse
    /// map of the per-domain reconstruction thresholds a proposal wants to
    /// change. Domain IDs in `threshold_updates` that are not present in the
    /// registry are rejected with [`DomainError::UnknownDomainInProposal`].
    /// Domains absent from `threshold_updates` retain their existing threshold.
    /// An empty map returns a structurally identical clone (no change).
    pub fn with_threshold_updates(
        &self,
        threshold_updates: &BTreeMap<DomainId, ReconstructionThreshold>,
    ) -> Result<DomainRegistry, Error> {
        for id in threshold_updates.keys() {
            if !self.domains.iter().any(|d| d.id == *id) {
                return Err(DomainError::UnknownDomainInProposal { domain_id: *id }.into());
            }
        }
        let domains: Vec<DomainConfig> = self
            .domains
            .iter()
            .map(|d| {
                let reconstruction_threshold = threshold_updates
                    .get(&d.id)
                    .copied()
                    .unwrap_or(d.reconstruction_threshold);
                DomainConfig {
                    reconstruction_threshold,
                    ..d.clone()
                }
            })
            .collect();
        Ok(DomainRegistry {
            domains,
            next_domain_id: self.next_domain_id,
        })
    }
}

/// Tracks votes to add domains. Each participant can at any given time vote for a list of domains
/// to add.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddDomainsVotes {
    pub(crate) proposal_by_account: BTreeMap<AuthenticatedParticipantId, Vec<DomainConfig>>,
}

impl AddDomainsVotes {
    /// Votes for the proposal, returning the total number of voters so far who
    /// have proposed the exact same domains to add.
    /// If the participant had voted already, this replaces the existing vote.
    pub fn vote(
        &mut self,
        proposal: Vec<DomainConfig>,
        participant: &AuthenticatedParticipantId,
    ) -> u64 {
        if self
            .proposal_by_account
            .insert(participant.clone(), proposal.clone())
            .is_some()
        {
            log!("removed old vote for signer");
        }
        let total = self
            .proposal_by_account
            .values()
            .filter(|&prop| prop == &proposal)
            .count() as u64;
        log!("total votes for proposal: {}", total);
        total
    }

    /// Filters out existing votes no longer in the participant set
    pub fn get_remaining_votes(&self, participants: &Participants) -> Self {
        let remaining_votes = self
            .proposal_by_account
            .iter()
            .filter(|&(participant_id, _vote)| {
                participants.is_participant_given_participant_id(&participant_id.get())
            })
            .map(|(participant_id, vote)| (participant_id.clone(), vote.clone()))
            .collect();
        AddDomainsVotes {
            proposal_by_account: remaining_votes,
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
pub mod tests {
    use super::{
        AddDomainsVotes, Curve, DomainConfig, DomainId, DomainPurpose, DomainRegistry, Protocol,
        is_valid_protocol_for_purpose, validate_domain_purpose,
    };
    use crate::primitives::test_utils::{
        gen_authenticated_participants, gen_participants, infer_purpose_from_protocol,
    };
    use near_mpc_contract_interface::types::ReconstructionThreshold;
    use rstest::rstest;
    use std::collections::BTreeMap;

    #[test]
    fn test_add_domains() {
        let registry = DomainRegistry::default();
        let domains1 = vec![
            DomainConfig {
                id: DomainId(0),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(1),
                protocol: Protocol::Frost,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
        ];
        let new_registry = registry.add_domains(domains1.clone()).unwrap();
        assert_eq!(new_registry.domains, domains1);

        let domains2 = vec![
            DomainConfig {
                id: DomainId(2),
                protocol: Protocol::ConfidentialKeyDerivation,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::CKD,
            },
            DomainConfig {
                id: DomainId(3),
                protocol: Protocol::DamgardEtAl,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
        ];
        let new_registry = new_registry.add_domains(domains2.clone()).unwrap();
        assert_eq!(&new_registry.domains[0..2], &domains1);
        assert_eq!(&new_registry.domains[2..4], &domains2);

        // This fails because the domain ID does not start from next_domain_id.
        let domains3 = vec![DomainConfig {
            id: DomainId(5),
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(2),
            purpose: DomainPurpose::Sign,
        }];
        let _ = new_registry.add_domains(domains3).unwrap_err();

        // This fails because the domain IDs are not sorted.
        let domains4 = vec![
            DomainConfig {
                id: DomainId(5),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(4),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
        ];
        let _ = new_registry.add_domains(domains4).unwrap_err();
    }

    #[test]
    fn test_retain_domains() {
        let expected = vec![
            DomainConfig {
                id: DomainId(0),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(2),
                protocol: Protocol::Frost,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(3),
                protocol: Protocol::ConfidentialKeyDerivation,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::CKD,
            },
            DomainConfig {
                id: DomainId(4),
                protocol: Protocol::DamgardEtAl,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
        ];
        let mut registry = DomainRegistry::from_raw_validated(expected.clone(), 6).unwrap();
        assert_eq!(registry.domains, expected);
        assert_eq!(registry.next_domain_id, 6);
        registry.retain_domains(3);
        assert_eq!(registry.domains, expected[0..3]);
        assert_eq!(registry.next_domain_id, 6);
        registry.retain_domains(2);
        assert_eq!(registry.domains, expected[0..2]);
        assert_eq!(registry.next_domain_id, 6);
        registry.retain_domains(0);
        assert_eq!(registry.domains, Vec::new());
        assert_eq!(registry.next_domain_id, 6);
    }

    #[test]
    fn test_most_recent_domain_for_curve() {
        let registry = DomainRegistry::from_raw_validated(
            vec![
                DomainConfig {
                    id: DomainId(0),
                    protocol: Protocol::CaitSith,
                    reconstruction_threshold: ReconstructionThreshold::new(2),
                    purpose: DomainPurpose::Sign,
                },
                DomainConfig {
                    id: DomainId(2),
                    protocol: Protocol::Frost,
                    reconstruction_threshold: ReconstructionThreshold::new(2),
                    purpose: DomainPurpose::Sign,
                },
                DomainConfig {
                    id: DomainId(3),
                    protocol: Protocol::CaitSith,
                    reconstruction_threshold: ReconstructionThreshold::new(2),
                    purpose: DomainPurpose::Sign,
                },
            ],
            6,
        )
        .unwrap();
        assert_eq!(
            registry.most_recent_domain_for_curve(Curve::Secp256k1),
            Some(DomainId(3))
        );
        assert_eq!(
            registry.most_recent_domain_for_curve(Curve::Edwards25519),
            Some(DomainId(2))
        );
    }

    #[rstest]
    #[case(Protocol::CaitSith, DomainPurpose::Sign)]
    #[case(Protocol::Frost, DomainPurpose::Sign)]
    #[case(Protocol::DamgardEtAl, DomainPurpose::Sign)]
    #[case(Protocol::ConfidentialKeyDerivation, DomainPurpose::CKD)]
    fn test_infer_purpose_from_protocol(
        #[case] protocol: Protocol,
        #[case] expected: DomainPurpose,
    ) {
        assert_eq!(infer_purpose_from_protocol(protocol), expected);
    }

    #[rstest]
    // Valid combinations
    #[case(DomainPurpose::Sign, Protocol::CaitSith, true)]
    #[case(DomainPurpose::Sign, Protocol::DamgardEtAl, true)]
    #[case(DomainPurpose::Sign, Protocol::Frost, true)]
    #[case(DomainPurpose::ForeignTx, Protocol::CaitSith, true)]
    #[case(DomainPurpose::CKD, Protocol::ConfidentialKeyDerivation, true)]
    // Invalid combinations
    #[case(DomainPurpose::Sign, Protocol::ConfidentialKeyDerivation, false)]
    #[case(DomainPurpose::ForeignTx, Protocol::Frost, false)]
    #[case(DomainPurpose::ForeignTx, Protocol::ConfidentialKeyDerivation, false)]
    #[case(DomainPurpose::ForeignTx, Protocol::DamgardEtAl, false)]
    #[case(DomainPurpose::CKD, Protocol::CaitSith, false)]
    fn test_valid_protocol_purpose_combinations(
        #[case] purpose: DomainPurpose,
        #[case] protocol: Protocol,
        #[case] expected: bool,
    ) {
        assert_eq!(is_valid_protocol_for_purpose(purpose, protocol), expected);
    }

    #[rstest]
    #[case(Protocol::CaitSith, DomainPurpose::Sign, true)]
    #[case(Protocol::CaitSith, DomainPurpose::ForeignTx, true)]
    #[case(Protocol::DamgardEtAl, DomainPurpose::Sign, true)]
    #[case(Protocol::Frost, DomainPurpose::Sign, true)]
    #[case(Protocol::ConfidentialKeyDerivation, DomainPurpose::CKD, true)]
    #[case(Protocol::DamgardEtAl, DomainPurpose::ForeignTx, false)]
    #[case(Protocol::Frost, DomainPurpose::ForeignTx, false)]
    #[case(Protocol::ConfidentialKeyDerivation, DomainPurpose::Sign, false)]
    #[case(Protocol::CaitSith, DomainPurpose::CKD, false)]
    fn test_validate_domain_purpose(
        #[case] protocol: Protocol,
        #[case] purpose: DomainPurpose,
        #[case] expected_ok: bool,
    ) {
        let domain = DomainConfig {
            id: DomainId(0),
            protocol,
            reconstruction_threshold: ReconstructionThreshold::new(2),
            purpose,
        };
        assert_eq!(validate_domain_purpose(&domain).is_ok(), expected_ok);
    }

    fn sample_proposal() -> Vec<DomainConfig> {
        vec![DomainConfig {
            id: DomainId(0),
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(2),
            purpose: DomainPurpose::Sign,
        }]
    }

    #[test]
    fn test_get_remaining_votes_empty_votes() {
        // Given
        let votes = AddDomainsVotes::default();
        let participants = gen_participants(3);

        // When
        let remaining = votes.get_remaining_votes(&participants);

        // Then
        assert_eq!(remaining, AddDomainsVotes::default());
    }

    #[test]
    fn test_get_remaining_votes_all_voters_still_participants() {
        // Given
        let (participants, auth_ids) = gen_authenticated_participants(3);
        let proposal = sample_proposal();
        let mut votes = AddDomainsVotes::default();
        for auth_id in &auth_ids {
            votes.vote(proposal.clone(), auth_id);
        }

        // When
        let remaining = votes.get_remaining_votes(&participants);

        // Then
        assert_eq!(remaining, votes);
    }

    #[test]
    fn test_get_remaining_votes_some_voters_removed() {
        // Given
        let (participants, auth_ids) = gen_authenticated_participants(3);
        let proposal = sample_proposal();
        let mut votes = AddDomainsVotes::default();
        for auth_id in &auth_ids {
            votes.vote(proposal.clone(), auth_id);
        }

        // When
        let smaller_participants = participants.subset(0..1);
        let remaining = votes.get_remaining_votes(&smaller_participants);

        // Then
        assert_eq!(remaining.proposal_by_account.len(), 1);
        assert!(remaining.proposal_by_account.contains_key(&auth_ids[0]));
    }

    #[test]
    fn test_get_remaining_votes_all_voters_removed() {
        // Given
        let (_, auth_ids) = gen_authenticated_participants(3);
        let proposal = sample_proposal();
        let mut votes = AddDomainsVotes::default();
        for auth_id in &auth_ids {
            votes.vote(proposal.clone(), auth_id);
        }

        // When
        let empty_participants = gen_participants(0);
        let remaining = votes.get_remaining_votes(&empty_participants);

        // Then
        assert_eq!(remaining, AddDomainsVotes::default());
    }

    #[test]
    fn test_get_remaining_votes_preserves_different_proposals() {
        // Given
        let (participants, auth_ids) = gen_authenticated_participants(3);
        let proposal_a = vec![DomainConfig {
            id: DomainId(0),
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(2),
            purpose: DomainPurpose::Sign,
        }];
        let proposal_b = vec![DomainConfig {
            id: DomainId(0),
            protocol: Protocol::Frost,
            reconstruction_threshold: ReconstructionThreshold::new(2),
            purpose: DomainPurpose::Sign,
        }];
        let mut votes = AddDomainsVotes::default();
        votes.vote(proposal_a.clone(), &auth_ids[0]);
        votes.vote(proposal_b.clone(), &auth_ids[1]);
        votes.vote(proposal_a.clone(), &auth_ids[2]);

        // When
        let subset = participants.subset(0..2);
        let remaining = votes.get_remaining_votes(&subset);

        // Then
        assert_eq!(remaining.proposal_by_account.len(), 2);
        assert_eq!(remaining.proposal_by_account[&auth_ids[0]], proposal_a);
        assert_eq!(remaining.proposal_by_account[&auth_ids[1]], proposal_b);
    }

    fn registry_of(domains: Vec<DomainConfig>) -> DomainRegistry {
        let next_domain_id = domains.iter().map(|d| d.id.0).max().map_or(0, |m| m + 1);
        DomainRegistry::from_raw_validated(domains, next_domain_id).unwrap()
    }

    #[test]
    fn with_threshold_updates__should_be_identity_when_updates_is_empty() {
        // Given a non-empty registry and no threshold updates
        let registry = registry_of(vec![
            DomainConfig {
                id: DomainId(0),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(3),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(1),
                protocol: Protocol::Frost,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
        ]);
        let threshold_updates = BTreeMap::new();

        // When applying the threshold updates
        let result = registry.with_threshold_updates(&threshold_updates).unwrap();

        // Then the registry is structurally identical
        assert_eq!(result, registry);
    }

    #[test]
    fn with_threshold_updates__should_apply_per_domain_updates() {
        // Given a registry with two domains and threshold updates targeting one
        let registry = registry_of(vec![
            DomainConfig {
                id: DomainId(0),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(3),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(1),
                protocol: Protocol::Frost,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
        ]);
        let mut threshold_updates = BTreeMap::new();
        threshold_updates.insert(DomainId(0), ReconstructionThreshold::new(5));

        // When applying the threshold updates
        let result = registry.with_threshold_updates(&threshold_updates).unwrap();

        // Then only the targeted domain's threshold changes
        assert_eq!(
            result.domains()[0].reconstruction_threshold,
            ReconstructionThreshold::new(5)
        );
        assert_eq!(
            result.domains()[1].reconstruction_threshold,
            ReconstructionThreshold::new(2)
        );
    }

    #[test]
    fn with_threshold_updates__should_reject_unknown_domain_id() {
        // Given a registry with one domain and a threshold update referencing a different ID
        let registry = registry_of(vec![DomainConfig {
            id: DomainId(0),
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(3),
            purpose: DomainPurpose::Sign,
        }]);
        let mut threshold_updates = BTreeMap::new();
        threshold_updates.insert(DomainId(42), ReconstructionThreshold::new(5));

        // When applying the threshold updates
        let err = registry
            .with_threshold_updates(&threshold_updates)
            .unwrap_err();

        // Then unknown-domain guard rejects
        assert!(
            err.to_string().contains("not in the current registry"),
            "Expected UnknownDomainInProposal, got: {err}"
        );
    }

    #[test]
    fn with_threshold_updates__should_accept_updates_that_diverge_caitsith_thresholds() {
        // Given a registry with two CaitSith domains sharing one threshold and
        // threshold updates that rewrite only one of them to a different value.
        let registry = registry_of(vec![
            DomainConfig {
                id: DomainId(0),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(3),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(1),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(3),
                purpose: DomainPurpose::Sign,
            },
        ]);
        let mut threshold_updates = BTreeMap::new();
        threshold_updates.insert(DomainId(0), ReconstructionThreshold::new(5));

        // When applying the threshold updates
        let result = registry.with_threshold_updates(&threshold_updates).unwrap();

        // Then CaitSith domains may carry independent thresholds.
        assert_eq!(
            result.domains()[0].reconstruction_threshold,
            ReconstructionThreshold::new(5)
        );
        assert_eq!(
            result.domains()[1].reconstruction_threshold,
            ReconstructionThreshold::new(3)
        );
    }

    #[test]
    fn with_threshold_updates__should_accept_updates_that_keep_caitsith_thresholds_uniform() {
        // Given two CaitSith domains and a Frost domain, with threshold updates
        // that move both CaitSith domains to the same new threshold.
        let registry = registry_of(vec![
            DomainConfig {
                id: DomainId(0),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(3),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(1),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(3),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(2),
                protocol: Protocol::Frost,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
        ]);
        let mut threshold_updates = BTreeMap::new();
        threshold_updates.insert(DomainId(0), ReconstructionThreshold::new(5));
        threshold_updates.insert(DomainId(1), ReconstructionThreshold::new(5));

        // When applying the threshold updates
        let result = registry.with_threshold_updates(&threshold_updates).unwrap();

        // Then both CaitSith domains move together and Frost is untouched
        assert_eq!(
            result.domains()[0].reconstruction_threshold,
            ReconstructionThreshold::new(5)
        );
        assert_eq!(
            result.domains()[1].reconstruction_threshold,
            ReconstructionThreshold::new(5)
        );
        assert_eq!(
            result.domains()[2].reconstruction_threshold,
            ReconstructionThreshold::new(2)
        );
    }
}
