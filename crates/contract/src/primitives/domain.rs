use super::key_state::AuthenticatedParticipantId;
use crate::errors::{DomainError, Error};
use crate::primitives::participants::Participants;
use crate::primitives::proposal_hash::{Borsh, ProposalHash, Sha256, ToProposalHash};
use crate::primitives::thresholds::{GovernanceThreshold, GovernanceThresholdParameters};
use crate::primitives::votes::Votes;
use crate::storage_keys::StorageKey;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, ParticipantCount, Protocol, ReconstructionThreshold,
};
use near_sdk::near;
use std::collections::{BTreeMap, BTreeSet};

/// Lower bound on a domain's reconstruction threshold. `t = 1` would mean a
/// single share is sufficient to reconstruct the secret, defeating the point
/// of threshold cryptography.
pub const MIN_RECONSTRUCTION_THRESHOLD: u64 = 2;

/// Returns whether the given protocol is valid for the given purpose.
pub fn is_valid_protocol_for_purpose(purpose: DomainPurpose, protocol: Protocol) -> bool {
    matches!(
        (purpose, protocol),
        (DomainPurpose::Sign, Protocol::CaitSith)
            | (DomainPurpose::Sign, Protocol::RobustEcdsa)
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

/// Validates `domains` against a participant set of `n = num_participants` governed at
/// `governance`: each domain's ReconstructionThreshold `t` satisfies `2 <= t <= n` and
/// [`Protocol::required_active_signers`]` <= n`, and `governance` meets the absolute and
/// relative bounds for `n` and is at least the largest `t` among them. Call this at every
/// point where the participant set, the GovernanceThreshold, or a ReconstructionThreshold
/// changes.
pub fn validate_domains_against_governance(
    domains: &[DomainConfig],
    num_participants: ParticipantCount,
    governance: GovernanceThreshold,
) -> Result<(), Error> {
    for domain in domains {
        validate_domain_reconstruction_threshold(domain, num_participants)?;
    }
    GovernanceThresholdParameters::validate_governance_against_reconstruction(
        num_participants,
        governance,
        max_reconstruction_threshold(domains),
    )
}

/// Validates the per-domain reconstruction threshold against the participant
/// count. Universal bound `2 <= t <= n` plus the per-scheme bound
/// [`Protocol::required_active_signers`]` <= n`.
fn validate_domain_reconstruction_threshold(
    domain: &DomainConfig,
    num_participants: ParticipantCount,
) -> Result<(), Error> {
    let t = domain.reconstruction_threshold.value();
    if t < MIN_RECONSTRUCTION_THRESHOLD {
        return Err(DomainError::ReconstructionThresholdTooLow.into());
    }
    if !domain.reconstruction_threshold.is_met_by(num_participants) {
        return Err(DomainError::ReconstructionThresholdExceedsParticipants {
            reconstruction_threshold: t,
            participants: num_participants,
        }
        .into());
    }
    let required = domain
        .protocol
        .required_active_signers(domain.reconstruction_threshold);
    if required > num_participants.value() {
        return Err(DomainError::InsufficientParticipantsForProtocol {
            protocol: domain.protocol,
            required,
            participants: num_participants,
        }
        .into());
    }
    Ok(())
}

/// The largest [`ReconstructionThreshold`] across `domains`, or `None` if there are none
/// (an empty set imposes no cross-domain lower bound on the GovernanceThreshold).
/// Feeds [`GovernanceThresholdParameters::validate_governance_against_reconstruction`](crate::primitives::thresholds::GovernanceThresholdParameters::validate_governance_against_reconstruction).
fn max_reconstruction_threshold(domains: &[DomainConfig]) -> Option<ReconstructionThreshold> {
    domains
        .iter()
        .map(|domain| domain.reconstruction_threshold)
        .max()
}

/// All the domains present in the contract, as well as the next domain ID which is kept to ensure
/// that we never reuse domain IDs. (Domains may be deleted in only one case: when we decided to
/// add domains but ultimately canceled that process.)
#[near(serializers=[borsh])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainRegistry {
    domains: Vec<DomainConfig>,
    next_domain_id: DomainId,
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
            id: self.next_domain_id,
            ..domain
        };
        self.next_domain_id = DomainId(
            self.next_domain_id
                .0
                .checked_add(1)
                .expect("domain id counter overflow"),
        );
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

    /// Constructs a DomainRegistry from its raw fields, but performing basic
    /// validation that the fields could've been produced by a valid
    /// sequence of add_domains and retain_domains calls. This is used for
    /// init_running and testing only.
    pub fn from_raw_validated(
        domains: Vec<DomainConfig>,
        next_domain_id: DomainId,
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
        if let Some(largest_domain_id) = registry.domains.last().map(|domain| domain.id)
            && largest_domain_id >= registry.next_domain_id
        {
            return Err(DomainError::InvalidDomains.into());
        }
        Ok(registry)
    }

    pub fn next_domain_id(&self) -> DomainId {
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

impl ToProposalHash for [DomainConfig] {
    type Serializer = Borsh;
    type Hasher = Sha256;
}

/// Votes to add domains, one per participant, stored by proposal hash.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct AddDomainsVotes(Votes<AuthenticatedParticipantId>);

impl Default for AddDomainsVotes {
    fn default() -> Self {
        Self(Votes::new(
            StorageKey::AddDomainsVotesByVoter,
            StorageKey::AddDomainsVotesByProposal,
        ))
    }
}

impl AddDomainsVotes {
    /// Registers `participant`'s vote for `domains`, replacing any existing vote. Returns `true`
    /// once every member of `participants` voted for `domains`.
    pub fn vote(
        &mut self,
        domains: &[DomainConfig],
        participant: AuthenticatedParticipantId,
        participants: &Participants,
    ) -> bool {
        let n_votes = self
            .0
            .vote(participant, domains.to_proposal_hash())
            .count_participants(participants);
        n_votes == participants.count()
    }

    /// Drops votes from accounts that are no longer in `participants`.
    pub fn retain(&mut self, participants: &Participants) {
        self.0.retain_votes(|p| participants.is_participant(p));
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn all(&self) -> BTreeMap<ProposalHash, BTreeSet<AuthenticatedParticipantId>> {
        self.0.all()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.all().is_empty()
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
pub mod tests {
    use super::{
        AddDomainsVotes, DomainConfig, DomainId, DomainPurpose, DomainRegistry, Protocol,
        is_valid_protocol_for_purpose, validate_domain_purpose,
        validate_domain_reconstruction_threshold,
    };
    use crate::errors::{DomainError, Error};
    use crate::primitives::proposal_hash::ToProposalHash;
    use crate::primitives::test_utils::{
        gen_authenticated_participants, gen_participants, infer_purpose_from_protocol,
    };
    use near_mpc_contract_interface::types::{ParticipantCount, ReconstructionThreshold};
    use rstest::rstest;
    use std::collections::{BTreeMap, BTreeSet};

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
                protocol: Protocol::RobustEcdsa,
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
                protocol: Protocol::RobustEcdsa,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            },
        ];
        let mut registry =
            DomainRegistry::from_raw_validated(expected.clone(), DomainId(6)).unwrap();
        assert_eq!(registry.domains, expected);
        assert_eq!(registry.next_domain_id, DomainId(6));
        registry.retain_domains(3);
        assert_eq!(registry.domains, expected[0..3]);
        assert_eq!(registry.next_domain_id, DomainId(6));
        registry.retain_domains(2);
        assert_eq!(registry.domains, expected[0..2]);
        assert_eq!(registry.next_domain_id, DomainId(6));
        registry.retain_domains(0);
        assert_eq!(registry.domains, Vec::new());
        assert_eq!(registry.next_domain_id, DomainId(6));
    }

    #[rstest]
    #[case(Protocol::CaitSith, DomainPurpose::Sign)]
    #[case(Protocol::Frost, DomainPurpose::Sign)]
    #[case(Protocol::RobustEcdsa, DomainPurpose::Sign)]
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
    #[case(DomainPurpose::Sign, Protocol::RobustEcdsa, true)]
    #[case(DomainPurpose::Sign, Protocol::Frost, true)]
    #[case(DomainPurpose::ForeignTx, Protocol::CaitSith, true)]
    #[case(DomainPurpose::CKD, Protocol::ConfidentialKeyDerivation, true)]
    // Invalid combinations
    #[case(DomainPurpose::Sign, Protocol::ConfidentialKeyDerivation, false)]
    #[case(DomainPurpose::ForeignTx, Protocol::Frost, false)]
    #[case(DomainPurpose::ForeignTx, Protocol::ConfidentialKeyDerivation, false)]
    #[case(DomainPurpose::ForeignTx, Protocol::RobustEcdsa, false)]
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
    #[case(Protocol::RobustEcdsa, DomainPurpose::Sign, true)]
    #[case(Protocol::Frost, DomainPurpose::Sign, true)]
    #[case(Protocol::ConfidentialKeyDerivation, DomainPurpose::CKD, true)]
    #[case(Protocol::RobustEcdsa, DomainPurpose::ForeignTx, false)]
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
    fn test_vote_accepts_once_every_participant_voted() {
        // Given
        let (participants, auth_ids) = gen_authenticated_participants(3);
        let proposal = sample_proposal();
        let mut votes = AddDomainsVotes::default();
        assert!(!votes.vote(&proposal, auth_ids[0].clone(), &participants));
        assert!(!votes.vote(&proposal, auth_ids[1].clone(), &participants));

        // When
        let accepted = votes.vote(&proposal, auth_ids[2].clone(), &participants);

        // Then
        assert!(accepted);
        assert!(!votes.is_empty());
    }

    #[test]
    fn test_vote_ignores_votes_from_dropped_participants() {
        // Given: a stale vote from a participant no longer in the set
        let (participants, auth_ids) = gen_authenticated_participants(3);
        let proposal = sample_proposal();
        let mut votes = AddDomainsVotes::default();
        votes.vote(&proposal, auth_ids[2].clone(), &participants);
        let current = participants.subset(0..2);

        // When / Then: only the current participants count towards acceptance
        assert!(!votes.vote(&proposal, auth_ids[0].clone(), &current));
        assert!(votes.vote(&proposal, auth_ids[1].clone(), &current));
    }

    #[test]
    fn test_retain_keeps_only_current_participants_votes() {
        // Given: three of four participants voted
        let (participants, auth_ids) = gen_authenticated_participants(4);
        let proposal = sample_proposal();
        let mut votes = AddDomainsVotes::default();
        for auth_id in &auth_ids[..3] {
            votes.vote(&proposal, auth_id.clone(), &participants);
        }

        // When
        votes.retain(&participants.subset(0..1));

        // Then
        assert_eq!(
            votes.all(),
            BTreeMap::from([(
                proposal.to_proposal_hash(),
                BTreeSet::from([auth_ids[0].clone()])
            )])
        );
    }

    #[test]
    fn test_retain_drops_all_votes_when_no_voter_remains() {
        // Given
        let (participants, auth_ids) = gen_authenticated_participants(4);
        let proposal = sample_proposal();
        let mut votes = AddDomainsVotes::default();
        for auth_id in &auth_ids[..3] {
            votes.vote(&proposal, auth_id.clone(), &participants);
        }

        // When
        votes.retain(&gen_participants(0));

        // Then
        assert!(votes.is_empty());
    }

    #[test]
    fn test_retain_preserves_different_proposals() {
        // Given
        let (participants, auth_ids) = gen_authenticated_participants(4);
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
        votes.vote(&proposal_a, auth_ids[0].clone(), &participants);
        votes.vote(&proposal_b, auth_ids[1].clone(), &participants);
        votes.vote(&proposal_a, auth_ids[2].clone(), &participants);

        // When
        votes.retain(&participants.subset(0..2));

        // Then
        assert_eq!(
            votes.all(),
            BTreeMap::from([
                (
                    proposal_a.to_proposal_hash(),
                    BTreeSet::from([auth_ids[0].clone()])
                ),
                (
                    proposal_b.to_proposal_hash(),
                    BTreeSet::from([auth_ids[1].clone()])
                ),
            ])
        );
    }

    fn registry_of(domains: Vec<DomainConfig>) -> DomainRegistry {
        let next_domain_id = DomainId(domains.iter().map(|d| d.id.0).max().map_or(0, |m| m + 1));
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

    fn sign_domain(protocol: Protocol, threshold: u64) -> DomainConfig {
        DomainConfig {
            id: DomainId(0),
            protocol,
            reconstruction_threshold: ReconstructionThreshold::new(threshold),
            purpose: DomainPurpose::Sign,
        }
    }

    #[test]
    fn validate_domain_reconstruction_threshold__should_accept_robust_ecdsa_at_required_signers_bound()
     {
        // Given t = 3, so RobustEcdsa requires 2t - 1 = 5 active signers
        let domain = sign_domain(Protocol::RobustEcdsa, 3);

        // When
        let result = validate_domain_reconstruction_threshold(&domain, ParticipantCount::new(5));

        // Then
        result.unwrap();
    }

    #[test]
    fn validate_domain_reconstruction_threshold__should_reject_robust_ecdsa_below_required_signers()
    {
        // Given t = 3 with only n = 4 participants, although t <= n holds
        let domain = sign_domain(Protocol::RobustEcdsa, 3);

        // When
        let err = validate_domain_reconstruction_threshold(&domain, ParticipantCount::new(4))
            .unwrap_err();

        // Then
        assert_eq!(
            err,
            Error::from(DomainError::InsufficientParticipantsForProtocol {
                protocol: Protocol::RobustEcdsa,
                required: 5,
                participants: ParticipantCount::new(4),
            })
        );
    }

    #[test]
    fn validate_domain_reconstruction_threshold__should_accept_cait_sith_when_threshold_equals_participants()
     {
        // Given t = n = 4, which RobustEcdsa would reject
        let domain = sign_domain(Protocol::CaitSith, 4);

        // When
        let result = validate_domain_reconstruction_threshold(&domain, ParticipantCount::new(4));

        // Then
        result.unwrap();
    }
}
