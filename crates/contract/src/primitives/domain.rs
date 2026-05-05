use super::key_state::AuthenticatedParticipantId;
use crate::errors::{DomainError, Error};
use crate::primitives::participants::Participants;
use near_mpc_contract_interface::types::{Curve, DomainConfig, DomainId, DomainPurpose, Protocol};
use near_sdk::{log, near};
use std::collections::BTreeMap;

/// Returns whether the given curve is valid for the given purpose.
pub fn is_valid_curve_for_purpose(purpose: DomainPurpose, curve: Curve) -> bool {
    matches!(
        (purpose, curve),
        (DomainPurpose::Sign, Curve::Secp256k1)
            | (DomainPurpose::Sign, Curve::V2Secp256k1)
            | (DomainPurpose::Sign, Curve::Edwards25519)
            | (DomainPurpose::ForeignTx, Curve::Secp256k1)
            | (DomainPurpose::CKD, Curve::Bls12381)
    )
}

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

/// Validates that a `DomainConfig` is internally consistent:
///   - `curve` matches the curve derived from `protocol`, and
///   - `protocol` is allowed for the requested `purpose`.
///
/// The legacy `Curve::V2Secp256k1` value is accepted as a stand-in for
/// `(Secp256k1, DamgardEtAl)`.
// TODO(#2442): drop the V2Secp256k1 carve-out once that variant is removed
// from `Curve` in the next PR.
pub fn validate_domain_consistency(domain: &DomainConfig) -> Result<(), Error> {
    let expected = Curve::from(domain.protocol);
    let curve_ok = domain.curve == expected
        || (domain.curve == Curve::V2Secp256k1 && domain.protocol == Protocol::DamgardEtAl);
    if !curve_ok {
        return Err(DomainError::InconsistentCurveProtocol {
            curve: domain.curve,
            protocol: domain.protocol,
            expected,
        }
        .into());
    }
    if !is_valid_protocol_for_purpose(domain.purpose, domain.protocol) {
        return Err(DomainError::InvalidProtocolPurposeCombination {
            protocol: domain.protocol,
            purpose: domain.purpose,
        }
        .into());
    }
    Ok(())
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

    /// Migration from legacy: creates a DomainRegistry with a single ecdsa key.
    pub fn new_single_ecdsa_key_from_legacy() -> Self {
        let mut registry = Self::default();
        registry.add_domain(Curve::Secp256k1, Protocol::CaitSith, DomainPurpose::Sign);
        registry
    }

    /// Append a domain at `next_domain_id`, returning its DomainId. The caller is
    /// responsible for any validation (curve/protocol consistency, etc.); this
    /// helper does no checks.
    fn add_domain(&mut self, curve: Curve, protocol: Protocol, purpose: DomainPurpose) -> DomainId {
        let domain = DomainConfig {
            id: DomainId(self.next_domain_id),
            curve,
            protocol,
            purpose,
        };
        self.next_domain_id += 1;
        self.domains.push(domain.clone());
        domain.id
    }

    /// Processes the addition of the given domains, returning a new DomainRegistry.
    /// This stringently requires that the domains specified have sorted and contiguous IDs starting
    /// from next_domain_id, returning an error otherwise.
    pub fn add_domains(&self, domains: Vec<DomainConfig>) -> Result<DomainRegistry, Error> {
        let mut new_registry = self.clone();
        for domain in domains {
            validate_domain_consistency(&domain)?;
            let new_domain_id =
                new_registry.add_domain(domain.curve, domain.protocol, domain.purpose);
            if new_domain_id != domain.id {
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

    /// Returns the most recently added domain for the given protocol,
    /// or None if no such domain exists.
    pub fn most_recent_domain_for_curve(&self, curve: Curve) -> Option<DomainId> {
        self.domains
            .iter()
            .rev()
            .find(|domain| domain.curve == curve)
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
            validate_domain_consistency(domain)?;
        }
        for (left, right) in registry.domains.iter().zip(registry.domains.iter().skip(1)) {
            if left.id.0 >= right.id.0 {
                return Err(DomainError::InvalidDomains.into());
            }
        }
        if let Some(largest_domain_id) = registry.domains.last().map(|domain| domain.id.0) {
            if largest_domain_id >= registry.next_domain_id {
                return Err(DomainError::InvalidDomains.into());
            }
        }
        Ok(registry)
    }

    pub fn next_domain_id(&self) -> u64 {
        self.next_domain_id
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
pub mod tests {
    use super::{
        is_valid_curve_for_purpose, is_valid_protocol_for_purpose, validate_domain_consistency,
        AddDomainsVotes, Curve, DomainConfig, DomainId, DomainPurpose, DomainRegistry,
        Participants, Protocol,
    };
    use crate::primitives::key_state::AuthenticatedParticipantId;
    use crate::primitives::test_utils::{
        gen_participant, gen_participants, infer_purpose_from_curve,
    };
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use rstest::rstest;

    #[test]
    fn test_add_domains() {
        let registry = DomainRegistry::default();
        let domains1 = vec![
            DomainConfig {
                id: DomainId(0),
                curve: Curve::Secp256k1,
                protocol: Protocol::from(Curve::Secp256k1),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(1),
                curve: Curve::Edwards25519,
                protocol: Protocol::from(Curve::Edwards25519),
                purpose: DomainPurpose::Sign,
            },
        ];
        let new_registry = registry.add_domains(domains1.clone()).unwrap();
        assert_eq!(new_registry.domains, domains1);

        let domains2 = vec![
            DomainConfig {
                id: DomainId(2),
                curve: Curve::Bls12381,
                protocol: Protocol::from(Curve::Bls12381),
                purpose: DomainPurpose::CKD,
            },
            DomainConfig {
                id: DomainId(3),
                curve: Curve::V2Secp256k1,
                protocol: Protocol::from(Curve::V2Secp256k1),
                purpose: DomainPurpose::Sign,
            },
        ];
        let new_registry = new_registry.add_domains(domains2.clone()).unwrap();
        assert_eq!(&new_registry.domains[0..2], &domains1);
        assert_eq!(&new_registry.domains[2..4], &domains2);

        // This fails because the domain ID does not start from next_domain_id.
        let domains3 = vec![DomainConfig {
            id: DomainId(5),
            curve: Curve::Secp256k1,
            protocol: Protocol::from(Curve::Secp256k1),
            purpose: DomainPurpose::Sign,
        }];
        let _ = new_registry.add_domains(domains3).unwrap_err();

        // This fails because the domain IDs are not sorted.
        let domains4 = vec![
            DomainConfig {
                id: DomainId(5),
                curve: Curve::Secp256k1,
                protocol: Protocol::from(Curve::Secp256k1),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(4),
                curve: Curve::Secp256k1,
                protocol: Protocol::from(Curve::Secp256k1),
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
                curve: Curve::Secp256k1,
                protocol: Protocol::from(Curve::Secp256k1),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(2),
                curve: Curve::Edwards25519,
                protocol: Protocol::from(Curve::Edwards25519),
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(3),
                curve: Curve::Bls12381,
                protocol: Protocol::from(Curve::Bls12381),
                purpose: DomainPurpose::CKD,
            },
            DomainConfig {
                id: DomainId(4),
                curve: Curve::V2Secp256k1,
                protocol: Protocol::from(Curve::V2Secp256k1),
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
                    curve: Curve::Secp256k1,
                    protocol: Protocol::from(Curve::Secp256k1),
                    purpose: DomainPurpose::Sign,
                },
                DomainConfig {
                    id: DomainId(2),
                    curve: Curve::Edwards25519,
                    protocol: Protocol::from(Curve::Edwards25519),
                    purpose: DomainPurpose::Sign,
                },
                DomainConfig {
                    id: DomainId(3),
                    curve: Curve::Secp256k1,
                    protocol: Protocol::from(Curve::Secp256k1),
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
    #[case(
        r#"{"id":3,"curve":"Secp256k1","purpose":"Sign"}"#,
        Curve::Secp256k1,
        DomainPurpose::Sign
    )]
    #[case(
        r#"{"id":1,"curve":"Bls12381","purpose":"CKD"}"#,
        Curve::Bls12381,
        DomainPurpose::CKD
    )]
    #[case(
        r#"{"id":1,"curve":"Edwards25519","purpose":"Sign"}"#,
        Curve::Edwards25519,
        DomainPurpose::Sign
    )]
    fn test_deserialize_domain_config(
        #[case] json: &str,
        #[case] expected_curve: Curve,
        #[case] expected_purpose: DomainPurpose,
    ) {
        let config: DomainConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.curve, expected_curve);
        assert_eq!(config.purpose, expected_purpose);
    }

    #[rstest]
    #[case(Curve::Secp256k1, DomainPurpose::Sign)]
    #[case(Curve::Edwards25519, DomainPurpose::Sign)]
    #[case(Curve::V2Secp256k1, DomainPurpose::Sign)]
    #[case(Curve::Bls12381, DomainPurpose::CKD)]
    fn test_infer_purpose_from_curve(#[case] curve: Curve, #[case] expected: DomainPurpose) {
        assert_eq!(infer_purpose_from_curve(curve), expected);
    }

    #[rstest]
    // Valid combinations
    #[case(DomainPurpose::Sign, Curve::Secp256k1, true)]
    #[case(DomainPurpose::Sign, Curve::V2Secp256k1, true)]
    #[case(DomainPurpose::Sign, Curve::Edwards25519, true)]
    #[case(DomainPurpose::ForeignTx, Curve::Secp256k1, true)]
    #[case(DomainPurpose::CKD, Curve::Bls12381, true)]
    // Invalid combinations
    #[case(DomainPurpose::Sign, Curve::Bls12381, false)]
    #[case(DomainPurpose::ForeignTx, Curve::Edwards25519, false)]
    #[case(DomainPurpose::ForeignTx, Curve::Bls12381, false)]
    #[case(DomainPurpose::ForeignTx, Curve::V2Secp256k1, false)]
    #[case(DomainPurpose::CKD, Curve::Secp256k1, false)]
    fn test_valid_curve_purpose_combinations(
        #[case] purpose: DomainPurpose,
        #[case] curve: Curve,
        #[case] expected: bool,
    ) {
        assert_eq!(is_valid_curve_for_purpose(purpose, curve), expected);
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
    // Canonical pairings (curve consistent with protocol AND protocol allowed for purpose)
    #[case(Curve::Secp256k1, Protocol::CaitSith, DomainPurpose::Sign, true)]
    #[case(Curve::Secp256k1, Protocol::CaitSith, DomainPurpose::ForeignTx, true)]
    #[case(Curve::Secp256k1, Protocol::DamgardEtAl, DomainPurpose::Sign, true)]
    #[case(Curve::Edwards25519, Protocol::Frost, DomainPurpose::Sign, true)]
    #[case(
        Curve::Bls12381,
        Protocol::ConfidentialKeyDerivation,
        DomainPurpose::CKD,
        true
    )]
    // Legacy: V2Secp256k1 stands in for (Secp256k1, DamgardEtAl) until V2 is removed.
    #[case(Curve::V2Secp256k1, Protocol::DamgardEtAl, DomainPurpose::Sign, true)]
    // Curve/protocol mismatches
    #[case(Curve::Secp256k1, Protocol::Frost, DomainPurpose::Sign, false)]
    #[case(Curve::Edwards25519, Protocol::CaitSith, DomainPurpose::Sign, false)]
    #[case(Curve::Bls12381, Protocol::DamgardEtAl, DomainPurpose::Sign, false)]
    #[case(Curve::V2Secp256k1, Protocol::CaitSith, DomainPurpose::Sign, false)]
    // Protocol/purpose mismatches (curve/protocol consistent, but protocol not allowed for purpose)
    #[case(
        Curve::Secp256k1,
        Protocol::DamgardEtAl,
        DomainPurpose::ForeignTx,
        false
    )]
    #[case(Curve::Edwards25519, Protocol::Frost, DomainPurpose::ForeignTx, false)]
    #[case(
        Curve::Bls12381,
        Protocol::ConfidentialKeyDerivation,
        DomainPurpose::Sign,
        false
    )]
    #[case(Curve::Secp256k1, Protocol::CaitSith, DomainPurpose::CKD, false)]
    fn test_domain_consistency(
        #[case] curve: Curve,
        #[case] protocol: Protocol,
        #[case] purpose: DomainPurpose,
        #[case] expected_ok: bool,
    ) {
        let domain = DomainConfig {
            id: DomainId(0),
            curve,
            protocol,
            purpose,
        };
        assert_eq!(validate_domain_consistency(&domain).is_ok(), expected_ok);
    }

    fn setup_participants(n: usize) -> (Participants, Vec<AuthenticatedParticipantId>) {
        let mut participants = Participants::new();
        let mut accounts = Vec::new();
        for i in 0..n {
            let (account_id, info) = gen_participant(i);
            accounts.push(account_id.clone());
            participants.insert(account_id, info).unwrap();
        }
        let mut auth_ids = Vec::new();
        for account_id in &accounts {
            let mut ctx = VMContextBuilder::new();
            ctx.signer_account_id(account_id.clone());
            testing_env!(ctx.build());
            auth_ids.push(AuthenticatedParticipantId::new(&participants).unwrap());
        }
        (participants, auth_ids)
    }

    fn sample_proposal() -> Vec<DomainConfig> {
        vec![DomainConfig {
            id: DomainId(0),
            curve: Curve::Secp256k1,
            protocol: Protocol::from(Curve::Secp256k1),
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
        let (participants, auth_ids) = setup_participants(3);
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
        let (participants, auth_ids) = setup_participants(3);
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
        let (_, auth_ids) = setup_participants(3);
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
        let (participants, auth_ids) = setup_participants(3);
        let proposal_a = vec![DomainConfig {
            id: DomainId(0),
            curve: Curve::Secp256k1,
            protocol: Protocol::from(Curve::Secp256k1),
            purpose: DomainPurpose::Sign,
        }];
        let proposal_b = vec![DomainConfig {
            id: DomainId(0),
            curve: Curve::Edwards25519,
            protocol: Protocol::from(Curve::Edwards25519),
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
}
