use super::key_state::AuthenticatedParticipantId;
use crate::errors::{DomainError, Error};
use crate::primitives::participants::Participants;
use derive_more::{Deref, From};
use near_sdk::{log, near};
use std::collections::BTreeMap;
use std::fmt::Display;

pub use contract_interface::types::DomainPurpose;

/// Each domain corresponds to a specific root key in a specific signature scheme. There may be
/// multiple domains per signature scheme. The domain ID uniquely identifies a domain.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, From, Deref)]
pub struct DomainId(pub u64);

impl Default for DomainId {
    fn default() -> Self {
        Self::legacy_ecdsa_id()
    }
}

impl DomainId {
    /// Returns the DomainId of the single ECDSA key present in the contract before V2.
    pub fn legacy_ecdsa_id() -> Self {
        Self(0)
    }
}

impl Display for DomainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Uniquely identifies a specific request algorithm.
/// More protocols may be added in the future. When adding new protocols, both Borsh
/// *and* JSON serialization must be kept compatible.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    Secp256k1,
    Ed25519,
    Bls12381,
    V2Secp256k1, // Robust ECDSA
}

impl Default for SignatureScheme {
    fn default() -> Self {
        Self::Secp256k1
    }
}

/// Infer a default purpose from the signature scheme.
/// Used during migration from old state that lacks the `purpose` field.
pub fn infer_purpose_from_scheme(scheme: SignatureScheme) -> DomainPurpose {
    match scheme {
        SignatureScheme::Bls12381 => DomainPurpose::CKD,
        _ => DomainPurpose::Sign,
    }
}

/// Returns whether the given scheme is valid for the given purpose.
pub fn is_valid_scheme_for_purpose(purpose: DomainPurpose, scheme: SignatureScheme) -> bool {
    matches!(
        (purpose, scheme),
        (DomainPurpose::Sign, SignatureScheme::Secp256k1)
            | (DomainPurpose::Sign, SignatureScheme::V2Secp256k1)
            | (DomainPurpose::Sign, SignatureScheme::Ed25519)
            | (DomainPurpose::ForeignTx, SignatureScheme::Secp256k1)
            | (DomainPurpose::CKD, SignatureScheme::Bls12381)
    )
}

/// Describes the configuration of a domain: the domain ID and the protocol it uses.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainConfig {
    pub id: DomainId,
    pub scheme: SignatureScheme,
    pub purpose: DomainPurpose,
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
        registry.add_domain(SignatureScheme::Secp256k1, DomainPurpose::Sign);
        registry
    }

    /// Add a single domain with the given protocol and purpose, returning the DomainId of the
    /// added domain.
    fn add_domain(&mut self, scheme: SignatureScheme, purpose: DomainPurpose) -> DomainId {
        let domain = DomainConfig {
            id: DomainId(self.next_domain_id),
            scheme,
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
            let new_domain_id = new_registry.add_domain(domain.scheme, domain.purpose);
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
    pub fn most_recent_domain_for_protocol(&self, scheme: SignatureScheme) -> Option<DomainId> {
        self.domains
            .iter()
            .rev()
            .find(|domain| domain.scheme == scheme)
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
        infer_purpose_from_scheme, is_valid_scheme_for_purpose, AddDomainsVotes, DomainConfig,
        DomainId, DomainPurpose, DomainRegistry, Participants, SignatureScheme,
    };
    use crate::primitives::key_state::AuthenticatedParticipantId;
    use crate::primitives::test_utils::{gen_participant, gen_participants};
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use rstest::rstest;

    #[test]
    fn test_add_domains() {
        let registry = DomainRegistry::default();
        let domains1 = vec![
            DomainConfig {
                id: DomainId(0),
                scheme: SignatureScheme::Secp256k1,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(1),
                scheme: SignatureScheme::Ed25519,
                purpose: DomainPurpose::Sign,
            },
        ];
        let new_registry = registry.add_domains(domains1.clone()).unwrap();
        assert_eq!(new_registry.domains, domains1);

        let domains2 = vec![
            DomainConfig {
                id: DomainId(2),
                scheme: SignatureScheme::Bls12381,
                purpose: DomainPurpose::CKD,
            },
            DomainConfig {
                id: DomainId(3),
                scheme: SignatureScheme::V2Secp256k1,
                purpose: DomainPurpose::Sign,
            },
        ];
        let new_registry = new_registry.add_domains(domains2.clone()).unwrap();
        assert_eq!(&new_registry.domains[0..2], &domains1);
        assert_eq!(&new_registry.domains[2..4], &domains2);

        // This fails because the domain ID does not start from next_domain_id.
        let domains3 = vec![DomainConfig {
            id: DomainId(5),
            scheme: SignatureScheme::Secp256k1,
            purpose: DomainPurpose::Sign,
        }];
        let _ = new_registry.add_domains(domains3).unwrap_err();

        // This fails because the domain IDs are not sorted.
        let domains4 = vec![
            DomainConfig {
                id: DomainId(5),
                scheme: SignatureScheme::Secp256k1,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(4),
                scheme: SignatureScheme::Secp256k1,
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
                scheme: SignatureScheme::Secp256k1,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(2),
                scheme: SignatureScheme::Ed25519,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(3),
                scheme: SignatureScheme::Bls12381,
                purpose: DomainPurpose::CKD,
            },
            DomainConfig {
                id: DomainId(4),
                scheme: SignatureScheme::V2Secp256k1,
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
    fn test_most_recent_domain_for_signature_scheme() {
        let registry = DomainRegistry::from_raw_validated(
            vec![
                DomainConfig {
                    id: DomainId(0),
                    scheme: SignatureScheme::Secp256k1,
                    purpose: DomainPurpose::Sign,
                },
                DomainConfig {
                    id: DomainId(2),
                    scheme: SignatureScheme::Ed25519,
                    purpose: DomainPurpose::Sign,
                },
                DomainConfig {
                    id: DomainId(3),
                    scheme: SignatureScheme::Secp256k1,
                    purpose: DomainPurpose::Sign,
                },
            ],
            6,
        )
        .unwrap();
        assert_eq!(
            registry.most_recent_domain_for_protocol(SignatureScheme::Secp256k1),
            Some(DomainId(3))
        );
        assert_eq!(
            registry.most_recent_domain_for_protocol(SignatureScheme::Ed25519),
            Some(DomainId(2))
        );
    }

    #[test]
    fn test_serialization_format() {
        let domain_config = DomainConfig {
            id: DomainId(3),
            scheme: SignatureScheme::Secp256k1,
            purpose: DomainPurpose::Sign,
        };
        let json = serde_json::to_string(&domain_config).unwrap();
        assert_eq!(json, r#"{"id":3,"scheme":"Secp256k1","purpose":"Sign"}"#);

        let domain_config: DomainConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(domain_config.id, DomainId(3));
        assert_eq!(domain_config.scheme, SignatureScheme::Secp256k1);
        assert_eq!(domain_config.purpose, DomainPurpose::Sign);
    }

    #[rstest]
    #[case(SignatureScheme::Secp256k1, DomainPurpose::Sign)]
    #[case(SignatureScheme::Ed25519, DomainPurpose::Sign)]
    #[case(SignatureScheme::V2Secp256k1, DomainPurpose::Sign)]
    #[case(SignatureScheme::Bls12381, DomainPurpose::CKD)]
    fn test_infer_purpose_from_scheme(
        #[case] scheme: SignatureScheme,
        #[case] expected: DomainPurpose,
    ) {
        assert_eq!(infer_purpose_from_scheme(scheme), expected);
    }

    #[rstest]
    // Valid combinations
    #[case(DomainPurpose::Sign, SignatureScheme::Secp256k1, true)]
    #[case(DomainPurpose::Sign, SignatureScheme::V2Secp256k1, true)]
    #[case(DomainPurpose::Sign, SignatureScheme::Ed25519, true)]
    #[case(DomainPurpose::ForeignTx, SignatureScheme::Secp256k1, true)]
    #[case(DomainPurpose::CKD, SignatureScheme::Bls12381, true)]
    // Invalid combinations
    #[case(DomainPurpose::Sign, SignatureScheme::Bls12381, false)]
    #[case(DomainPurpose::ForeignTx, SignatureScheme::Ed25519, false)]
    #[case(DomainPurpose::ForeignTx, SignatureScheme::Bls12381, false)]
    #[case(DomainPurpose::ForeignTx, SignatureScheme::V2Secp256k1, false)]
    #[case(DomainPurpose::CKD, SignatureScheme::Secp256k1, false)]
    fn test_valid_scheme_purpose_combinations(
        #[case] purpose: DomainPurpose,
        #[case] scheme: SignatureScheme,
        #[case] expected: bool,
    ) {
        assert_eq!(is_valid_scheme_for_purpose(purpose, scheme), expected);
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
            scheme: SignatureScheme::Secp256k1,
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
            scheme: SignatureScheme::Secp256k1,
            purpose: DomainPurpose::Sign,
        }];
        let proposal_b = vec![DomainConfig {
            id: DomainId(0),
            scheme: SignatureScheme::Ed25519,
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
