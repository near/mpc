use super::key_state::AuthenticatedParticipantId;
use super::votes::Votes;
use crate::errors::{DomainError, Error};
use derive_more::{Deref, From};
use near_sdk::near;
use std::fmt::Display;

pub use near_mpc_contract_interface::types::DomainPurpose;

/// Each domain corresponds to a specific root key in a specific signature scheme. There may be
/// multiple domains per signature scheme. The domain ID uniquely identifies a domain.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, From, Deref)]
pub struct DomainId(pub u64);

impl From<near_mpc_contract_interface::types::DomainId> for DomainId {
    fn from(id: near_mpc_contract_interface::types::DomainId) -> Self {
        Self(id.0)
    }
}

impl From<DomainId> for near_mpc_contract_interface::types::DomainId {
    fn from(id: DomainId) -> Self {
        Self(id.0)
    }
}

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

/// Elliptic curve used by a domain.
/// More curves may be added in the future. When adding new curves, both Borsh
/// *and* JSON serialization must be kept compatible.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    Secp256k1,
    Ed25519,
    Bls12381,
    V2Secp256k1, // Robust ECDSA
}

impl Default for Curve {
    fn default() -> Self {
        Self::Secp256k1
    }
}

/// Returns whether the given curve is valid for the given purpose.
pub fn is_valid_curve_for_purpose(purpose: DomainPurpose, curve: Curve) -> bool {
    matches!(
        (purpose, curve),
        (DomainPurpose::Sign, Curve::Secp256k1)
            | (DomainPurpose::Sign, Curve::V2Secp256k1)
            | (DomainPurpose::Sign, Curve::Ed25519)
            | (DomainPurpose::ForeignTx, Curve::Secp256k1)
            | (DomainPurpose::CKD, Curve::Bls12381)
    )
}

/// Describes the configuration of a domain: the domain ID and the curve it uses.
///
/// JSON deserialization accepts both `"scheme"` (legacy) and `"curve"` (new) field names.
/// Serialization outputs `"scheme"` for backward compatibility with the current contract.
/// After 3.8 is released the compat struct should be removed.
#[near(serializers=[borsh, json])]
#[serde(from = "DomainConfigCompat", into = "DomainConfigCompat")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainConfig {
    pub id: DomainId,
    pub curve: Curve,
    pub purpose: DomainPurpose,
}

/// JSON-only compatibility helper for [`DomainConfig`]:
/// - Deserializes both `"scheme"` (legacy) and `"curve"` (new) field names.
/// - Serializes as `"scheme"` for backward compatibility with the current contract.
///
/// After 3.8 is released this compat struct should be removed.
#[derive(serde::Serialize, serde::Deserialize)]
struct DomainConfigCompat {
    id: DomainId,
    #[serde(alias = "curve")]
    scheme: Curve,
    purpose: DomainPurpose,
}

impl From<DomainConfigCompat> for DomainConfig {
    fn from(value: DomainConfigCompat) -> Self {
        Self {
            id: value.id,
            curve: value.scheme,
            purpose: value.purpose,
        }
    }
}

impl From<DomainConfig> for DomainConfigCompat {
    fn from(value: DomainConfig) -> Self {
        Self {
            id: value.id,
            scheme: value.curve,
            purpose: value.purpose,
        }
    }
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
        registry.add_domain(Curve::Secp256k1, DomainPurpose::Sign);
        registry
    }

    /// Add a single domain with the given protocol and purpose, returning the DomainId of the
    /// added domain.
    fn add_domain(&mut self, curve: Curve, purpose: DomainPurpose) -> DomainId {
        let domain = DomainConfig {
            id: DomainId(self.next_domain_id),
            curve,
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
            let new_domain_id = new_registry.add_domain(domain.curve, domain.purpose);
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
pub type AddDomainsVotes = Votes<AuthenticatedParticipantId, Vec<DomainConfig>>;

#[cfg(test)]
pub mod tests {
    use super::{
        is_valid_curve_for_purpose, Curve, DomainConfig, DomainId, DomainPurpose, DomainRegistry,
    };
    use crate::primitives::participants::Participants;
    use crate::primitives::key_state::AuthenticatedParticipantId;
    use crate::primitives::test_utils::{
        gen_participant, gen_participants, infer_purpose_from_curve,
    };
    use crate::primitives::votes::Votes;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use rstest::rstest;

    type AddDomainsVotes = Votes<AuthenticatedParticipantId, Vec<DomainConfig>>;

    #[test]
    fn test_add_domains() {
        let registry = DomainRegistry::default();
        let domains1 = vec![
            DomainConfig {
                id: DomainId(0),
                curve: Curve::Secp256k1,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(1),
                curve: Curve::Ed25519,
                purpose: DomainPurpose::Sign,
            },
        ];
        let new_registry = registry.add_domains(domains1.clone()).unwrap();
        assert_eq!(new_registry.domains, domains1);

        let domains2 = vec![
            DomainConfig {
                id: DomainId(2),
                curve: Curve::Bls12381,
                purpose: DomainPurpose::CKD,
            },
            DomainConfig {
                id: DomainId(3),
                curve: Curve::V2Secp256k1,
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
            purpose: DomainPurpose::Sign,
        }];
        let _ = new_registry.add_domains(domains3).unwrap_err();

        // This fails because the domain IDs are not sorted.
        let domains4 = vec![
            DomainConfig {
                id: DomainId(5),
                curve: Curve::Secp256k1,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(4),
                curve: Curve::Secp256k1,
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
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(2),
                curve: Curve::Ed25519,
                purpose: DomainPurpose::Sign,
            },
            DomainConfig {
                id: DomainId(3),
                curve: Curve::Bls12381,
                purpose: DomainPurpose::CKD,
            },
            DomainConfig {
                id: DomainId(4),
                curve: Curve::V2Secp256k1,
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
                    purpose: DomainPurpose::Sign,
                },
                DomainConfig {
                    id: DomainId(2),
                    curve: Curve::Ed25519,
                    purpose: DomainPurpose::Sign,
                },
                DomainConfig {
                    id: DomainId(3),
                    curve: Curve::Secp256k1,
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
            registry.most_recent_domain_for_curve(Curve::Ed25519),
            Some(DomainId(2))
        );
    }

    #[test]
    fn test_serialization_format() {
        let domain_config = DomainConfig {
            id: DomainId(3),
            curve: Curve::Secp256k1,
            purpose: DomainPurpose::Sign,
        };
        // Serializes as "scheme" for backward compat; remove after 3.8 release.
        let json = serde_json::to_string(&domain_config).unwrap();
        assert_eq!(json, r#"{"id":3,"scheme":"Secp256k1","purpose":"Sign"}"#);

        let domain_config: DomainConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(domain_config.id, DomainId(3));
        assert_eq!(domain_config.curve, Curve::Secp256k1);
        assert_eq!(domain_config.purpose, DomainPurpose::Sign);
    }

    #[rstest]
    #[case(
        r#"{"id":3,"scheme":"Secp256k1","purpose":"Sign"}"#,
        Curve::Secp256k1,
        DomainPurpose::Sign
    )]
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
    fn test_deserialize_scheme_and_curve_keys(
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
    #[case(Curve::Ed25519, DomainPurpose::Sign)]
    #[case(Curve::V2Secp256k1, DomainPurpose::Sign)]
    #[case(Curve::Bls12381, DomainPurpose::CKD)]
    fn test_infer_purpose_from_curve(#[case] curve: Curve, #[case] expected: DomainPurpose) {
        assert_eq!(infer_purpose_from_curve(curve), expected);
    }

    #[rstest]
    // Valid combinations
    #[case(DomainPurpose::Sign, Curve::Secp256k1, true)]
    #[case(DomainPurpose::Sign, Curve::V2Secp256k1, true)]
    #[case(DomainPurpose::Sign, Curve::Ed25519, true)]
    #[case(DomainPurpose::ForeignTx, Curve::Secp256k1, true)]
    #[case(DomainPurpose::CKD, Curve::Bls12381, true)]
    // Invalid combinations
    #[case(DomainPurpose::Sign, Curve::Bls12381, false)]
    #[case(DomainPurpose::ForeignTx, Curve::Ed25519, false)]
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
            purpose: DomainPurpose::Sign,
        }]
    }

    #[test]
    fn test_retain_empty_votes() {
        // Given
        let mut votes = AddDomainsVotes::default();
        let participants = gen_participants(3);

        // When
        votes.retain(|v| participants.is_participant_given_participant_id(&v.get()));

        // Then
        assert_eq!(votes, AddDomainsVotes::default());
    }

    #[test]
    fn test_retain_all_voters_still_participants() {
        // Given
        let (participants, auth_ids) = setup_participants(3);
        let proposal = sample_proposal();
        let mut votes = AddDomainsVotes::default();
        for auth_id in &auth_ids {
            votes.vote(auth_id.clone(), proposal.clone());
        }
        let expected = votes.clone();

        // When
        votes.retain(|v| participants.is_participant_given_participant_id(&v.get()));

        // Then
        assert_eq!(votes, expected);
    }

    #[test]
    fn test_retain_some_voters_removed() {
        // Given
        let (participants, auth_ids) = setup_participants(3);
        let proposal = sample_proposal();
        let mut votes = AddDomainsVotes::default();
        for auth_id in &auth_ids {
            votes.vote(auth_id.clone(), proposal.clone());
        }

        // When
        let smaller_participants = participants.subset(0..1);
        votes.retain(|v| smaller_participants.is_participant_given_participant_id(&v.get()));

        // Then
        assert_eq!(votes.proposal_by_voter.len(), 1);
        assert!(votes.proposal_by_voter.contains_key(&auth_ids[0]));
    }

    #[test]
    fn test_retain_all_voters_removed() {
        // Given
        let (_, auth_ids) = setup_participants(3);
        let proposal = sample_proposal();
        let mut votes = AddDomainsVotes::default();
        for auth_id in &auth_ids {
            votes.vote(auth_id.clone(), proposal.clone());
        }

        // When
        let empty_participants = gen_participants(0);
        votes.retain(|v| empty_participants.is_participant_given_participant_id(&v.get()));

        // Then
        assert_eq!(votes, AddDomainsVotes::default());
    }

    #[test]
    fn test_retain_preserves_different_proposals() {
        // Given
        let (participants, auth_ids) = setup_participants(3);
        let proposal_a = vec![DomainConfig {
            id: DomainId(0),
            curve: Curve::Secp256k1,
            purpose: DomainPurpose::Sign,
        }];
        let proposal_b = vec![DomainConfig {
            id: DomainId(0),
            curve: Curve::Ed25519,
            purpose: DomainPurpose::Sign,
        }];
        let mut votes = AddDomainsVotes::default();
        votes.vote(auth_ids[0].clone(), proposal_a.clone());
        votes.vote(auth_ids[1].clone(), proposal_b.clone());
        votes.vote(auth_ids[2].clone(), proposal_a.clone());

        // When
        let subset = participants.subset(0..2);
        votes.retain(|v| subset.is_participant_given_participant_id(&v.get()));

        // Then
        assert_eq!(votes.proposal_by_voter.len(), 2);
        assert_eq!(votes.proposal_by_voter[&auth_ids[0]], proposal_a);
        assert_eq!(votes.proposal_by_voter[&auth_ids[1]], proposal_b);
    }
}
