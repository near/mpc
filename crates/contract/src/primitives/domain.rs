use super::key_state::AuthenticatedParticipantId;
use crate::errors::{DomainError, Error};
pub use contract_interface::types::DomainPurpose;
use derive_more::{Deref, From};
use near_sdk::{log, near};
use std::collections::BTreeMap;
use std::fmt::Display;

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

pub trait InferFromScheme {
    fn infer_from_scheme(scheme: SignatureScheme) -> Self;
}

impl InferFromScheme for DomainPurpose {
    fn infer_from_scheme(scheme: SignatureScheme) -> Self {
        match scheme {
            SignatureScheme::Secp256k1
            | SignatureScheme::Ed25519
            | SignatureScheme::V2Secp256k1 => DomainPurpose::Sign,
            SignatureScheme::Bls12381 => DomainPurpose::CKD,
        }
    }
}

/// Describes the configuration of a domain: the domain ID and the protocol it uses.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainConfig {
    pub id: DomainId,
    pub scheme: SignatureScheme,
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
        registry.add_domain(SignatureScheme::Secp256k1);
        registry
    }

    /// Add a single domain with the given protocol, returning the DomainId of the added
    /// domain.
    fn add_domain(&mut self, scheme: SignatureScheme) -> DomainId {
        let domain = DomainConfig {
            id: DomainId(self.next_domain_id),
            scheme,
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
            let new_domain_id = new_registry.add_domain(domain.scheme);
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
    pub(crate) proposal_by_account:
        BTreeMap<AuthenticatedParticipantId, Vec<(DomainConfig, DomainPurpose)>>,
}

impl AddDomainsVotes {
    /// Votes for the proposal, returning the total number of voters so far who
    /// have proposed the exact same domains to add.
    /// If the participant had voted already, this replaces the existing vote.
    pub fn vote(
        &mut self,
        proposal: Vec<(DomainConfig, DomainPurpose)>,
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
}

#[cfg(test)]
pub mod tests {
    use super::{
        DomainConfig, DomainId, DomainPurpose, DomainRegistry, InferFromScheme, SignatureScheme,
    };

    #[test]
    fn test_add_domains() {
        let registry = DomainRegistry::default();
        let domains1 = vec![
            DomainConfig {
                id: DomainId(0),
                scheme: SignatureScheme::Secp256k1,
            },
            DomainConfig {
                id: DomainId(1),
                scheme: SignatureScheme::Ed25519,
            },
        ];
        let new_registry = registry.add_domains(domains1.clone()).unwrap();
        assert_eq!(new_registry.domains, domains1);

        let domains2 = vec![
            DomainConfig {
                id: DomainId(2),
                scheme: SignatureScheme::Bls12381,
            },
            DomainConfig {
                id: DomainId(3),
                scheme: SignatureScheme::V2Secp256k1,
            },
        ];
        let new_registry = new_registry.add_domains(domains2.clone()).unwrap();
        assert_eq!(&new_registry.domains[0..2], &domains1);
        assert_eq!(&new_registry.domains[2..4], &domains2);

        // This fails because the domain ID does not start from next_domain_id.
        let domains3 = vec![DomainConfig {
            id: DomainId(5),
            scheme: SignatureScheme::Secp256k1,
        }];
        let _ = new_registry.add_domains(domains3).unwrap_err();

        // This fails because the domain IDs are not sorted.
        let domains4 = vec![
            DomainConfig {
                id: DomainId(5),
                scheme: SignatureScheme::Secp256k1,
            },
            DomainConfig {
                id: DomainId(4),
                scheme: SignatureScheme::Secp256k1,
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
            },
            DomainConfig {
                id: DomainId(2),
                scheme: SignatureScheme::Ed25519,
            },
            DomainConfig {
                id: DomainId(3),
                scheme: SignatureScheme::Bls12381,
            },
            DomainConfig {
                id: DomainId(4),
                scheme: SignatureScheme::V2Secp256k1,
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
                },
                DomainConfig {
                    id: DomainId(2),
                    scheme: SignatureScheme::Ed25519,
                },
                DomainConfig {
                    id: DomainId(3),
                    scheme: SignatureScheme::Secp256k1,
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
        };
        let json = serde_json::to_string(&domain_config).unwrap();
        assert_eq!(json, r#"{"id":3,"scheme":"Secp256k1"}"#);

        let domain_config: DomainConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(domain_config.id, DomainId(3));
        assert_eq!(domain_config.scheme, SignatureScheme::Secp256k1);
    }

    #[test]
    fn test_infer_domain_purpose_from_scheme() {
        assert_eq!(
            DomainPurpose::infer_from_scheme(SignatureScheme::Secp256k1),
            DomainPurpose::Sign
        );
        assert_eq!(
            DomainPurpose::infer_from_scheme(SignatureScheme::Ed25519),
            DomainPurpose::Sign
        );
        assert_eq!(
            DomainPurpose::infer_from_scheme(SignatureScheme::V2Secp256k1),
            DomainPurpose::Sign
        );
        assert_eq!(
            DomainPurpose::infer_from_scheme(SignatureScheme::Bls12381),
            DomainPurpose::CKD
        );
    }

    #[test]
    fn test_domain_purpose_json_serialization() {
        let purpose = DomainPurpose::ForeignTx;
        let json = serde_json::to_string(&purpose).unwrap();
        assert_eq!(json, r#""ForeignTx""#);
        let parsed: DomainPurpose = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, DomainPurpose::ForeignTx);
    }
}
