use super::key_state::AuthenticatedParticipantId;
use crate::errors::{DomainError, Error};
use near_sdk::{log, near};
use std::collections::BTreeMap;

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DomainId(pub u64);

impl DomainId {
    pub fn legacy_ecdsa_id() -> Self {
        Self(0)
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureScheme {
    Secp256k1,
    EdDsa,
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainConfig {
    pub id: DomainId,
    pub scheme: SignatureScheme,
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRegistry {
    domains: Vec<DomainConfig>,
    next_domain_id: u64,
}

impl DomainRegistry {
    pub fn new() -> Self {
        Self {
            domains: Vec::new(),
            next_domain_id: 0,
        }
    }

    pub fn domains(&self) -> &[DomainConfig] {
        &self.domains
    }

    pub fn new_single_ecdsa_key_from_legacy() -> Self {
        let mut registry = Self::new();
        registry.add_domain(SignatureScheme::Secp256k1);
        registry
    }

    fn add_domain(&mut self, scheme: SignatureScheme) -> DomainId {
        let domain = DomainConfig {
            id: DomainId(self.next_domain_id),
            scheme,
        };
        self.next_domain_id += 1;
        self.domains.push(domain.clone());
        domain.id
    }

    pub fn add_domains(&self, domains: Vec<DomainConfig>) -> Result<DomainRegistry, Error> {
        let mut new_registry = self.clone();
        for domain in domains {
            let new_domain_id = new_registry.add_domain(domain.scheme);
            if new_domain_id != domain.id {
                return Err(DomainError::NewDomainIdsNotContiguous.into());
            }
        }
        Ok(new_registry)
    }

    pub fn retain_domains(&mut self, num_domains: usize) {
        self.domains.truncate(num_domains);
    }

    pub fn get_domain_by_index(&self, index: usize) -> Option<&DomainConfig> {
        self.domains.get(index)
    }

    pub fn most_recent_domain_for_signature_scheme(
        &self,
        scheme: SignatureScheme,
    ) -> Option<DomainId> {
        self.domains
            .iter()
            .rev()
            .find(|domain| domain.scheme == scheme)
            .map(|domain| domain.id)
    }

    pub fn from_raw_validated(
        domains: Vec<DomainConfig>,
        next_domain_id: u64,
    ) -> Result<Self, Error> {
        let registry = Self {
            domains,
            next_domain_id,
        };
        if !registry.domains.is_sorted_by_key(|domain| domain.id.0) {
            return Err(DomainError::InvalidDomains.into());
        }
        if let Some(largest_domain_id) = registry.domains.last().map(|domain| domain.id.0) {
            if largest_domain_id >= registry.next_domain_id {
                return Err(DomainError::InvalidDomains.into());
            }
        }
        Ok(registry)
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Default)]
pub struct AddDomainsVotes {
    proposal_by_account: BTreeMap<AuthenticatedParticipantId, Vec<DomainConfig>>,
}

impl AddDomainsVotes {
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
}

#[cfg(test)]
pub mod tests {
    use super::{DomainConfig, DomainId, DomainRegistry, SignatureScheme};

    const ALL_SIGNATURE_SCHEMES: [SignatureScheme; 2] =
        [SignatureScheme::Secp256k1, SignatureScheme::EdDsa];

    pub fn gen_domain_registry(num_domains: usize) -> DomainRegistry {
        let mut registry = DomainRegistry::new();
        let mut domains = Vec::new();
        for i in 0..num_domains {
            domains.push(DomainConfig {
                id: DomainId(i as u64 * 2),
                scheme: ALL_SIGNATURE_SCHEMES[i % ALL_SIGNATURE_SCHEMES.len()],
            });
        }
        DomainRegistry::from_raw_validated(domains, num_domains as u64 * 2).unwrap()
    }

    pub fn gen_domains_to_add(registry: &DomainRegistry, num_domains: usize) -> Vec<DomainConfig> {
        let mut new_domains = Vec::new();
        for i in 0..num_domains {
            new_domains.push(DomainConfig {
                id: DomainId(registry.next_domain_id + i as u64),
                scheme: ALL_SIGNATURE_SCHEMES[i % ALL_SIGNATURE_SCHEMES.len()],
            });
        }
        new_domains
    }

    #[test]
    fn test_add_domains() {
        let mut registry = DomainRegistry::new();
        let domains1 = vec![
            DomainConfig {
                id: DomainId(0),
                scheme: SignatureScheme::Secp256k1,
            },
            DomainConfig {
                id: DomainId(1),
                scheme: SignatureScheme::EdDsa,
            },
        ];
        let new_registry = registry.add_domains(domains1.clone()).unwrap();
        assert_eq!(new_registry.domains, domains1);

        let domains2 = vec![
            DomainConfig {
                id: DomainId(2),
                scheme: SignatureScheme::Secp256k1,
            },
            DomainConfig {
                id: DomainId(3),
                scheme: SignatureScheme::EdDsa,
            },
        ];
        let new_registry = new_registry.add_domains(domains2.clone()).unwrap();
        assert_eq!(&new_registry.domains[0..2], &domains1);
        assert_eq!(&new_registry.domains[2..4], &domains2);
    }
}
