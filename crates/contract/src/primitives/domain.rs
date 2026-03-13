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

/// Specifies what protocol the nodes need to run for a domain.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    OtBasedEcdsa,
    Frost,
    ConfidentialKeyDerivation,
    DamgardEtAl,
}

impl Default for Protocol {
    fn default() -> Self {
        Self::OtBasedEcdsa
    }
}

/// Elliptic curve used by a domain.
/// More curves may be added in the future. When adding new curves, both Borsh
/// *and* JSON serialization must be kept compatible.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    Secp256k1,
    #[serde(rename = "Ed25519")]
    Edwards25519,
    Bls12381,
}

impl Default for Curve {
    fn default() -> Self {
        Self::Secp256k1
    }
}

/// Number of shares required to reconstruct the secret key for a domain.
/// For legacy domains this matches the global threshold; new domains can set it independently.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReconstructionThreshold(pub u64);

impl ReconstructionThreshold {
    pub fn new(val: u64) -> Self {
        Self(val)
    }
    pub fn value(&self) -> u64 {
        self.0
    }
}

/// Specifies the key configuration for a domain: protocol, curve, and reconstruction threshold.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyConfig {
    pub protocol: Protocol,
    pub curve: Curve,
    pub reconstruction_threshold: ReconstructionThreshold,
}

/// Infer a default purpose from the curve.
/// Used during migration from old state that lacks the `purpose` field.
pub fn infer_purpose_from_curve(curve: Curve) -> DomainPurpose {
    match curve {
        Curve::Bls12381 => DomainPurpose::CKD,
        _ => DomainPurpose::Sign,
    }
}

/// Infer the protocol from a curve for **legacy domains only**.
///
/// This mapping is only valid for domains that existed before the `Protocol` field
/// was introduced. It is NOT a general-purpose mapping: e.g. both `OtBasedEcdsa`
/// and `DamgardEtAl` use `Secp256k1`, but only `OtBasedEcdsa` was ever deployed.
pub fn infer_legacy_protocol_from_curve(curve: Curve) -> Protocol {
    match curve {
        Curve::Secp256k1 => Protocol::OtBasedEcdsa,
        Curve::Edwards25519 => Protocol::Frost,
        Curve::Bls12381 => Protocol::ConfidentialKeyDerivation,
    }
}

/// Build a `KeyConfig` from just a curve, inferring the protocol from legacy rules.
/// `reconstruction_threshold` defaults to 0 (must be set by the caller/migration).
pub fn infer_key_config_from_curve(curve: Curve) -> KeyConfig {
    KeyConfig {
        protocol: infer_legacy_protocol_from_curve(curve),
        curve,
        reconstruction_threshold: ReconstructionThreshold::default(),
    }
}

/// Returns whether the given curve is valid for the given purpose.
pub fn is_valid_curve_for_purpose(purpose: DomainPurpose, curve: Curve) -> bool {
    matches!(
        (purpose, curve),
        (DomainPurpose::Sign, Curve::Secp256k1)
            | (DomainPurpose::Sign, Curve::Edwards25519)
            | (DomainPurpose::ForeignTx, Curve::Secp256k1)
            | (DomainPurpose::CKD, Curve::Bls12381)
    )
}

/// Describes the configuration of a domain: the domain ID, key configuration, and purpose.
#[near(serializers=[borsh, json])]
#[serde(from = "DomainConfigCompat", into = "DomainConfigSer")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainConfig {
    pub id: DomainId,
    pub key_config: KeyConfig,
    pub purpose: DomainPurpose,
}

/// Serialization helper for [`DomainConfig`].
///
/// Emits a `scheme` field (the curve name) alongside `key_config` so that
/// older contracts that only understand `{ scheme: "Secp256k1" }` can still
/// parse the JSON.  Newer contracts use [`DomainConfigCompat`] which prefers
/// `key_config` when present.
#[derive(serde::Serialize)]
struct DomainConfigSer {
    id: DomainId,
    /// Backward-compat: older contracts read this field.
    scheme: Curve,
    key_config: KeyConfig,
    purpose: DomainPurpose,
}

impl From<DomainConfig> for DomainConfigSer {
    fn from(d: DomainConfig) -> Self {
        Self {
            id: d.id,
            scheme: d.key_config.curve,
            key_config: d.key_config,
            purpose: d.purpose,
        }
    }
}

/// JSON-only compatibility helper:
/// - Old 3.4.x format: `{ id, scheme: "Secp256k1" }` (no `purpose`, no `key_config`)
/// - Previous format:  `{ id, scheme: "Secp256k1", purpose: "Sign" }` (no `key_config`)
/// - New format:       `{ id, key_config: { protocol, curve, reconstruction_threshold }, purpose }`
#[derive(serde::Deserialize)]
struct DomainConfigCompat {
    id: DomainId,
    /// New format: full key configuration.
    key_config: Option<KeyConfig>,
    /// Old format fallback: bare curve (field was called "scheme" in older JSON).
    #[serde(alias = "scheme")]
    curve: Option<Curve>,
    #[serde(default)]
    purpose: Option<DomainPurpose>,
}

impl From<DomainConfigCompat> for DomainConfig {
    fn from(value: DomainConfigCompat) -> Self {
        let key_config = value.key_config.unwrap_or_else(|| {
            let curve = value
                .curve
                .expect("DomainConfig JSON must contain either `key_config` or `curve`/`scheme`");
            infer_key_config_from_curve(curve)
        });
        let purpose = value
            .purpose
            .unwrap_or_else(|| infer_purpose_from_curve(key_config.curve));
        Self {
            id: value.id,
            key_config,
            purpose,
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
        registry.add_domain(
            KeyConfig {
                protocol: Protocol::OtBasedEcdsa,
                curve: Curve::Secp256k1,
                reconstruction_threshold: ReconstructionThreshold::default(),
            },
            DomainPurpose::Sign,
        );
        registry
    }

    /// Add a single domain with the given key configuration and purpose, returning the DomainId
    /// of the added domain.
    fn add_domain(&mut self, key_config: KeyConfig, purpose: DomainPurpose) -> DomainId {
        let domain = DomainConfig {
            id: DomainId(self.next_domain_id),
            key_config,
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
            let new_domain_id = new_registry.add_domain(domain.key_config, domain.purpose);
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
            .find(|domain| domain.key_config.curve == curve)
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
        infer_key_config_from_curve, infer_purpose_from_curve, is_valid_curve_for_purpose,
        AddDomainsVotes, Curve, DomainConfig, DomainId, DomainPurpose, DomainRegistry,
        KeyConfig, Participants, Protocol, ReconstructionThreshold,
    };
    use crate::primitives::key_state::AuthenticatedParticipantId;
    use crate::primitives::test_utils::{gen_participant, gen_participants};
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use rstest::rstest;

    fn make_domain(id: u64, curve: Curve, purpose: DomainPurpose) -> DomainConfig {
        DomainConfig {
            id: DomainId(id),
            key_config: infer_key_config_from_curve(curve),
            purpose,
        }
    }

    #[test]
    fn test_add_domains() {
        let registry = DomainRegistry::default();
        let domains1 = vec![
            make_domain(0, Curve::Secp256k1, DomainPurpose::Sign),
            make_domain(1, Curve::Edwards25519, DomainPurpose::Sign),
        ];
        let new_registry = registry.add_domains(domains1.clone()).unwrap();
        assert_eq!(new_registry.domains, domains1);

        let domains2 = vec![
            make_domain(2, Curve::Bls12381, DomainPurpose::CKD),
            DomainConfig {
                id: DomainId(3),
                key_config: KeyConfig {
                    protocol: Protocol::DamgardEtAl,
                    curve: Curve::Secp256k1,
                    reconstruction_threshold: ReconstructionThreshold::default(),
                },
                purpose: DomainPurpose::Sign,
            },
        ];
        let new_registry = new_registry.add_domains(domains2.clone()).unwrap();
        assert_eq!(&new_registry.domains[0..2], &domains1);
        assert_eq!(&new_registry.domains[2..4], &domains2);

        // This fails because the domain ID does not start from next_domain_id.
        let domains3 = vec![make_domain(5, Curve::Secp256k1, DomainPurpose::Sign)];
        let _ = new_registry.add_domains(domains3).unwrap_err();

        // This fails because the domain IDs are not sorted.
        let domains4 = vec![
            make_domain(5, Curve::Secp256k1, DomainPurpose::Sign),
            make_domain(4, Curve::Secp256k1, DomainPurpose::Sign),
        ];
        let _ = new_registry.add_domains(domains4).unwrap_err();
    }

    #[test]
    fn test_retain_domains() {
        let expected = vec![
            make_domain(0, Curve::Secp256k1, DomainPurpose::Sign),
            make_domain(2, Curve::Edwards25519, DomainPurpose::Sign),
            make_domain(3, Curve::Bls12381, DomainPurpose::CKD),
            DomainConfig {
                id: DomainId(4),
                key_config: KeyConfig {
                    protocol: Protocol::DamgardEtAl,
                    curve: Curve::Secp256k1,
                    reconstruction_threshold: ReconstructionThreshold::default(),
                },
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
                make_domain(0, Curve::Secp256k1, DomainPurpose::Sign),
                make_domain(2, Curve::Edwards25519, DomainPurpose::Sign),
                make_domain(3, Curve::Secp256k1, DomainPurpose::Sign),
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

    #[test]
    fn test_serialization_format() {
        let domain_config = make_domain(3, Curve::Secp256k1, DomainPurpose::Sign);
        let json = serde_json::to_string(&domain_config).unwrap();
        let expected = r#"{"id":3,"scheme":"Secp256k1","key_config":{"protocol":"OtBasedEcdsa","curve":"Secp256k1","reconstruction_threshold":0},"purpose":"Sign"}"#;
        assert_eq!(json, expected);

        let domain_config: DomainConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(domain_config.id, DomainId(3));
        assert_eq!(domain_config.key_config.curve, Curve::Secp256k1);
        assert_eq!(domain_config.key_config.protocol, Protocol::OtBasedEcdsa);
        assert_eq!(domain_config.purpose, DomainPurpose::Sign);
    }

    #[rstest]
    #[case(
        r#"{"id":0,"curve":"Secp256k1"}"#,
        Curve::Secp256k1,
        DomainPurpose::Sign
    )]
    #[case(r#"{"id":1,"curve":"Bls12381"}"#, Curve::Bls12381, DomainPurpose::CKD)]
    // Old JSON used "scheme" as the key — verify the alias still works.
    #[case(
        r#"{"id":0,"scheme":"Secp256k1"}"#,
        Curve::Secp256k1,
        DomainPurpose::Sign
    )]
    fn test_deserialization_without_key_config(
        #[case] json: &str,
        #[case] expected_curve: Curve,
        #[case] expected_purpose: DomainPurpose,
    ) {
        // Simulates JSON from older contracts that lack the `key_config` field.
        let config: DomainConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.key_config.curve, expected_curve);
        assert_eq!(config.purpose, expected_purpose);
    }

    #[rstest]
    #[case(Curve::Secp256k1, DomainPurpose::Sign)]
    #[case(Curve::Edwards25519, DomainPurpose::Sign)]
    #[case(Curve::Bls12381, DomainPurpose::CKD)]
    fn test_infer_purpose_from_curve(#[case] curve: Curve, #[case] expected: DomainPurpose) {
        assert_eq!(infer_purpose_from_curve(curve), expected);
    }

    #[rstest]
    // Valid combinations
    #[case(DomainPurpose::Sign, Curve::Secp256k1, true)]
    #[case(DomainPurpose::Sign, Curve::Edwards25519, true)]
    #[case(DomainPurpose::ForeignTx, Curve::Secp256k1, true)]
    #[case(DomainPurpose::CKD, Curve::Bls12381, true)]
    // Invalid combinations
    #[case(DomainPurpose::Sign, Curve::Bls12381, false)]
    #[case(DomainPurpose::ForeignTx, Curve::Edwards25519, false)]
    #[case(DomainPurpose::ForeignTx, Curve::Bls12381, false)]
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
        vec![make_domain(0, Curve::Secp256k1, DomainPurpose::Sign)]
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
        let proposal_a = vec![make_domain(0, Curve::Secp256k1, DomainPurpose::Sign)];
        let proposal_b = vec![make_domain(0, Curve::Edwards25519, DomainPurpose::Sign)];
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
