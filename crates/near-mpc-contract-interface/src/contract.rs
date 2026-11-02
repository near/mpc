//! The MPC signer contract as a `#[near_kit_primitives::contract]` trait.
//!
//! The trait mirrors the contract's signatures: each method's name, its
//! parameters (sent by name, as near-sdk reads them) and return type. The
//! macro generates [`MpcContractClient<C>`] over any
//! [`Viewer`](near_kit_primitives::Viewer) / [`TxSender`](near_kit_primitives::TxSender)
//! backend and offline [`FunctionCall`](near_kit_primitives::transaction::FunctionCall)
//! constructors on [`MpcContract`]. Each call declares the gas and deposit it
//! is sent with, from [`gas`] and [`deposit`]; a caller overrides them with
//! `.gas(..)`/`.deposit(..)` only where they depend on the arguments.

use std::collections::{BTreeMap, BTreeSet};

use near_mpc_bounded_collections::NonEmptyBTreeMap;

use crate::types::{
    AccountId, AllowedMpcDockerImageHash, Attestation, AuthenticatedParticipantId,
    AvailableForeignChains, BackupServiceInfo, CKDRequest, CKDRequestArgs, CKDResponse, ChainEntry,
    CodeHashesVotes, Config, DestinationNodeInfo, DomainConfig, DomainId, Ed25519PublicKey,
    EpochId, ExpectedMeasurements, ForeignChain, ForeignChainsConfig, ForeignChainsConfigs,
    GovernanceThresholdParameters, InitConfig, KeyEventId, Keyset, LauncherDockerComposeHash,
    LauncherHashVotes, LauncherImageHash, MeasurementVotes, MigrationInfo, NodeId, NodeImageHash,
    ParticipantUrl, ProposalHash, ProposedGovernanceThresholdParameters, ProtocolContractState,
    PublicKey, SignRequestArgs, SignatureRequest, SignatureResponse, StoredAttestation,
    TeeVerifierCodeHash, Update, UpdateHash, VerifyForeignTransactionRequest,
    VerifyForeignTransactionRequestArgs, VerifyForeignTransactionResponse, YieldIndex,
};

#[near_kit_primitives::contract]
pub trait MpcContract {
    fn allowed_docker_image_hashes(&self) -> Vec<AllowedMpcDockerImageHash>;
    fn allowed_launcher_image_hashes(&self) -> Vec<LauncherImageHash>;
    fn allowed_launcher_compose_hashes(&self) -> Vec<LauncherDockerComposeHash>;
    fn allowed_os_measurements(&self) -> Vec<ExpectedMeasurements>;
    fn mpc_node_manifest_digest_votes(&self) -> CodeHashesVotes;
    fn launcher_hash_votes(&self) -> LauncherHashVotes;
    fn os_measurement_votes(&self) -> MeasurementVotes;
    fn contract_update_votes(&self) -> BTreeMap<ProposalHash, BTreeSet<AccountId>>;
    fn state(&self) -> ProtocolContractState;
    fn config(&self) -> Config;
    fn get_tee_accounts(&self) -> Vec<NodeId>;
    fn migration_info(&self) -> MigrationInfo;
    fn get_available_foreign_chains(&self) -> AvailableForeignChains;
    fn get_foreign_chains_configs(&self) -> ForeignChainsConfigs;
    fn allowed_foreign_chain_providers(&self) -> BTreeMap<ForeignChain, ChainEntry>;
    fn version(&self) -> String;
    fn tee_verifier_account_id(&self) -> AccountId;
    fn tee_verifier_votes(&self) -> BTreeMap<ProposalHash, BTreeSet<AuthenticatedParticipantId>>;
    fn public_key(&self, domain_id: Option<DomainId>) -> PublicKey;
    fn derived_public_key(
        &self,
        path: String,
        predecessor: Option<AccountId>,
        domain_id: Option<DomainId>,
    ) -> PublicKey;
    fn available_attestation_grants(&self, account_id: AccountId) -> u32;
    fn get_attestation(&self, tls_public_key: &Ed25519PublicKey) -> Option<StoredAttestation>;
    fn get_pending_request(&self, request: &SignatureRequest) -> Option<YieldIndex>;
    fn get_pending_ckd_request(&self, request: &CKDRequest) -> Option<YieldIndex>;
    fn get_pending_verify_foreign_tx_request(
        &self,
        request: &VerifyForeignTransactionRequest,
    ) -> Option<YieldIndex>;

    #[call(gas = gas::MAX)]
    fn init(
        &mut self,
        parameters: GovernanceThresholdParameters,
        tee_verifier_account_id: AccountId,
        init_config: Option<InitConfig>,
    );
    #[call(gas = gas::MAX)]
    fn init_running(
        &mut self,
        domains: Vec<DomainConfig>,
        next_domain_id: DomainId,
        keyset: Keyset,
        parameters: GovernanceThresholdParameters,
        tee_verifier_account_id: AccountId,
        init_config: Option<InitConfig>,
    );
    #[call(gas = gas::MAX)]
    fn migrate(&mut self);
    #[call(gas = gas::SIGN, deposit = deposit::SIGN)]
    fn sign(&mut self, request: SignRequestArgs);
    #[call(gas = gas::MAX)]
    fn respond(&mut self, request: SignatureRequest, response: SignatureResponse);
    /// The gas depends on the request: attach [`gas::request_app_private_key`].
    #[call(deposit = deposit::SIGN)]
    fn request_app_private_key(&mut self, request: CKDRequestArgs);
    #[call(gas = gas::MAX)]
    fn respond_ckd(&mut self, request: CKDRequest, response: CKDResponse);
    #[call(gas = gas::SIGN, deposit = deposit::SIGN)]
    fn verify_foreign_transaction(&mut self, request: VerifyForeignTransactionRequestArgs);
    #[call(gas = gas::MAX)]
    fn respond_verify_foreign_tx(
        &mut self,
        request: VerifyForeignTransactionRequest,
        response: VerifyForeignTransactionResponse,
    );
    #[call(gas = gas::MAX, deposit = deposit::SUBMIT_CONTRACT_UPDATE)]
    #[borsh]
    fn submit_contract_update(&mut self, update: Update);
    #[call(gas = gas::VOTE_CONTRACT_UPDATE)]
    fn vote_contract_update(&mut self, update_hash: UpdateHash);
    #[call(gas = gas::REMOVE_CONTRACT_UPDATE_VOTE)]
    fn remove_contract_update_vote(&mut self);
    #[call(gas = gas::REMOVE_NON_PARTICIPANT_CONTRACT_UPDATE_VOTES)]
    fn remove_non_participant_contract_update_votes(&mut self);
    #[call(gas = gas::VOTE_ADD_DOMAINS)]
    fn vote_add_domains(&mut self, domains: Vec<DomainConfig>);
    #[call(gas = gas::MAX)]
    fn start_keygen_instance(&mut self, key_event_id: KeyEventId);
    #[call(gas = gas::MAX)]
    fn vote_pk(&mut self, key_event_id: KeyEventId, public_key: PublicKey);
    #[call(gas = gas::VOTE_NEW_PARAMETERS)]
    fn vote_new_parameters(
        &mut self,
        prospective_epoch_id: EpochId,
        proposal: ProposedGovernanceThresholdParameters,
    );
    #[call(gas = gas::MAX)]
    fn start_reshare_instance(&mut self, key_event_id: KeyEventId);
    #[call(gas = gas::MAX)]
    fn vote_reshared(&mut self, key_event_id: KeyEventId);
    #[call(gas = gas::MAX)]
    fn vote_abort_key_event_instance(&mut self, key_event_id: KeyEventId);
    #[call(gas = gas::VOTE_CANCEL_KEYGEN)]
    fn vote_cancel_keygen(&mut self, next_domain_id: DomainId);
    #[call(gas = gas::VOTE_CANCEL_RESHARING)]
    fn vote_cancel_resharing(&mut self);
    #[call(gas = gas::VOTE_MPC_NODE_MANIFEST_DIGEST)]
    fn vote_mpc_node_manifest_digest(&mut self, mpc_node_manifest_digest: NodeImageHash);
    #[call(gas = gas::MAX)]
    fn vote_add_launcher_hash(&mut self, launcher_hash: LauncherImageHash);
    #[call(gas = gas::MAX)]
    fn vote_add_os_measurement(&mut self, measurement: ExpectedMeasurements);
    #[call(gas = gas::VOTE_TEE_VERIFIER_CHANGE)]
    fn vote_tee_verifier_change(
        &mut self,
        candidate_account_id: AccountId,
        expected_code_hash: TeeVerifierCodeHash,
    );
    #[call(gas = gas::MAX, deposit = deposit::NODE_MANAGEMENT)]
    fn update_participant_url(&mut self, url: ParticipantUrl);
    #[call(gas = gas::MAX, deposit = deposit::NODE_MANAGEMENT)]
    fn register_backup_service(&mut self, backup_service_info: BackupServiceInfo);
    #[call(gas = gas::MAX, deposit = deposit::NODE_MANAGEMENT)]
    fn start_node_migration(&mut self, destination_node_info: DestinationNodeInfo);
    #[call(gas = gas::MAX, deposit = deposit::NODE_MANAGEMENT)]
    fn cancel_node_migration(&mut self);
    #[call(gas = gas::MAX)]
    fn conclude_node_migration(&mut self, keyset: Keyset);
    #[call(gas = gas::MAX)]
    fn register_foreign_chains_config(&mut self, foreign_chains_config: ForeignChainsConfig);
    #[call(gas = gas::VOTE_FOREIGN_CHAIN)]
    fn vote_update_foreign_chain_providers(
        &mut self,
        votes: NonEmptyBTreeMap<ForeignChain, ChainEntry>,
    );
    /// The deposit is the storage cost of the grants (see
    /// `STORAGE_BYTE_COST_YOCTONEAR`), so callers attach it.
    #[call(gas = gas::PREPAY_ATTESTATION_STORAGE)]
    fn prepay_attestation_storage(&mut self, account_id: AccountId, grants: u32);
    /// No deposit: the node's function-call key cannot attach one; attestation
    /// storage is funded by the contract's own balance.
    #[call(gas = gas::MAX)]
    fn submit_participant_info(
        &mut self,
        proposed_participant_attestation: Attestation,
        tls_public_key: Ed25519PublicKey,
    );
    #[call(gas = gas::MAX)]
    fn verify_tee(&mut self);
    #[call(gas = gas::MAX)]
    fn clean_tee_status(&mut self);
    #[call(gas = gas::MAX)]
    fn clean_invalid_attestations(&mut self, max_scan: u32);
}

/// Gas the calls declare. Methods without a method-specific amount take
/// [`gas::MAX`].
pub mod gas {
    use near_kit_primitives::Gas;

    use crate::types::{CKDAppPublicKey, CKDRequestArgs};

    /// Default for methods without a method-specific amount.
    // TODO(#166): 300 Tgas used to be the protocol maximum and higher than most methods
    // need; benchmark per method and reduce.
    pub const MAX: Gas = Gas::from_tgas(300);
    pub const SIGN: Gas = Gas::from_tgas(15);
    // AppPublicKeyPV does an on-chain bls12381_pairing_check (2 pairs) before yielding,
    // which costs significantly more than a plain CKD or sign request.
    pub const CKD_PV: Gas = Gas::from_tgas(100);
    pub const VOTE_FOREIGN_CHAIN: Gas = Gas::from_tgas(30);
    pub const VOTE_ADD_DOMAINS: Gas = Gas::from_tgas(22);
    pub const VOTE_NEW_PARAMETERS: Gas = Gas::from_tgas(22);
    pub const VOTE_CANCEL_KEYGEN: Gas = Gas::from_tgas(5);
    pub const VOTE_CANCEL_RESHARING: Gas = Gas::from_tgas(5);
    pub const VOTE_TEE_VERIFIER_CHANGE: Gas = Gas::from_tgas(22);
    // TODO(#166): not benchmarked, carried over from the callers.
    pub const PREPAY_ATTESTATION_STORAGE: Gas = Gas::from_tgas(30);
    pub const VOTE_MPC_NODE_MANIFEST_DIGEST: Gas = Gas::from_tgas(300);
    // TODO(#166): not benchmarked.
    pub const VOTE_CONTRACT_UPDATE: Gas = Gas::from_tgas(22);
    pub const REMOVE_CONTRACT_UPDATE_VOTE: Gas = Gas::from_tgas(5);
    pub const REMOVE_NON_PARTICIPANT_CONTRACT_UPDATE_VOTES: Gas = Gas::from_tgas(5);

    /// `request_app_private_key` costs more when the contract checks the key pair.
    pub fn request_app_private_key(request: &CKDRequestArgs) -> Gas {
        match request.app_public_key {
            CKDAppPublicKey::AppPublicKey(_) => SIGN,
            CKDAppPublicKey::AppPublicKeyPV(_) => CKD_PV,
        }
    }
}

/// Deposits the calls declare. Methods not listed take none.
pub mod deposit {
    use near_kit_primitives::NearToken;

    use crate::deposits::{
        MINIMUM_NODE_MANAGEMENT_DEPOSIT_YOCTONEAR, SIGN_DEPOSIT_YOCTONEAR,
        SUBMIT_CONTRACT_UPDATE_DEPOSIT_YOCTONEAR,
    };

    pub const SIGN: NearToken = NearToken::from_yoctonear(SIGN_DEPOSIT_YOCTONEAR);
    pub const SUBMIT_CONTRACT_UPDATE: NearToken =
        NearToken::from_yoctonear(SUBMIT_CONTRACT_UPDATE_DEPOSIT_YOCTONEAR);
    pub const NODE_MANAGEMENT: NearToken =
        NearToken::from_yoctonear(MINIMUM_NODE_MANAGEMENT_DEPOSIT_YOCTONEAR);
}

#[cfg(test)]
mod tests;
