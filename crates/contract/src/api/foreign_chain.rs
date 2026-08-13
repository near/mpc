//! Foreign-chain transaction verification, plus the per-node chain support
//! reports and the RPC provider policy that decide which chains are available.

use std::collections::{BTreeMap, BTreeSet};

use crate::crypto_shared::types::PublicKeyExtended;
use crate::errors::{InvalidParameters, InvalidState, RespondError, TeeError};
use crate::{dto_mapping::args_into_verify_foreign_tx_request, errors::Error};
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_mpc_contract_interface::types::{
    self as dtos, VerifyForeignTransactionRequest, VerifyForeignTransactionRequestArgs,
    VerifyForeignTransactionResponse,
};

use crate::primitives::{key_state::AuthenticatedParticipantId, signature::YieldIndex};
use dtos::DomainPurpose;
use near_sdk::{CryptoHash, Gas, NearToken, Promise, PromiseError, PromiseOrValue, env, log, near};

use crate::api::sign::MINIMUM_SIGN_REQUEST_DEPOSIT;
use crate::pending_requests;
use crate::state::ProtocolContractState;
use crate::{MpcContract, MpcContractExt};

#[near]
impl MpcContract {
    fn add_verify_foreign_tx_request(
        &mut self,
        request: VerifyForeignTransactionRequest,
        data_id: CryptoHash,
    ) {
        pending_requests::push_pending_yield(
            &mut self.pending_verify_foreign_tx_requests,
            request,
            data_id,
        );
    }

    /// Submit a verification + signing request for a foreign chain transaction.
    /// MPC nodes will verify the transaction on the foreign chain before signing.
    /// The signed payload is derived from the transaction ID (hash of tx_id).
    #[handle_result]
    #[payable]
    pub fn verify_foreign_transaction(&mut self, request: VerifyForeignTransactionRequestArgs) {
        log!(
            "verify_foreign_transaction: predecessor={:?}, request={:?}",
            env::predecessor_account_id(),
            request
        );

        self.check_request_preconditions(
            request.domain_id,
            DomainPurpose::ForeignTx,
            Gas::from_tgas(self.config.sign_call_gas_attachment_requirement_tera_gas),
            MINIMUM_SIGN_REQUEST_DEPOSIT,
        );

        let requested_chain = request.request.chain();
        let supported_chains = self.get_supported_foreign_chains();
        if !supported_chains.contains(&requested_chain) {
            env::panic_str(
                &InvalidParameters::ForeignChainNotSupported {
                    requested: requested_chain,
                }
                .to_string(),
            );
        }

        let callback_gas = Gas::from_tgas(
            self.config
                .return_signature_and_clean_state_on_success_call_tera_gas,
        );

        let request = args_into_verify_foreign_tx_request(request);
        let callback_args = serde_json::to_vec(&(&request,)).unwrap();
        self.enqueue_yield_request(
            method_names::RETURN_VERIFY_FOREIGN_TX_AND_CLEAN_STATE_ON_SUCCESS,
            callback_args,
            callback_gas,
            move |this, id| this.add_verify_foreign_tx_request(request, id),
        );
    }

    #[handle_result]
    pub fn respond_verify_foreign_tx(
        &mut self,
        request: VerifyForeignTransactionRequest,
        response: VerifyForeignTransactionResponse,
    ) -> Result<(), Error> {
        let signer = Self::assert_caller_is_signer();

        log!(
            "respond_verify_foreign_tx: signer={}, request={:?}",
            &signer,
            &request
        );

        self.assert_caller_is_attested_participant_and_protocol_active();

        if !self.protocol_state.is_running_or_resharing() {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        }

        if !self.accept_requests {
            return Err(TeeError::TeeValidationFailed.into());
        }

        if let Some(expected_payload_hash) = &request.expected_payload_hash
            && &response.payload_hash != expected_payload_hash
        {
            return Err(RespondError::UnexpectedPayloadHash.into());
        }

        let domain = request.domain_id;
        let public_key = self.public_key_extended(domain.0.into())?;

        let signature_is_valid = match (&response.signature, public_key) {
            (
                dtos::SignatureResponse::Secp256k1(signature_response),
                PublicKeyExtended::Secp256k1 { near_public_key },
            ) => {
                let secp_pk = dtos::Secp256k1PublicKey::try_from(&near_public_key)
                    .expect("Secp256k1 variant always has a secp256k1 key");

                let payload_hash: [u8; 32] = response.payload_hash.0;

                // Check the signature is correct against the root public key
                near_mpc_signature_verifier::verify_ecdsa_signature(
                    signature_response,
                    &payload_hash,
                    &secp_pk,
                )
                .is_ok()
            }
            (signature_response, public_key_requested) => {
                return Err(RespondError::SignatureSchemeMismatch {
                    mpc_scheme: Box::new(signature_response.clone()),
                    user_scheme: Box::new(public_key_requested),
                }
                .into());
            }
        };

        if !signature_is_valid {
            return Err(RespondError::InvalidSignature.into());
        }

        pending_requests::resolve_yields_for(
            &mut self.pending_verify_foreign_tx_requests,
            &request,
            serde_json::to_vec(&response).unwrap(),
        )
    }

    /// Registers the set of foreign chains the calling node supports.
    ///
    /// Must be called directly from the participant's own NEAR account
    /// (`voter_or_panic` requires `signer == predecessor`, blocking calls forwarded
    /// through another contract). Callable by a participant in any active protocol phase
    /// (Initializing, Running, or Resharing — authenticated against that phase's participant
    /// set); panics in [`NotInitialized`](ProtocolContractState::NotInitialized) or when the caller is not a participant. Entries for
    /// accounts that are no longer participants are pruned after resharing by
    /// [`Self::clean_foreign_chain_data`].
    #[handle_result]
    pub fn register_foreign_chain_support(
        &mut self,
        foreign_chain_support: dtos::SupportedForeignChains,
    ) -> Result<(), Error> {
        let account_id = self.voter_or_panic();

        self.node_foreign_chain_support
            .foreign_chain_support_by_node
            .insert(account_id, foreign_chain_support);

        Ok(())
    }

    /// (Re)registers the foreign chains this node currently covers.
    #[handle_result]
    pub fn register_foreign_chains_config(
        &mut self,
        foreign_chains_config: dtos::ForeignChainsConfig,
    ) -> Result<(), Error> {
        Self::assert_caller_is_signer();
        let signer_account_id = env::signer_account_id();
        let signer_account_pk = env::signer_account_pk();
        let signer_account_ed25519_pk = Ed25519PublicKey::try_from(&signer_account_pk)
            .unwrap_or_else(|_| env::panic_str("signer account key must be Ed25519"));
        let node_id = self
            .tee_state
            .lookup_node_id_by_signer_pk(&signer_account_ed25519_pk)
            .map_err(|_| InvalidState::NotParticipant {
                account_id: signer_account_id.clone(),
            })?;
        if node_id.account_id != signer_account_id {
            return Err(InvalidState::NotParticipant {
                account_id: signer_account_id,
            }
            .into());
        }
        let is_participant = self
            .protocol_state
            .is_existing_or_prospective_participant(&node_id.account_id)?;
        if !is_participant {
            return Err(InvalidState::NotParticipant {
                account_id: node_id.account_id.clone(),
            }
            .into());
        }
        let tls_key = node_id.tls_public_key.clone();

        self.foreign_chains
            .get_mut()
            .register(tls_key, foreign_chains_config);
        self.recompute_available_foreign_chains();

        Ok(())
    }

    /// No-op when outside [`ProtocolContractState::Running`] and [`ProtocolContractState::Resharing`].
    pub(crate) fn recompute_available_foreign_chains(&mut self) {
        let Ok(params) = self.protocol_state.threshold_parameters() else {
            return;
        };
        // TODO(#3556): replace this with a per-scheme
        // `required_active_signers(protocol, reconstruction_threshold)`.
        let Some(reconstruction_threshold) =
            self.protocol_state.domain_registry().ok().and_then(|r| {
                r.domains()
                    .iter()
                    .filter(|d| d.purpose == DomainPurpose::ForeignTx)
                    .map(|d| d.reconstruction_threshold.inner())
                    .max()
            })
        else {
            // No op if contract isn't in Running or Resharing state, or
            // there is no foreign tx domain registered.
            // Not panicking is intentional.
            log!("Skipping available foreign chains recomputation");
            return;
        };
        let active_tls_keys: BTreeSet<_> = params
            .participants()
            .participants()
            .iter()
            .map(|(_, _, info)| info.tls_public_key.clone())
            .collect();
        self.foreign_chains
            .get_mut()
            .update_available_chains_config_cache(&active_tls_keys, reconstruction_threshold);
    }

    #[deprecated(
        note = "https://github.com/near/mpc/issues/3079. Node will be upgraded to use register_foreign_chain_support instead"
    )]
    #[handle_result]
    pub fn register_foreign_chain_config(
        &mut self,
        foreign_chain_configuration: dtos::ForeignChainConfiguration,
    ) -> Result<(), Error> {
        let foreign_chain_support: dtos::SupportedForeignChains = foreign_chain_configuration
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            .into();

        self.register_foreign_chain_support(foreign_chain_support)
    }

    /// Vote on per-chain RPC provider whitelist state. The input is keyed by
    /// [`ForeignChain`](dtos::ForeignChain); each [`ChainEntry`](dtos::ChainEntry) value carries the proposed full provider list
    /// and the RPC response quorum for that chain. The chain's stored state is replaced
    /// once the protocol's signing threshold of participants has voted the same
    /// `(providers, quorum)` pair. [`NonEmptyBTreeMap`](near_mpc_bounded_collections::NonEmptyBTreeMap) enforces a non-empty batch and
    /// at-most-one entry per chain at borsh-deserialize time.
    #[handle_result]
    pub fn vote_update_foreign_chain_providers(
        &mut self,
        #[serializer(borsh)] votes: near_mpc_bounded_collections::NonEmptyBTreeMap<
            dtos::ForeignChain,
            dtos::ChainEntry,
        >,
    ) -> Result<Vec<dtos::ForeignChain>, Error> {
        let batch_hash = env::sha256_array(
            borsh::to_vec(&votes).expect("borsh serialization of votes batch must succeed"),
        );
        log!(
            "vote_update_foreign_chain_providers: signer={}, n_votes={}, batch_hash={}",
            env::signer_account_id(),
            votes.len(),
            hex::encode(batch_hash),
        );
        self.voter_or_panic();

        let threshold_parameters = self
            .protocol_state
            .threshold_parameters()
            .expect("voter_or_panic() above already errors on NotInitialized");

        let participant = AuthenticatedParticipantId::new(threshold_parameters.participants())?;
        let applied = self.foreign_chains.get_mut().rpc_whitelist.vote(
            participant,
            votes,
            threshold_parameters,
        )?;
        log!(
            "vote_update_foreign_chain_providers: applied chains={:?}",
            applied,
        );
        if !applied.is_empty() {
            self.recompute_available_foreign_chains();
        }
        Ok(applied)
    }

    /// On-chain RPC provider whitelist keyed by [`ForeignChain`](dtos::ForeignChain). Nodes read this at
    /// startup to validate their local `foreign_chains.yaml`. Borsh-encoded result.
    #[result_serializer(borsh)]
    pub fn allowed_foreign_chain_providers(
        &self,
    ) -> std::collections::BTreeMap<dtos::ForeignChain, dtos::ChainEntry> {
        log!("allowed_foreign_chain_providers");
        self.foreign_chains.get().rpc_whitelist.entries.snapshot()
    }

    /// Private endpoint to clean up foreign chain policy votes and node configurations
    /// for non-participants after resharing.
    #[private]
    #[handle_result]
    pub fn clean_foreign_chain_data(&mut self) -> Result<(), Error> {
        log!(
            "clean_foreign_chain_data: signer={}",
            env::signer_account_id()
        );

        let participants = match &self.protocol_state {
            ProtocolContractState::Running(state) => state.parameters.participants(),
            _ => {
                return Err(InvalidState::ProtocolStateNotRunning.into());
            }
        };

        let participant_accounts: std::collections::HashSet<dtos::AccountId> = participants
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect();

        let active_tls_keys: std::collections::BTreeSet<dtos::Ed25519PublicKey> = participants
            .participants()
            .iter()
            .map(|(_, _, info)| info.tls_public_key.clone())
            .collect();

        let non_participant_configs: Vec<dtos::AccountId> = self
            .node_foreign_chain_support
            .foreign_chain_support_by_node
            .keys()
            .filter(|account| !participant_accounts.contains(*account))
            .cloned()
            .collect();
        for account in &non_participant_configs {
            self.node_foreign_chain_support
                .foreign_chain_support_by_node
                .remove(account);
        }

        self.foreign_chains
            .get_mut()
            .remove_stale_configs(&active_tls_keys);

        self.foreign_chains
            .get_mut()
            .rpc_whitelist
            .votes
            .retain(participants);

        Ok(())
    }

    /// Presence check for a pending foreign-tx verification request, exposed as a
    /// view call.
    ///
    /// See [`Self::get_pending_request`] for the contract: the returned [`YieldIndex`]
    /// is an arbitrary representative of a fan-out queue, not "the" yield. Only the
    /// `Some`/`None` distinction is meaningful.
    pub fn get_pending_verify_foreign_tx_request(
        &self,
        request: &VerifyForeignTransactionRequest,
    ) -> Option<YieldIndex> {
        self.pending_verify_foreign_tx_requests
            .get(request)
            .and_then(|q| q.first().cloned())
    }

    pub fn get_supported_foreign_chains(&self) -> dtos::SupportedForeignChains {
        let active_participant_account_ids = self
            .protocol_state
            .active_participants()
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect::<BTreeSet<_>>();

        let mut foreign_chain_to_node_mapping: BTreeMap<
            &dtos::ForeignChain,
            BTreeSet<dtos::AccountId>,
        > = BTreeMap::new();

        for (account_id, chains) in self
            .node_foreign_chain_support
            .foreign_chain_support_by_node
            .iter()
        {
            for chain in chains.iter() {
                foreign_chain_to_node_mapping
                    .entry(chain)
                    .or_default()
                    .insert(account_id.clone());
            }
        }

        foreign_chain_to_node_mapping
            .into_iter()
            .filter_map(|(foreign_chain, nodes_supporting_chain)| {
                let all_active_nodes_supports_chain =
                    nodes_supporting_chain.is_superset(&active_participant_account_ids);

                if all_active_nodes_supports_chain {
                    Some(foreign_chain)
                } else {
                    None
                }
            })
            .cloned()
            .collect::<BTreeSet<dtos::ForeignChain>>()
            .into()
    }

    pub fn get_foreign_chain_support_by_node(&self) -> dtos::ForeignChainSupportByNode {
        self.node_foreign_chain_support.to_dto()
    }

    /// The **available** foreign chains: whitelisted chains that are supported
    /// by at least the signing threshold of active participants.
    pub fn get_available_foreign_chains(&self) -> dtos::AvailableForeignChains {
        self.foreign_chains.get().available_foreign_chains.clone()
    }

    /// Per-participant view of which foreign chains each node currently covers. Feeds the
    /// available-set computation ([`Self::get_available_foreign_chains`]) and coverage alerting.
    pub fn get_foreign_chains_configs(&self) -> dtos::ForeignChainsConfigs {
        self.foreign_chains.get().snapshot_by_node()
    }

    /// Yield-resume callback for a single queued foreign-tx verification request.
    ///
    /// On success, returns the verification response to the original caller. On
    /// timeout, pops this yield's slot (the head of the FIFO fan-out queue) from the
    /// pending-request map and fires `fail_on_timeout` to fail the original
    /// transaction. Sibling yields queued under the same request key remain pending
    /// and are cleaned up by their own timeouts (or drained together by a subsequent
    /// `respond_verify_foreign_tx`).
    #[private]
    pub fn return_verify_foreign_tx_and_clean_state_on_success(
        &mut self,
        request: VerifyForeignTransactionRequest,
        #[callback_result] response: Result<VerifyForeignTransactionResponse, PromiseError>,
    ) -> PromiseOrValue<VerifyForeignTransactionResponse> {
        match response {
            Ok(response) => PromiseOrValue::Value(response),
            Err(_) => {
                pending_requests::pop_oldest_pending_yield(
                    &mut self.pending_verify_foreign_tx_requests,
                    &request,
                );
                let fail_on_timeout_gas = Gas::from_tgas(self.config.fail_on_timeout_tera_gas);
                let promise = Promise::new(env::current_account_id()).function_call(
                    method_names::FAIL_ON_TIMEOUT.to_string(),
                    vec![],
                    NearToken::from_near(0),
                    fail_on_timeout_gas,
                );
                near_sdk::PromiseOrValue::Promise(promise.as_return())
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::test_utils::*;
    use crate::dto_mapping::IntoInterfaceType;
    use crate::primitives::domain::AddDomainsVotes;
    use crate::primitives::key_state::EpochId;
    use crate::primitives::key_state::Keyset;
    use crate::primitives::thresholds::GovernanceThreshold;
    use crate::primitives::thresholds::GovernanceThresholdParameters;
    use crate::primitives::thresholds::ProposedGovernanceThresholdParameters;
    use crate::state::running::RunningContractState;
    use std::time::Duration;
    use std::{collections::BTreeMap, panic, str::FromStr};

    use crate::primitives::participants::ParticipantInfo;

    use crate::primitives::test_utils::{
        bogus_ed25519_public_key, gen_account_id, gen_participant, gen_participants,
    };

    use crate::state::key_event::tests::Environment;

    use crate::state::test_utils::{gen_resharing_state, gen_running_state};

    use crate::tee::tee_state::{NodeAttestation, NodeId};

    use crate::*;
    use assert_matches::assert_matches;
    use dtos::ForeignTxSignPayload;
    use dtos::{Curve, DomainConfig, DomainId, Protocol, ReconstructionThreshold};

    use k256::{self, Secp256k1, ecdsa::SigningKey, elliptic_curve};
    use mpc_attestation::attestation::{
        MockAttestation as MpcMockAttestation, VerifiedAttestation,
    };
    use near_mpc_bounded_collections::{NonEmptyBTreeMap, NonEmptyBTreeSet};

    use near_mpc_contract_interface::types::DestinationNodeInfo;
    use near_mpc_contract_interface::types::{
        BitcoinExtractedValue, BitcoinExtractor, BitcoinRpcRequest, ExtractedValue,
        ForeignTxPayloadVersion, ForeignTxSignPayloadV1,
    };
    use near_sdk::{NearToken, test_utils::VMContextBuilder, testing_env};
    use primitives::key_state::{AttemptId, KeyForDomain};
    use rand::SeedableRng;
    use rand::rngs::OsRng;

    use rstest::rstest;

    /// Register the given foreign chains as supported by all active participants.
    fn register_supported_chains(
        contract: &mut MpcContract,
        chains: impl IntoIterator<Item = dtos::ForeignChain>,
    ) {
        let foreign_chain_configuration: dtos::ForeignChainConfiguration = chains
            .into_iter()
            .map(|foreign_chain| {
                (
                    foreign_chain,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: "dummy_url.com".to_string(),
                    }),
                )
            })
            .collect::<BTreeMap<dtos::ForeignChain, NonEmptyBTreeSet<dtos::RpcProvider>>>()
            .into();

        // pub struct ForeignChainConfiguration(BTreeMap<ForeignChain, NonEmptyBTreeSet<RpcProvider>>);

        let participants: Vec<_> = contract
            .protocol_state
            .active_participants()
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect();
        for account_id in participants {
            let _env = Environment::new(None, Some(account_id), None);
            contract
                .register_foreign_chain_config(foreign_chain_configuration.clone())
                .expect("register should succeed");
        }
    }

    #[test]
    fn verify_foreign_transaction__should_queue_duplicates_from_different_callers() {
        // Given: two different callers will submit the same foreign-tx verification request.
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        register_supported_chains(&mut contract, [dtos::ForeignChain::Bitcoin]);
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };

        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };
        let request = args_into_verify_foreign_tx_request(request_args.clone());

        // When: caller alice submits the request.
        let alice = AccountId::from_str("alice.near").unwrap();
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(alice.clone())
                .predecessor_account_id(alice)
                .current_account_id(context.current_account_id.clone())
                .attached_deposit(NearToken::from_yoctonear(1))
                .build()
        );
        contract.verify_foreign_transaction(request_args.clone());

        // And: caller bob submits the identical request — a different account would today
        // be blocked from receiving a response by alice's submission.
        let bob = AccountId::from_str("bob.near").unwrap();
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(bob.clone())
                .predecessor_account_id(bob)
                .current_account_id(context.current_account_id.clone())
                .attached_deposit(NearToken::from_yoctonear(1))
                .build()
        );
        contract.verify_foreign_transaction(request_args);

        // Then: both yields are queued under the single (caller-agnostic) request key.
        assert_eq!(
            contract
                .pending_verify_foreign_tx_requests
                .get(&request)
                .map(|q| q.len()),
            Some(2),
            "duplicate foreign-tx requests from different callers should fan out",
        );

        // When: a single valid response is delivered.
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: request.request.clone(),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });
        let payload_hash_arr = payload.compute_msg_hash().unwrap().0;
        let secret_key_ec: elliptic_curve::SecretKey<Secp256k1> =
            elliptic_curve::SecretKey::from_bytes(&secret_key.to_bytes()).unwrap();
        let signing_key = SigningKey::from_bytes(&secret_key_ec.to_bytes()).unwrap();
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&payload_hash_arr)
            .unwrap();
        let response = VerifyForeignTransactionResponse {
            payload_hash: payload.compute_msg_hash().unwrap(),
            signature: dtos::SignatureResponse::Secp256k1(
                dtos::K256Signature::from_ecdsa_recoverable(&signature, recovery_id),
            ),
        };

        with_active_participant_and_attested_context(&contract);
        contract
            .respond_verify_foreign_tx(request.clone(), response)
            .expect("respond_verify_foreign_tx should succeed");

        // Then: both queued yields are drained from the single map entry.
        assert!(
            contract
                .pending_verify_foreign_tx_requests
                .get(&request)
                .is_none()
        );
    }

    #[test]
    fn respond_verify_foreign_tx__should_succeed_when_response_is_valid_and_request_exists() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        register_supported_chains(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context.clone());
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };
        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };

        // When
        let request = args_into_verify_foreign_tx_request(request_args.clone());
        contract.verify_foreign_transaction(request_args);
        contract
            .get_pending_verify_foreign_tx_request(&request)
            .unwrap();
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: request.request.clone(),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });
        let response = sign_foreign_tx_payload(&secret_key, &payload);

        with_active_participant_and_attested_context(&contract);

        // Then
        match contract.respond_verify_foreign_tx(request.clone(), response.clone()) {
            Ok(_) => {
                contract
                    .return_verify_foreign_tx_and_clean_state_on_success(
                        request.clone(),
                        Ok(response),
                    )
                    .detach();

                assert!(
                    contract
                        .get_pending_verify_foreign_tx_request(&request)
                        .is_none(),
                );
            }
            Err(_) => panic!("respond_verify_foreign_tx should not fail"),
        }
    }

    #[test]
    fn respond_verify_foreign_tx__should_reject_response_with_unexpected_payload_hash() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        register_supported_chains(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context.clone());
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };
        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: Some(dtos::Hash256([1u8; 32])),
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };
        let request = args_into_verify_foreign_tx_request(request_args.clone());
        contract.verify_foreign_transaction(request_args);
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: request.request.clone(),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });
        let response = sign_foreign_tx_payload(&secret_key, &payload);
        with_active_participant_and_attested_context(&contract);

        // When
        let result = contract.respond_verify_foreign_tx(request.clone(), response);

        // Then
        assert_matches!(
            result.unwrap_err(),
            Error::Respond(RespondError::UnexpectedPayloadHash)
        );
        assert!(
            contract
                .get_pending_verify_foreign_tx_request(&request)
                .is_some(),
            "the pending request must remain unresolved",
        );
    }

    #[test]
    fn respond_verify_foreign_tx__should_succeed_when_response_matches_expected_payload_hash() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        register_supported_chains(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context.clone());
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };
        let rpc_request = dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
            tx_id: [7u8; 32].into(),
            confirmations: 2.into(),
            extractors: vec![BitcoinExtractor::BlockHash],
        });
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: rpc_request.clone(),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });
        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: Some(payload.compute_msg_hash().unwrap()),
            request: rpc_request,
        };
        let request = args_into_verify_foreign_tx_request(request_args.clone());
        contract.verify_foreign_transaction(request_args);
        let response = sign_foreign_tx_payload(&secret_key, &payload);
        with_active_participant_and_attested_context(&contract);

        // When
        let result = contract.respond_verify_foreign_tx(request.clone(), response);

        // Then
        assert!(
            result.is_ok(),
            "response matching the expected payload hash must be accepted: {result:?}",
        );
    }

    #[test]
    fn respond_verify_foreign_tx__should_reject_request_with_erased_expected_payload_hash() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        register_supported_chains(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context.clone());
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };
        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: Some(dtos::Hash256([1u8; 32])),
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };
        let request = args_into_verify_foreign_tx_request(request_args.clone());
        contract.verify_foreign_transaction(request_args);
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: request.request.clone(),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });
        let response = sign_foreign_tx_payload(&secret_key, &payload);
        with_active_participant_and_attested_context(&contract);

        // When
        let tampered_request = VerifyForeignTransactionRequest {
            expected_payload_hash: None,
            ..request.clone()
        };
        let result = contract.respond_verify_foreign_tx(tampered_request, response);

        // Then
        assert_matches!(
            result.unwrap_err(),
            Error::InvalidParameters(InvalidParameters::RequestNotFound)
        );
        assert!(
            contract
                .get_pending_verify_foreign_tx_request(&request)
                .is_some(),
            "the pending request must remain unresolved",
        );
    }

    fn sign_foreign_tx_payload(
        secret_key: &k256::Scalar,
        payload: &ForeignTxSignPayload,
    ) -> VerifyForeignTransactionResponse {
        let payload_hash = payload.compute_msg_hash().unwrap();
        let secret_key_ec: elliptic_curve::SecretKey<Secp256k1> =
            elliptic_curve::SecretKey::from_bytes(&secret_key.to_bytes()).unwrap();
        let secret_key = SigningKey::from_bytes(&secret_key_ec.to_bytes()).unwrap();
        let (signature, recovery_id) = secret_key
            .sign_prehash_recoverable(&payload_hash.0)
            .unwrap();
        let signature = dtos::SignatureResponse::Secp256k1(
            dtos::K256Signature::from_ecdsa_recoverable(&signature, recovery_id),
        );
        VerifyForeignTransactionResponse {
            payload_hash,
            signature,
        }
    }

    #[test]
    fn test_verify_foreign_tx_timeout() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, _secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        register_supported_chains(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context.clone());
        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };
        let request = args_into_verify_foreign_tx_request(request_args.clone());

        // When
        contract.verify_foreign_transaction(request_args);

        // Then
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(
            contract.return_verify_foreign_tx_and_clean_state_on_success(
                request.clone(),
                Err(PromiseError::Failed)
            ),
            PromiseOrValue::Promise(_)
        ));
        assert!(
            contract
                .get_pending_verify_foreign_tx_request(&request)
                .is_none()
        );
    }

    #[rstest]
    #[case(Protocol::CaitSith, DomainPurpose::Sign)]
    #[case(Protocol::ConfidentialKeyDerivation, DomainPurpose::CKD)]
    #[should_panic(expected = "this method requires ForeignTx")]
    fn verify_foreign_tx__should_reject_non_foreign_tx_domain(
        #[case] protocol: Protocol,
        #[case] purpose: DomainPurpose,
    ) {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (_context, mut contract, _sk) = basic_setup_with_protocol(protocol, purpose, &mut rng);

        // When
        contract.verify_foreign_transaction(VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        });
    }

    #[test]
    #[should_panic(expected = "Requested foreign chain, Bitcoin, is not supported.")]
    fn verify_foreign_tx__should_reject_chain_not_in_policy() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, _sk) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        // Supported chains has Solana but not Bitcoin
        register_supported_chains(&mut contract, [dtos::ForeignChain::Solana]);
        testing_env!(context.clone());

        // When - requesting Bitcoin which is not in the policy
        contract.verify_foreign_transaction(VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        });
    }

    #[test]
    #[should_panic(expected = "Caller must be the signer account")]
    fn register_foreign_chain_support__should_panic_when_predecessor_differs_from_signer() {
        let mut contract = forwarded_participant_call_contract();
        contract
            .register_foreign_chain_support(BTreeSet::new().into())
            .expect("expected panic when predecessor != signer");
    }

    #[test]
    fn register_foreign_chain_support__should_store_supported_chains_for_participant() {
        // Given
        let running_state = gen_running_state(1);
        let participants = running_state
            .parameters
            .participants()
            .participants()
            .clone();
        let first_account = participants[0].0.clone();
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));

        let foreign_chain_support: dtos::SupportedForeignChains =
            BTreeSet::from([dtos::ForeignChain::Bitcoin, dtos::ForeignChain::Ethereum]).into();

        let _env = Environment::new(None, Some(first_account.clone()), None);

        // When
        contract
            .register_foreign_chain_support(foreign_chain_support.clone())
            .expect("register should succeed");

        // Then
        let votes = contract.get_foreign_chain_support_by_node();
        assert_eq!(votes.foreign_chain_support_by_node.len(), 1);
        assert_eq!(
            votes
                .foreign_chain_support_by_node
                .get(&first_account.clone()),
            Some(&foreign_chain_support)
        );
    }

    #[test]
    fn register_foreign_chain_support__should_store_for_previous_participant_during_resharing() {
        // Given: a contract mid-resharing, and a participant from the previous running set.
        let (_env, resharing_state) = gen_resharing_state(1);
        let previous_participant = resharing_state
            .previous_running_state
            .parameters
            .participants()
            .participants()[0]
            .0
            .clone();
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Resharing(resharing_state));
        let foreign_chain_support: dtos::SupportedForeignChains =
            BTreeSet::from([dtos::ForeignChain::Bitcoin]).into();
        let _env = Environment::new(None, Some(previous_participant.clone()), None);

        // When: that participant registers foreign-chain support outside of Running state.
        contract
            .register_foreign_chain_support(foreign_chain_support.clone())
            .expect("a previous participant may register during resharing");

        // Then: the registration is stored against their account.
        let stored = contract.get_foreign_chain_support_by_node();
        assert_eq!(
            stored
                .foreign_chain_support_by_node
                .get(&previous_participant),
            Some(&foreign_chain_support)
        );
    }

    #[test]
    #[should_panic(expected = "not a voter")]
    fn register_foreign_chain_config__should_reject_non_participant() {
        // Given
        let running_state = gen_running_state(1);
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));
        let foreign_chain_configuration: dtos::ForeignChainConfiguration = BTreeMap::from([(
            dtos::ForeignChain::Bitcoin,
            NonEmptyBTreeSet::new(dtos::RpcProvider {
                rpc_url: "https://btc.example.com".to_string(),
            }),
        )])
        .into();

        let non_participant = gen_account_id();
        let _env = Environment::new(None, Some(non_participant), None);

        // When / Then: a non-participant is rejected. Registration now authenticates via
        // `voter_or_panic()`, which panics rather than returning an error.
        contract
            .register_foreign_chain_config(foreign_chain_configuration)
            .expect("non-participant should not be able to register");
    }

    #[test]
    fn get_supported_foreign_chains__should_return_chains_supported_by_all_participants() {
        // Given
        let running_state = gen_running_state(1);
        let participants = running_state
            .parameters
            .participants()
            .participants()
            .clone();
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));

        // Both participants support Bitcoin and Ethereum
        let foreign_chain_configuration: dtos::ForeignChainConfiguration = BTreeMap::from([
            (
                dtos::ForeignChain::Bitcoin,
                NonEmptyBTreeSet::new(dtos::RpcProvider {
                    rpc_url: "https://btc.example.com".to_string(),
                }),
            ),
            (
                dtos::ForeignChain::Ethereum,
                NonEmptyBTreeSet::new(dtos::RpcProvider {
                    rpc_url: "https://eth.example.com".to_string(),
                }),
            ),
        ])
        .into();

        for (account_id, _, _) in &participants {
            let _env = Environment::new(None, Some(account_id.clone()), None);
            contract
                .register_foreign_chain_config(foreign_chain_configuration.clone())
                .expect("register should succeed");
        }

        // When
        let result = contract.get_supported_foreign_chains();

        // Then
        assert!(result.contains(&dtos::ForeignChain::Bitcoin));
        assert!(result.contains(&dtos::ForeignChain::Ethereum));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn get_supported_foreign_chains__should_exclude_chains_not_supported_by_all() {
        // Given
        let running_state = gen_running_state(1);
        let participants = running_state
            .parameters
            .participants()
            .participants()
            .clone();
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));

        // All participants except the last support Bitcoin + Ethereum
        for (account_id, _, _) in &participants[..participants.len() - 1] {
            let _env = Environment::new(None, Some(account_id.clone()), None);
            let foreign_chain_configuration: dtos::ForeignChainConfiguration = BTreeMap::from([
                (
                    dtos::ForeignChain::Bitcoin,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: "https://btc.example.com".to_string(),
                    }),
                ),
                (
                    dtos::ForeignChain::Ethereum,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: "https://eth.example.com".to_string(),
                    }),
                ),
            ])
            .into();
            contract
                .register_foreign_chain_config(foreign_chain_configuration)
                .expect("register should succeed");
        }

        // Last participant supports only Bitcoin
        {
            let last = &participants[participants.len() - 1].0;
            let _env = Environment::new(None, Some(last.clone()), None);
            let foreign_chain_configuration: dtos::ForeignChainConfiguration = BTreeMap::from([(
                dtos::ForeignChain::Bitcoin,
                NonEmptyBTreeSet::new(dtos::RpcProvider {
                    rpc_url: "https://btc.example.com".to_string(),
                }),
            )])
            .into();
            contract
                .register_foreign_chain_config(foreign_chain_configuration)
                .expect("register should succeed");
        }

        // When
        let result = contract.get_supported_foreign_chains();

        // Then - only Bitcoin is unanimous
        assert!(result.contains(&dtos::ForeignChain::Bitcoin));
        assert!(!result.contains(&dtos::ForeignChain::Ethereum));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn get_supported_foreign_chains__different_rpc_urls_per_participant_is_fine() {
        // Given
        let running_state = gen_running_state(1);
        let participants = running_state
            .parameters
            .participants()
            .participants()
            .clone();
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));

        // Each participant registers the same chains but with different RPC URLs
        for (i, (account_id, _, _)) in participants.iter().enumerate() {
            let _env = Environment::new(None, Some(account_id.clone()), None);
            let foreign_chain_configuration: dtos::ForeignChainConfiguration = BTreeMap::from([
                (
                    dtos::ForeignChain::Bitcoin,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: format!("https://btc-node-{i}.example.com"),
                    }),
                ),
                (
                    dtos::ForeignChain::Ethereum,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: format!("https://eth-node-{i}.example.com"),
                    }),
                ),
            ])
            .into();
            contract
                .register_foreign_chain_config(foreign_chain_configuration)
                .expect("register should succeed");
        }

        // When
        let result = contract.get_supported_foreign_chains();

        // Then — both chains are supported despite different RPC URLs
        assert!(result.contains(&dtos::ForeignChain::Bitcoin));
        assert!(result.contains(&dtos::ForeignChain::Ethereum));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn get_supported_foreign_chains__should_return_empty_when_no_votes() {
        // Given
        let running_state = gen_running_state(1);
        let contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));

        // When
        let result = contract.get_supported_foreign_chains();

        // Then
        assert!(result.is_empty());
    }

    #[test]
    fn vote_update_foreign_chain_providers__should_apply_chain_and_return_it_when_threshold_reached()
     {
        // Given: a running contract with 4 participants and signing threshold 3.
        let (_context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let participant_account_ids: Vec<AccountId> = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .participants()
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect();
        assert_eq!(participant_account_ids.len(), 4);

        let chain = dtos::ForeignChain::Ethereum;
        let entry = dtos::ChainEntry {
            providers: NonEmptyBTreeMap::new(
                dtos::ProviderId("alchemy".to_string()),
                dtos::ProviderConfig {
                    base_url: "https://alchemy.example.com".to_string(),
                    auth_scheme: dtos::AuthScheme::None,
                    chain_routing: dtos::ChainRouting::Embedded,
                },
            ),
            quorum: 1,
        };
        let batch = NonEmptyBTreeMap::new(chain, entry.clone());

        let vote_as = |contract: &mut MpcContract, account_id: &AccountId| {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_update_foreign_chain_providers(batch.clone())
                .expect("vote should succeed")
        };

        // When: first two participants vote (count = 2, below threshold 3).
        let applied_p0 = vote_as(&mut contract, &participant_account_ids[0]);
        let applied_p1 = vote_as(&mut contract, &participant_account_ids[1]);

        // Then: nothing applied yet.
        assert!(applied_p0.is_empty(), "1st vote should not apply");
        assert!(applied_p1.is_empty(), "2nd vote should not apply");
        assert!(contract.allowed_foreign_chain_providers().is_empty());

        // When: third participant votes (crosses threshold).
        let applied_p2 = vote_as(&mut contract, &participant_account_ids[2]);

        // Then: the chain is reported as applied this call and is now stored.
        assert_eq!(applied_p2, vec![chain]);
        let stored = contract.allowed_foreign_chain_providers();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored.get(&chain), Some(&entry));
    }

    #[test]
    #[should_panic(expected = "not a voter")]
    fn vote_update_foreign_chain_providers__should_panic_when_caller_is_not_a_participant() {
        // Given: a running contract whose participant set does NOT contain `non_participant`.
        let (_context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let non_participant = gen_account_id();

        let batch = NonEmptyBTreeMap::new(
            dtos::ForeignChain::Ethereum,
            dtos::ChainEntry {
                providers: NonEmptyBTreeMap::new(
                    dtos::ProviderId("alchemy".to_string()),
                    dtos::ProviderConfig {
                        base_url: "https://alchemy.example.com".to_string(),
                        auth_scheme: dtos::AuthScheme::None,
                        chain_routing: dtos::ChainRouting::Embedded,
                    },
                ),
                quorum: 1,
            },
        );

        // When: a non-participant attempts to vote — voter_or_panic should reject.
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(non_participant.clone())
                .predecessor_account_id(non_participant)
                .build()
        );
        let _ = contract.vote_update_foreign_chain_providers(batch);
    }

    /// Votes `chain` into the on-chain RPC whitelist using the signing threshold of
    /// participants (so the chain becomes whitelisted).
    fn whitelist_chain(contract: &mut MpcContract, chain: dtos::ForeignChain) {
        let entry = dtos::ChainEntry {
            providers: NonEmptyBTreeMap::new(
                dtos::ProviderId("alchemy".to_string()),
                dtos::ProviderConfig {
                    base_url: "https://provider.example.com".to_string(),
                    auth_scheme: dtos::AuthScheme::None,
                    chain_routing: dtos::ChainRouting::Embedded,
                },
            ),
            quorum: 1,
        };
        let batch = NonEmptyBTreeMap::new(chain, entry);
        let threshold = contract.threshold().unwrap().value() as usize;
        for account_id in participant_account_ids(contract).iter().take(threshold) {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_update_foreign_chain_providers(batch.clone())
                .expect("vote should succeed");
        }
    }

    fn register_foreign_chain_config(
        contract: &mut MpcContract,
        account_id: &AccountId,
        chains: impl IntoIterator<Item = dtos::ForeignChain>,
    ) {
        let foreign_chains_config: dtos::ForeignChainsConfig =
            chains.into_iter().collect::<BTreeSet<_>>().into();
        // In mock setup, account_public_key == tls_public_key.
        let tls_key = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .participants()
            .info(account_id)
            .expect("account must be a participant")
            .tls_public_key
            .clone();
        let mut env = Environment::new(None, Some(account_id.clone()), None);
        env.set_pk(near_sdk::PublicKey::from(tls_key));
        contract
            .register_foreign_chains_config(foreign_chains_config)
            .expect("register should succeed");
    }

    #[test]
    // Setup with 4 participants, first 3 supporting 4 chains, 4th one supports only 2.
    // Node operator of 4th node spins up new node, and registers config that supports all 4 chains.
    // Available chains should still be 2.
    // Node operator of 4th node migrates node to new node, and new node becomes participant,
    // then all 4 chains should be supported.
    fn get_available_foreign_chains__should_not_count_non_participant_node_config() {
        // Given: 4 participants, threshold 4 (all must agree); 4 chains whitelisted.
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let all_chains = [
            dtos::ForeignChain::Bitcoin,
            dtos::ForeignChain::Ethereum,
            dtos::ForeignChain::Solana,
            dtos::ForeignChain::Bnb,
        ];
        let partial_chains = [dtos::ForeignChain::Bitcoin, dtos::ForeignChain::Ethereum];
        for chain in all_chains {
            whitelist_chain(&mut contract, chain);
        }

        // Raise both the governance threshold and ForeignTx domain threshold to 4 so that all
        // participants must cover a chain for it to be available.
        {
            let ProtocolContractState::Running(ref mut state) = contract.protocol_state else {
                panic!("expected Running");
            };
            state.parameters = GovernanceThresholdParameters::new(
                state.parameters.participants().clone(),
                GovernanceThreshold::new(4),
            )
            .unwrap();
            for domain in state.domains.domains_mut() {
                if domain.purpose == DomainPurpose::ForeignTx {
                    domain.reconstruction_threshold = ReconstructionThreshold::new(4);
                }
            }
        }

        let participants = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .participants()
            .clone();
        let participant_ids = participant_account_ids(&contract);

        // Nodes 1-3 cover all 4 chains.
        for account_id in participant_ids.iter().take(3) {
            register_foreign_chain_config(&mut contract, account_id, all_chains);
        }

        // Node 4 (active participant) only covers 2 chains.
        let operator4 = &participant_ids[3];
        register_foreign_chain_config(&mut contract, operator4, partial_chains);

        // Operator 4's new migration node (not yet a participant) covers all 4 chains and registers.
        let new_tls_key = dtos::Ed25519PublicKey([99u8; 32]);
        let new_signer_pk = dtos::Ed25519PublicKey([98u8; 32]);
        contract.tee_state.stored_attestations.insert(
            new_tls_key.clone(),
            NodeAttestation {
                node_id: NodeId {
                    account_id: operator4.clone(),
                    tls_public_key: new_tls_key.clone(),
                    account_public_key: new_signer_pk.clone(),
                },
                verified_attestation: VerifiedAttestation::Mock(MpcMockAttestation::Valid),
            },
        );
        let foreign_chains_config: dtos::ForeignChainsConfig =
            all_chains.into_iter().collect::<BTreeSet<_>>().into();
        let mut env = Environment::new(None, Some(operator4.clone()), None);
        env.set_pk(near_sdk::PublicKey::from(new_signer_pk));
        contract
            .register_foreign_chains_config(foreign_chains_config)
            .expect("new node of same operator should be able to register");

        // Then: only 2 chains available — new node's config doesn't count since it's not a participant.
        let available = contract.get_available_foreign_chains();
        assert_eq!(available.len(), 2);
        assert!(available.contains(&dtos::ForeignChain::Bitcoin));
        assert!(available.contains(&dtos::ForeignChain::Ethereum));

        // When: migration completes — participant 4's TLS key is updated to the new node.
        let old_info = participants.info(operator4).unwrap().clone();
        let new_info = ParticipantInfo {
            tls_public_key: new_tls_key,
            ..old_info
        };
        {
            let ProtocolContractState::Running(ref mut state) = contract.protocol_state else {
                panic!("expected Running");
            };
            // Reconstruct GovernanceThresholdParameters with the updated participants.
            let mut updated_participants = state.parameters.participants().clone();
            updated_participants
                .update_info(operator4.clone(), new_info)
                .unwrap();
            state.parameters = GovernanceThresholdParameters::new(
                updated_participants,
                GovernanceThreshold::new(4),
            )
            .unwrap();
        }
        contract.recompute_available_foreign_chains();

        // Then: all 4 chains are now available.
        let available = contract.get_available_foreign_chains();
        assert_eq!(available.len(), 4);
    }

    #[test]
    fn conclude_node_migration__should_recompute_available_foreign_chains() {
        // Given: 4 participants, threshold 4; 4 chains whitelisted.
        // Node 4 supports only 2 chains.
        // Node 4's operator migrates to a new node that supports all 4 chains.
        // After conclude_node_migration the cache must reflect 4 chains without a manual recompute.
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let all_chains = [
            dtos::ForeignChain::Bitcoin,
            dtos::ForeignChain::Ethereum,
            dtos::ForeignChain::Solana,
            dtos::ForeignChain::Bnb,
        ];
        let partial_chains = [dtos::ForeignChain::Bitcoin, dtos::ForeignChain::Ethereum];
        for chain in all_chains {
            whitelist_chain(&mut contract, chain);
        }
        {
            let ProtocolContractState::Running(ref mut state) = contract.protocol_state else {
                panic!("expected Running");
            };
            state.parameters = GovernanceThresholdParameters::new(
                state.parameters.participants().clone(),
                GovernanceThreshold::new(4),
            )
            .unwrap();
            for domain in state.domains.domains_mut() {
                if domain.purpose == DomainPurpose::ForeignTx {
                    domain.reconstruction_threshold = ReconstructionThreshold::new(4);
                }
            }
        }
        let participant_ids = participant_account_ids(&contract);
        for account_id in participant_ids.iter().take(3) {
            register_foreign_chain_config(&mut contract, account_id, all_chains);
        }
        let operator4 = &participant_ids[3];
        register_foreign_chain_config(&mut contract, operator4, partial_chains);

        let available = contract.get_available_foreign_chains();
        assert_eq!(
            available.len(),
            2,
            "only partial chains available before migration"
        );

        // When: operator 4 migrates to a new node that supports all 4 chains.
        let (_, new_participant_info) = gen_participant(100);
        let new_tls_key = new_participant_info.tls_public_key.clone();
        let new_signer_pk = bogus_ed25519_public_key();
        let new_signer_near_pk = near_sdk::PublicKey::from(new_signer_pk.clone());
        let destination_node_info = DestinationNodeInfo {
            signer_account_pk: new_signer_pk.clone(),
            destination_node_info: new_participant_info.into(),
        };

        // Add attestation for the new node (mirrors what ConcludeNodeMigrationTestSetup::setup does).
        contract
            .tee_state
            .verify_and_store_mock(
                NodeId {
                    account_id: operator4.clone(),
                    tls_public_key: new_tls_key.clone(),
                    account_public_key: new_signer_pk.clone(),
                },
                MpcMockAttestation::Valid,
                Duration::from_secs(contract.config.tee_upgrade_deadline_duration_seconds),
            )
            .expect("attestation insertion should succeed");

        // New node pre-registers its config.
        let mut env = Environment::new(None, Some(operator4.clone()), None);
        env.set_pk(new_signer_near_pk.clone());
        let full_config: dtos::ForeignChainsConfig =
            all_chains.into_iter().collect::<BTreeSet<_>>().into();
        contract
            .register_foreign_chains_config(full_config)
            .expect("new node should be able to register");

        let keyset = match &contract.protocol_state {
            ProtocolContractState::Running(s) => s.keyset.clone(),
            _ => panic!("expected Running"),
        };
        contract
            .node_migrations
            .set_destination_node_info(operator4.clone(), destination_node_info);
        let mut env = Environment::new(None, Some(operator4.clone()), None);
        env.set_pk(new_signer_near_pk);
        contract
            .conclude_node_migration(&keyset)
            .expect("migration should succeed");

        // Then: all 4 chains available — no manual recompute needed.
        let available = contract.get_available_foreign_chains();
        assert_eq!(available.len(), 4);
    }

    #[test]
    fn get_available_foreign_chains__should_include_chain_when_at_least_threshold_participants_cover_it()
     {
        // Given: 4 participants, signing threshold 3; Bitcoin whitelisted.
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);

        // When: exactly the threshold (3) of 4 participants cover Bitcoin — one node does not.
        for account_id in participants.iter().take(3) {
            register_foreign_chain_config(&mut contract, account_id, [dtos::ForeignChain::Bitcoin]);
        }

        // Then: Bitcoin is available. A single non-covering node cannot take it down — the
        // regression the legacy intersection rule had.
        let available = contract.get_available_foreign_chains();
        assert!(available.contains(&dtos::ForeignChain::Bitcoin));
        assert_eq!(available.len(), 1);
    }

    #[test]
    fn get_available_foreign_chains__should_exclude_chain_when_fewer_than_threshold_cover_it() {
        // Given: 4 participants, threshold 3; Bitcoin whitelisted.
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);

        // When: only 2 of 4 (< threshold) cover Bitcoin.
        for account_id in participants.iter().take(2) {
            register_foreign_chain_config(&mut contract, account_id, [dtos::ForeignChain::Bitcoin]);
        }

        // Then: Bitcoin is not available.
        let available = contract.get_available_foreign_chains();
        assert!(!available.contains(&dtos::ForeignChain::Bitcoin));
        assert!(available.is_empty());
    }

    #[test]
    fn get_available_foreign_chains__should_exclude_chain_that_is_covered_but_not_whitelisted() {
        // Given: 4 participants, threshold 3; Bitcoin is NOT whitelisted.
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let participants = participant_account_ids(&contract);

        // When: all 4 participants cover Bitcoin.
        for account_id in &participants {
            register_foreign_chain_config(&mut contract, account_id, [dtos::ForeignChain::Bitcoin]);
        }

        // Then: Bitcoin is still not available — `available` is a subset of `whitelisted`.
        let available = contract.get_available_foreign_chains();
        assert!(available.is_empty());
    }

    #[test]
    fn get_available_foreign_chains__should_only_include_whitelisted_chains_with_threshold_coverage()
     {
        // Given: 4 participants, threshold 3. Bitcoin and Ethereum are whitelisted; Solana is not.
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);
        whitelist_chain(&mut contract, dtos::ForeignChain::Ethereum);

        // When (each participant registers its full covered set in one call, since a
        // registration replaces the participant's previously reported set):
        // - Bitcoin: covered by 3 participants (whitelisted + threshold) -> available.
        // - Ethereum: covered by 1 participant (whitelisted but under threshold) -> not available.
        // - Solana: covered by all 4 (threshold met but not whitelisted) -> not available.
        register_foreign_chain_config(
            &mut contract,
            &participants[0],
            [
                dtos::ForeignChain::Bitcoin,
                dtos::ForeignChain::Ethereum,
                dtos::ForeignChain::Solana,
            ],
        );
        register_foreign_chain_config(
            &mut contract,
            &participants[1],
            [dtos::ForeignChain::Bitcoin, dtos::ForeignChain::Solana],
        );
        register_foreign_chain_config(
            &mut contract,
            &participants[2],
            [dtos::ForeignChain::Bitcoin, dtos::ForeignChain::Solana],
        );
        register_foreign_chain_config(
            &mut contract,
            &participants[3],
            [dtos::ForeignChain::Solana],
        );

        // Then: only Bitcoin is available.
        let available = contract.get_available_foreign_chains();
        assert!(available.contains(&dtos::ForeignChain::Bitcoin));
        assert!(!available.contains(&dtos::ForeignChain::Ethereum));
        assert!(!available.contains(&dtos::ForeignChain::Solana));
        assert_eq!(available.len(), 1);
    }

    #[test]
    fn vote_update_foreign_chain_providers__should_populate_available_set_when_whitelisting_covered_chain()
     {
        // Given: 4 participants, threshold 3. Bitcoin is NOT yet whitelisted.
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let participants = participant_account_ids(&contract);

        // GovernanceThreshold (3) participants already cover Bitcoin — but the chain is not whitelisted,
        // so the cache must be empty.
        for account_id in participants.iter().take(3) {
            register_foreign_chain_config(&mut contract, account_id, [dtos::ForeignChain::Bitcoin]);
        }
        assert!(contract.get_available_foreign_chains().is_empty());

        // When: whitelist Bitcoin (vote_update_foreign_chain_providers triggers a recompute).
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);

        // Then: cache flips from empty to populated.
        let available = contract.get_available_foreign_chains();
        assert!(available.contains(&dtos::ForeignChain::Bitcoin));
        assert_eq!(available.len(), 1);
    }

    #[test]
    fn clean_foreign_chain_data__should_drop_departed_participant_contribution_from_cache() {
        // Given: 4 participants, threshold 3, Bitcoin whitelisted.
        // Exactly 3 participants (0, 1, 2) cover Bitcoin → threshold met → available.
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);
        for account_id in participants.iter().take(3) {
            register_foreign_chain_config(&mut contract, account_id, [dtos::ForeignChain::Bitcoin]);
        }
        assert!(
            contract
                .get_available_foreign_chains()
                .contains(&dtos::ForeignChain::Bitcoin)
        );

        // Simulate resharing completion: the new Running state drops participant[2] and keeps
        // participant[3] (who has not registered any chain).  Participant[2]'s registration
        // entry is still in foreign_chains_configs — this is the stale data that
        // clean_foreign_chain_data must remove.
        let (domains, keyset) = {
            let ProtocolContractState::Running(ref state) = contract.protocol_state else {
                panic!("expected Running state");
            };
            (state.domains.clone(), state.keyset.clone())
        };
        let mut new_participants = {
            let ProtocolContractState::Running(ref state) = contract.protocol_state else {
                panic!("expected Running state");
            };
            state.parameters.participants().clone()
        };
        new_participants.remove(&participants[2]);
        // New Running: participants {0, 1, 3}, threshold 3.  Only 0 and 1 cover Bitcoin → 2 < 3.
        let new_params = GovernanceThresholdParameters::new_unvalidated(
            new_participants,
            GovernanceThreshold::new(3),
        );
        contract.protocol_state = ProtocolContractState::Running(RunningContractState::new(
            domains,
            keyset,
            new_params,
            AddDomainsVotes::default(),
        ));

        // When: vote_reshared recomputes the cache, then clean_foreign_chain_data
        // prunes participant[2]'s stale storage entry.
        contract.recompute_available_foreign_chains();
        contract
            .clean_foreign_chain_data()
            .expect("clean should succeed");

        // Then: 2 participants cover Bitcoin (< threshold 3) → no longer available.
        let available = contract.get_available_foreign_chains();
        assert!(!available.contains(&dtos::ForeignChain::Bitcoin));
        assert!(available.is_empty());
    }

    #[test]
    fn recompute_available_foreign_chains__should_update_cache_during_resharing() {
        // Given: Running contract with Bitcoin whitelisted; threshold 3, only 2 participants
        // registered → Bitcoin not yet available.
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);
        for account_id in participants.iter().take(2) {
            register_foreign_chain_config(&mut contract, account_id, [dtos::ForeignChain::Bitcoin]);
        }
        assert!(contract.get_available_foreign_chains().is_empty());

        // Transition to Resharing. Use the same participant set so mocked attestations remain valid.
        let resharing = {
            let ProtocolContractState::Running(ref mut state) = contract.protocol_state else {
                panic!("expected Running state");
            };
            let proposal = ProposedGovernanceThresholdParameters::new(
                state.parameters.clone(),
                BTreeMap::new(),
            );
            state
                .transition_to_resharing_no_checks(&proposal)
                .expect("contract has at least one domain")
        };
        contract.protocol_state = ProtocolContractState::Resharing(resharing);

        // When: the 3rd participant (from the old running set) registers during Resharing.
        register_foreign_chain_config(
            &mut contract,
            &participants[2],
            [dtos::ForeignChain::Bitcoin],
        );

        // Then: cache updated using the embedded previous running-state — Bitcoin now available.
        assert!(
            contract
                .get_available_foreign_chains()
                .contains(&dtos::ForeignChain::Bitcoin)
        );
    }

    #[test]
    fn recompute_available_foreign_chains__should_use_domain_threshold_not_governance_threshold() {
        // Given: 4 participants, governance threshold=3, ForeignTx domain reconstruction_threshold=2.
        // Only 2 supporters will register — below governance threshold but meets domain threshold.
        let contract_account_id = AccountId::from_str("contract_account.near").unwrap();
        testing_env!(
            VMContextBuilder::new()
                .attached_deposit(NearToken::from_yoctonear(1))
                .predecessor_account_id(contract_account_id.clone())
                .current_account_id(contract_account_id)
                .build()
        );
        let domain_id = DomainId::default();
        let domains = vec![DomainConfig {
            id: domain_id,
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(2),
            purpose: DomainPurpose::ForeignTx,
        }];
        let (pk, _sk) = make_public_key_for_curve(Curve::Secp256k1, &mut OsRng);
        let key_for_domain = KeyForDomain {
            domain_id,
            key: pk.try_into().unwrap(),
            attempt: AttemptId::new(),
        };
        let keyset = Keyset::new(EpochId::new(0), vec![key_for_domain]);
        let parameters =
            GovernanceThresholdParameters::new(gen_participants(4), GovernanceThreshold::new(3))
                .unwrap();
        let mut contract =
            MpcContract::init_running(domains, 1, keyset, (&parameters).into_dto_type(), None)
                .unwrap();
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);

        // When: exactly 2 participants register Bitcoin (meets domain threshold=2, below governance threshold=3).
        register_foreign_chain_config(
            &mut contract,
            &participants[0],
            [dtos::ForeignChain::Bitcoin],
        );
        register_foreign_chain_config(
            &mut contract,
            &participants[1],
            [dtos::ForeignChain::Bitcoin],
        );

        // Then: Bitcoin is available — the ForeignTx domain threshold (2) is used, not governance (3).
        assert!(
            contract
                .get_available_foreign_chains()
                .contains(&dtos::ForeignChain::Bitcoin),
            "chain should be available at domain threshold=2 even though governance threshold=3"
        );
    }

    #[test]
    fn recompute_available_foreign_chains__should_use_max_threshold_across_foreign_tx_domains() {
        // Given
        // The lower-threshold domain is listed first so a regression to `.find()` would pick
        // threshold=2, whereas `.max()` across both foreign-tx domains picks threshold=3.
        let contract_account_id = AccountId::from_str("contract_account.near").unwrap();
        testing_env!(
            VMContextBuilder::new()
                .attached_deposit(NearToken::from_yoctonear(1))
                .predecessor_account_id(contract_account_id.clone())
                .current_account_id(contract_account_id)
                .build()
        );
        let foreign_tx_domain = |id: u64, threshold: u64| DomainConfig {
            id: DomainId(id),
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(threshold),
            purpose: DomainPurpose::ForeignTx,
        };
        let domains = vec![foreign_tx_domain(0, 2), foreign_tx_domain(1, 3)];
        let keys_for_domains = domains
            .iter()
            .map(|domain| {
                let (pk, _sk) = make_public_key_for_curve(Curve::Secp256k1, &mut OsRng);
                KeyForDomain {
                    domain_id: domain.id,
                    key: pk.try_into().unwrap(),
                    attempt: AttemptId::new(),
                }
            })
            .collect();
        let keyset = Keyset::new(EpochId::new(0), keys_for_domains);
        let parameters =
            GovernanceThresholdParameters::new(gen_participants(4), GovernanceThreshold::new(3))
                .unwrap();
        let mut contract =
            MpcContract::init_running(domains, 2, keyset, (&parameters).into_dto_type(), None)
                .unwrap();
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);

        // When
        let bitcoin_available = |contract: &MpcContract| {
            contract
                .get_available_foreign_chains()
                .contains(&dtos::ForeignChain::Bitcoin)
        };
        register_foreign_chain_config(
            &mut contract,
            &participants[0],
            [dtos::ForeignChain::Bitcoin],
        );
        register_foreign_chain_config(
            &mut contract,
            &participants[1],
            [dtos::ForeignChain::Bitcoin],
        );
        let available_below_threshold = bitcoin_available(&contract);
        register_foreign_chain_config(
            &mut contract,
            &participants[2],
            [dtos::ForeignChain::Bitcoin],
        );
        let available_at_threshold = bitcoin_available(&contract);

        // Then
        assert!(
            !available_below_threshold,
            "2 supporters is below the max foreign-tx threshold (3)"
        );
        assert!(
            available_at_threshold,
            "3 supporters meets the max foreign-tx threshold (3)"
        );
    }

    #[test]
    fn register_foreign_chains_config__should_succeed_for_new_participant_during_resharing() {
        // Given: Running contract; transition to Resharing whose proposed set adds a new participant
        // not present in the old running set.
        let (_context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let (new_account_id, new_info) = gen_participant(100);
        let mut new_participants = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .participants()
            .clone();
        new_participants
            .insert(new_account_id.clone(), new_info)
            .expect("new participant should be inserted");
        let new_params = GovernanceThresholdParameters::new(
            new_participants.clone(),
            GovernanceThreshold::new(3),
        )
        .unwrap();
        let new_proposal = ProposedGovernanceThresholdParameters::new(new_params, BTreeMap::new());

        let resharing = {
            let ProtocolContractState::Running(ref mut state) = contract.protocol_state else {
                panic!("expected Running state");
            };
            state
                .transition_to_resharing_no_checks(&new_proposal)
                .expect("contract has at least one domain")
        };
        contract.protocol_state = ProtocolContractState::Resharing(resharing);
        // Provide mocked attestations for every participant in the proposed new set,
        // including the newly added one.
        contract.tee_state = TeeState::with_mocked_participant_attestations(&new_participants);

        // When: the new participant (not in the old running set) registers its foreign chain config.
        let foreign_chains_config: dtos::ForeignChainsConfig =
            BTreeSet::from([dtos::ForeignChain::Bitcoin]).into();
        let new_tls_key = new_participants
            .info(&new_account_id)
            .unwrap()
            .tls_public_key
            .clone();
        let mut env = Environment::new(None, Some(new_account_id.clone()), None);
        // Set the signer pk to the new participant's TLS key, which is also its account_public_key
        // in the mocked attestation, so lookup_node_id_by_signer_pk finds exactly this participant.
        env.set_pk(near_sdk::PublicKey::from(new_tls_key.clone()));

        // Then: the call succeeds — new participant is in the proposed set.
        contract
            .register_foreign_chains_config(foreign_chains_config)
            .expect("new participant should be able to register during Resharing");
        assert!(
            contract
                .foreign_chains
                .get()
                .foreign_chains_configs
                .contains_key(&new_tls_key),
            "config should be stored under the new participant's TLS key"
        );
    }

    #[test]
    fn register_foreign_chains_config__should_allow_two_nodes_from_same_operator_to_register_config()
     {
        // Given: Running contract; pick one operator account.
        let (_context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let participants = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .participants()
            .clone();
        let (operator_account, _, info) = participants.participants().iter().next().unwrap();
        let tls_key_a = info.tls_public_key.clone();

        // Simulate a second node for the same operator with a distinct TLS key and signer pk.
        let tls_key_b = dtos::Ed25519PublicKey([99u8; 32]);
        let signer_pk_b = dtos::Ed25519PublicKey([98u8; 32]);
        contract.tee_state.stored_attestations.insert(
            tls_key_b.clone(),
            NodeAttestation {
                node_id: NodeId {
                    account_id: operator_account.clone(),
                    tls_public_key: tls_key_b.clone(),
                    account_public_key: signer_pk_b.clone(),
                },
                verified_attestation: VerifiedAttestation::Mock(MpcMockAttestation::Valid),
            },
        );

        // When: node A (the registered participant node) registers its config.
        register_foreign_chain_config(
            &mut contract,
            operator_account,
            [dtos::ForeignChain::Bitcoin],
        );

        // When: node B (the migration candidate, same operator) registers its config.
        let foreign_chains_config: dtos::ForeignChainsConfig =
            BTreeSet::from([dtos::ForeignChain::Bitcoin]).into();
        let mut env = Environment::new(None, Some(operator_account.clone()), None);
        env.set_pk(near_sdk::PublicKey::from(signer_pk_b));
        contract
            .register_foreign_chains_config(foreign_chains_config)
            .expect("second node from same operator should be able to register");

        // Then: both nodes' configs exist independently.
        let configs = &contract.foreign_chains.get().foreign_chains_configs;
        assert!(configs.contains_key(&tls_key_a), "node A config must exist");
        assert!(configs.contains_key(&tls_key_b), "node B config must exist");
    }
}
