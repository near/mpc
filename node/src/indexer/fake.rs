use super::handler::{ChainBlockUpdate, SignatureRequestFromChain};
use super::participants::ContractState;
use super::types::{ChainRespondArgs, ChainSendTransactionRequest};
use super::IndexerAPI;
use crate::config::ParticipantsConfig;
use crate::sign_request::SignatureId;
use crate::signing::recent_blocks_tracker::tests::TestBlockMaker;
use crate::tracking::{AutoAbortTask, AutoAbortTaskCollection};
use mpc_contract::config::Config;
use mpc_contract::primitives::{
    domain::{DomainConfig, DomainRegistry},
    key_state::{EpochId, KeyEventId, Keyset},
    participants::{ParticipantId, ParticipantInfo, Participants},
    signature::Payload,
    thresholds::{Threshold, ThresholdParameters},
};
use mpc_contract::state::{
    initializing::InitializingContractState, key_event::tests::Environment, key_event::KeyEvent,
    resharing::ResharingContractState, running::RunningContractState, ProtocolContractState,
};
use near_crypto::PublicKey;
use near_sdk::AccountId;
use near_time::{Clock, Duration};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{atomic::AtomicBool, Arc};
use tokio::sync::{broadcast, mpsc, watch};

/// A simplification of the real MPC contract state for testing.
pub struct FakeMpcContractState {
    pub state: ProtocolContractState,
    config: Config,
    env: Environment,
    pub pending_signatures: BTreeMap<Payload, SignatureId>,
}

impl FakeMpcContractState {
    pub fn new() -> Self {
        let state = ProtocolContractState::NotInitialized;
        let config = Config {
            key_event_timeout_blocks: 10,
        };
        let block_timestamp = 1757785600_u64 * 1_000_000_u64; // 2025-05-21 00:00:00 UTC to ensure TEE quote verification succeeds
        let env = Environment::new(None, None, None, Some(block_timestamp));
        Self {
            state,
            config,
            env,
            pending_signatures: BTreeMap::new(),
        }
    }

    pub fn initialize(&mut self, participants: ParticipantsConfig) {
        assert!(matches!(self.state, ProtocolContractState::NotInitialized));

        self.state = ProtocolContractState::Running(RunningContractState::new(
            DomainRegistry::default(),
            Keyset::new(EpochId::new(0), Vec::new()),
            participants_config_to_threshold_parameters(&participants),
        ));
    }

    pub fn add_domains(&mut self, domains: Vec<DomainConfig>) {
        let state = match &mut self.state {
            ProtocolContractState::Running(state) => state,
            _ => panic!("Cannot add domains to non-running state"),
        };
        let new_state = InitializingContractState {
            domains: state
                .domains
                .add_domains(domains.clone())
                .expect("Failed to add domains"),
            epoch_id: state.keyset.epoch_id,
            generated_keys: state.keyset.domains.clone(),
            generating_key: KeyEvent::new(
                state.keyset.epoch_id,
                domains[0].clone(),
                state.parameters.clone(),
            ),
            cancel_votes: BTreeSet::new(),
        };
        self.state = ProtocolContractState::Initializing(new_state);
    }

    pub fn start_resharing(&mut self, new_participants: ParticipantsConfig) {
        let (previous_running_state, prev_epoch_id) = match &self.state {
            ProtocolContractState::Running(state) => (state, state.keyset.epoch_id),
            ProtocolContractState::Resharing(state) => {
                (&state.previous_running_state, state.prospective_epoch_id())
            }
            _ => panic!("Cannot start resharing from non-running state"),
        };
        self.state = ProtocolContractState::Resharing(ResharingContractState {
            previous_running_state: RunningContractState::new(
                previous_running_state.domains.clone(),
                previous_running_state.keyset.clone(),
                previous_running_state.parameters.clone(),
            ),
            reshared_keys: Vec::new(),
            resharing_key: KeyEvent::new(
                prev_epoch_id.next(),
                previous_running_state
                    .domains
                    .get_domain_by_index(0)
                    .unwrap()
                    .clone(),
                participants_config_to_threshold_parameters(&new_participants),
            ),
        });
    }

    pub fn vote_pk(&mut self, account_id: AccountId, key_id: KeyEventId, pk: PublicKey) {
        let near_sdk_pk: near_sdk::PublicKey = pk.to_string().parse().unwrap();
        let contract_extended_pk = near_sdk_pk.try_into().unwrap();

        match &mut self.state {
            ProtocolContractState::Initializing(state) => {
                self.env.set_signer(&account_id);
                let result = match state.vote_pk(key_id, contract_extended_pk) {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::info!("vote_pk transaction failed: {}", e);
                        return;
                    }
                };
                if let Some(new_state) = result {
                    self.state = ProtocolContractState::Running(new_state);
                }
            }
            _ => {
                tracing::info!(
                    "vote_pk transaction ignored because the contract is not in initializing state"
                );
            }
        }
    }

    pub fn vote_start_keygen(&mut self, account_id: AccountId, id: KeyEventId) {
        match &mut self.state {
            ProtocolContractState::Initializing(state) => {
                self.env.set_signer(&account_id);
                if let Err(e) = state.start(id, self.config.key_event_timeout_blocks) {
                    tracing::info!("vote_start_keygen transaction failed: {}", e);
                }
            }
            _ => {
                tracing::info!(
                    "vote_start_keygen transaction ignored because the contract is not in initializing state"
                );
            }
        }
    }

    pub fn vote_abort_key_event(&mut self, account_id: AccountId, id: KeyEventId) {
        self.env.set_signer(&account_id);
        match &mut self.state {
            ProtocolContractState::Initializing(state) => {
                if let Err(e) = state.vote_abort(id) {
                    tracing::info!("vote_abort_key_event transaction failed: {}", e);
                }
            }
            ProtocolContractState::Resharing(state) => {
                if let Err(e) = state.vote_abort(id) {
                    tracing::info!("vote_abort_key_event transaction failed: {}", e);
                }
            }
            _ => {
                tracing::info!(
                    "vote_abort_key_event transaction ignored because the contract is not in initializing or resharing state"
                );
            }
        }
    }

    pub fn vote_start_reshare(&mut self, account_id: AccountId, id: KeyEventId) {
        match &mut self.state {
            ProtocolContractState::Resharing(state) => {
                self.env.set_signer(&account_id);
                if let Err(e) = state.start(id, self.config.key_event_timeout_blocks) {
                    tracing::info!("vote_start_reshare transaction failed: {}", e);
                }
            }
            _ => {
                tracing::info!(
                    "vote_start_reshare transaction ignored because the contract is not in resharing state"
                );
            }
        }
    }

    pub fn vote_reshared(&mut self, account_id: AccountId, key_id: KeyEventId) {
        match &mut self.state {
            ProtocolContractState::Resharing(state) => {
                self.env.set_signer(&account_id);
                let result = match state.vote_reshared(key_id) {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::info!("vote_reshared transaction failed: {}", e);
                        return;
                    }
                };
                if let Some(new_state) = result {
                    self.state = ProtocolContractState::Running(new_state);
                }
            }
            _ => {
                tracing::info!(
                    "vote_reshared transaction ignored because the contract is not in resharing state"
                );
            }
        }
    }
}

fn participants_config_to_threshold_parameters(
    participants_config: &ParticipantsConfig,
) -> ThresholdParameters {
    let mut participants = Participants::new();
    let mut infos = participants_config.participants.clone();
    infos.sort_by_key(|info| info.id);
    let quote_collateral = json!({"tcb_info_issuer_chain":"-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNTAxMFoXDTI1MDUyMTEwNTAxMFowbDEeMBwG\nA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw\nb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD\nVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv\nP+mAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh/zN3C4xvpoouGlirMba+W2lju\nypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f\nBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz\nLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK\nQEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG\nSM49BAMCA0cAMEQCIB9C8wOAN/ImxDtGACV246KcqjagZOR0kyctyBrsGGJVAiAj\nftbrNGsGU8YH211dRiYNoPPu19Zp/ze8JmhujB0oBw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\nAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n","tcb_info":"{\"id\":\"TDX\",\"version\":3,\"issueDate\":\"2025-03-11T00:36:15Z\",\"nextUpdate\":\"2025-04-10T00:36:15Z\",\"fmspc\":\"20a06f000000\",\"pceId\":\"0000\",\"tcbType\":0,\"tcbEvaluationDataNumber\":17,\"tdxModule\":{\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\"},\"tdxModuleIdentities\":[{\"id\":\"TDX_03\",\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\",\"tcbLevels\":[{\"tcb\":{\"isvsvn\":3},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"}]},{\"id\":\"TDX_01\",\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\",\"tcbLevels\":[{\"tcb\":{\"isvsvn\":4},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"},{\"tcb\":{\"isvsvn\":2},\"tcbDate\":\"2023-08-09T00:00:00Z\",\"tcbStatus\":\"OutOfDate\"}]}],\"tcbLevels\":[{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":2,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":255,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":13,\"tdxtcbcomponents\":[{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":2,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":255,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":5,\"tdxtcbcomponents\":[{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2018-01-04T00:00:00Z\",\"tcbStatus\":\"OutOfDate\"}]}","tcb_info_signature":"dff1380a12d533bff4ad7f69fd0355ad97ff034b42c8269e26e40e3d585dffff3e55bf21f8cda481d3c163fafcd4eab11c8818ba6aa7553ba6866bce06b56a95","qe_identity_issuer_chain":"-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNTAxMFoXDTI1MDUyMTEwNTAxMFowbDEeMBwG\nA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw\nb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD\nVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv\nP+mAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh/zN3C4xvpoouGlirMba+W2lju\nypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f\nBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz\nLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK\nQEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG\nSM49BAMCA0cAMEQCIB9C8wOAN/ImxDtGACV246KcqjagZOR0kyctyBrsGGJVAiAj\nftbrNGsGU8YH211dRiYNoPPu19Zp/ze8JmhujB0oBw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\nAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n","qe_identity":"{\"id\":\"TD_QE\",\"version\":2,\"issueDate\":\"2025-03-10T23:38:16Z\",\"nextUpdate\":\"2025-04-09T23:38:16Z\",\"tcbEvaluationDataNumber\":17,\"miscselect\":\"00000000\",\"miscselectMask\":\"FFFFFFFF\",\"attributes\":\"11000000000000000000000000000000\",\"attributesMask\":\"FBFFFFFFFFFFFFFF0000000000000000\",\"mrsigner\":\"DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5\",\"isvprodid\":2,\"tcbLevels\":[{\"tcb\":{\"isvsvn\":4},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"}]}","qe_identity_signature":"920d5f18df6da142a667caf71844d45dfd4de3e3b14f846bae92a3e52a9c765d855b9a8b4b54307dd3feae30f28f09888a3200c29584d7c50d42f85275afe6cc"});
    let quote_collateral = quote_collateral.to_string();
    let quote_hex = "040002008100000000000000939a7233f79c4ca9940a0db3957f0607ac666ed993e70e31ff5f5a8a2c743b220000000007010300000000000000000000000000c51e5cb16c461fe29b60394984755325ecd05a9a7a8fb3a116f1c3cf0aca4b0eb9edefb9b404deeaee4b7d454372d17a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000702000000000000c68518a0ebb42136c12b2275164f8c72f25fa9a34392228687ed6e9caeb9c0f1dbd895e9cf475121c029dc47e70e91fd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000085e0855a6384fa1c8a6ab36d0dcbfaa11a5753e5a070c08218ae5fe872fcb86967fd2449c29e22e59dc9fec998cb65474a7db64a609c77e85f603c23e9a9fd03bfd9e6b52ce527f774a598e66d58386026cea79b2aea13b81a0b70cfacdec0ca8a4fe048fea22663152ef128853caa5c033cbe66baf32ba1ff7f6b1afc1624c279f50a4cbc522a735ca6f69551e61ef2561c1b02351cd6f7c803dd36bc95ba25463aa025ce7761156260c9131a5d7c03aeccc10e12160ec3205bb2876a203a7fb81447910d62fd92897d68b1f51d54fb75dfe2aeba3a97a879cba59a771fc522d88046cc26b407d723f726fae17c3e5a50529d0b6c2b991d027f06a9b430d43ecc1000003bdd12b68ee3cfc93a1758479840b6f8734c2439106d8f0faa50ac919d86ea101c002c41d262670ad84afb8f9ee35c7abbb72dcc01bbc3e3a3773672d665005ee6bcb0c5f4b03f0563c797747f7ddd25d92d4f120bee4a829daca986bbc03c155b3d158f6a386bca7ee49ceb3ec31494b792e0cf22fc4e561ddc57156da1b77a0600461000000303070704ff00020000000000000000000000000000000000000000000000000000000000000000000000000000000015000000000000000700000000000000e5a3a7b5d830c2953b98534c6c59a3a34fdc34e933f7f5898f0a85cf08846bca0000000000000000000000000000000000000000000000000000000000000000dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005d2eb8ae211693884eadaea0be0392c5532c7ff55429e4696c84954444d62ed600000000000000000000000000000000000000000000000000000000000000004f1cd2dde7dd5d4a9a495815f3ac76c56a77a9e06a5279a8c8550b54cf2d7287a630c3b9aefb94b1b6e8491eba4b43baa811c8f44167eb7d9ca933678ea64f5b2000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f05005e0e00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49494538544343424a656741774942416749554439426b736e734170713045567861464a59785a56794f6774664d77436759494b6f5a497a6a3045417749770a634445694d434147413155454177775a535735305a577767553064594946424453794251624746305a6d397962534244515445614d42674741315545436777520a535735305a577767513239796347397959585270623234784644415342674e564241634d43314e68626e526849454e7359584a684d51737743515944565151490a44414a445154454c4d416b474131554542684d4356564d774868634e4d6a55774d6a41334d5463774f4441325768634e4d7a49774d6a41334d5463774f4441320a576a42774d534977494159445651514444426c4a626e526c624342545231676755454e4c49454e6c636e52705a6d6c6a5958526c4d526f77474159445651514b0a4442464a626e526c6243424462334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e560a4241674d416b4e424d517377435159445651514745774a56557a425a4d424d4742797147534d34394167454743437147534d34394177454841304941424853770a3977506a72554532734f4a644c5653415434686565414a572b31796c6473615556696b5a4c485832506235777374326a79697539414f5865576a7a6a6d585a4c0a4343742b457858716f53394e45476c6b52724b6a67674d4e4d4949444354416642674e5648534d4547444157674253566231334e765276683655424a796454300a4d383442567776655644427242674e56485238455a4442694d47436758714263686c706f64485277637a6f764c32467761533530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c334e6e6543396a5a584a3061575a7059324630615739754c3359304c33426a61324e796244396a595431770a624746305a6d397962535a6c626d4e765a476c755a7a316b5a584977485159445652304f42425945464d6a464e59626f7464634b636859487258467966774b460a774e534d4d41344741315564447745422f775145417749477744414d42674e5648524d4241663845416a41414d4949434f67594a4b6f5a496876684e415130420a424949434b7a4343416963774867594b4b6f5a496876684e41513042415151514134346b35686a336951797044574873756f5a474144434341575147436971470a534962345451454e41514977676746554d42414743797147534962345451454e41514942416745434d42414743797147534962345451454e41514943416745430a4d42414743797147534962345451454e41514944416745434d42414743797147534962345451454e41514945416745434d42414743797147534962345451454e0a41514946416745434d42454743797147534962345451454e41514947416749412f7a415142677371686b69472b453042445145434277494241444151426773710a686b69472b4530424451454343414942416a415142677371686b69472b45304244514543435149424144415142677371686b69472b45304244514543436749420a4144415142677371686b69472b45304244514543437749424144415142677371686b69472b45304244514543444149424144415142677371686b69472b4530420a44514543445149424144415142677371686b69472b45304244514543446749424144415142677371686b69472b453042445145434477494241444151426773710a686b69472b45304244514543454149424144415142677371686b69472b45304244514543455149424454416642677371686b69472b45304244514543456751510a4167494341674c2f4141494141414141414141414144415142676f71686b69472b45304244514544424149414144415542676f71686b69472b453042445145450a424159676f473841414141774477594b4b6f5a496876684e4151304242516f424154416542676f71686b69472b453042445145474242414b496f456755387a650a486d2b49596f7a686c337a314d45514743697147534962345451454e415163774e6a415142677371686b69472b45304244514548415145422f7a4151426773710a686b69472b45304244514548416745422f7a415142677371686b69472b45304244514548417745422f7a414b42676771686b6a4f5051514441674e49414442460a4169417362735a44796d2f72455a30476c454c62442f6e64755061536a485341746e5871567453313047486255774968414d585666784b334b666f4b675131660a4578397478765331314362363662323467424344523963477942562b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436c6a4343416a32674177494241674956414a567658633239472b487051456e4a3150517a7a674658433935554d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484178496a41670a42674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d45556c75644756730a49454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b474131554543417743513045780a437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741454e53422f377432316c58534f0a3243757a7078773734654a423732457944476757357258437478327456544c7136684b6b367a2b5569525a436e71523770734f766771466553786c6d546c4a6c0a65546d693257597a33714f42757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f536347724442530a42674e5648523845537a424a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e5648513445466751556c5739640a7a62306234656c4153636e553944504f4156634c336c517744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159420a4166384341514177436759494b6f5a497a6a30454177494452774177524149675873566b6930772b6936565947573355462f32327561586530594a446a3155650a6e412b546a44316169356343494359623153416d4435786b66545670766f34556f79695359787244574c6d5552344349394e4b7966504e2b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    for info in infos {
        participants
            .insert_with_id(
                info.near_account_id,
                ParticipantInfo {
                    sign_pk: info.p2p_public_key.to_string().parse().unwrap(),
                    url: format!("http://{}:{}", info.address, info.port),
                    tee_quote: hex::decode(quote_hex).unwrap(),
                    quote_collateral: quote_collateral.clone(),
                },
                ParticipantId(info.id.raw()),
            )
            .expect("Failed to insert participant");
    }
    ThresholdParameters::new(participants, Threshold::new(participants_config.threshold)).unwrap()
}

/// Runs the fake indexer's shared state and logic. There's one instance of this per test.
struct FakeIndexerCore {
    clock: Clock,
    /// Delay (in number of blocks) from when a txn is submitted to when it affects the contract
    /// state.
    txn_delay_blocks: u64,
    /// A fake contract state to emulate the real MPC contract but with much less complexity.
    contract: Arc<tokio::sync::Mutex<FakeMpcContractState>>,
    /// Receives transactions sent via the APIs of each node.
    txn_receiver: mpsc::UnboundedReceiver<(ChainSendTransactionRequest, AccountId)>,
    /// Receives signature requests from the FakeIndexerManager.
    signature_request_receiver: mpsc::UnboundedReceiver<SignatureRequestFromChain>,
    /// Broadcasts the contract state to each node.
    state_change_sender: broadcast::Sender<ContractState>,
    /// Broadcasts block updates to each node.
    block_update_sender: broadcast::Sender<ChainBlockUpdate>,

    /// When the core receives signature response txns, it processes them by sending them through
    /// this sender. The receiver end of this is in FakeIndexManager to be received by the test
    /// code.
    sign_response_sender: mpsc::UnboundedSender<ChainRespondArgs>,
}

impl FakeIndexerCore {
    pub async fn run(mut self) {
        let mut tasks = AutoAbortTaskCollection::new();
        let contract = self.contract.clone();
        tasks.spawn_with_tokio({
            let contract = contract.clone();
            let clock = self.clock.clone();
            let state_change_sender = self.state_change_sender.clone();
            async move {
                loop {
                    {
                        let state = contract.lock().await;
                        let config = ContractState::from_contract_state(
                            &state.state,
                            state.env.block_height,
                            None,
                        )
                        .expect("Failed to convert contract state");
                        state_change_sender.send(config).ok();
                    }
                    clock.sleep(Duration::seconds(1)).await;
                }
            }
        });

        let block_maker = TestBlockMaker::new();
        let mut current_block = block_maker.block(1);
        let mut pending_transactions = VecDeque::new();
        loop {
            loop {
                match self.txn_receiver.try_recv() {
                    Ok((txn, account_id)) => {
                        pending_transactions.push_back((
                            current_block.height() + self.txn_delay_blocks,
                            txn,
                            account_id,
                        ));
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        return;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        break;
                    }
                }
            }

            let block = current_block.child(current_block.height() + 1);

            let mut transactions_to_process = Vec::new();
            while let Some((height, _, _)) = pending_transactions.front() {
                if *height <= block.height() {
                    let (_, txn, account_id) = pending_transactions.pop_front().unwrap();
                    transactions_to_process.push((txn, account_id));
                } else {
                    break;
                }
            }

            let mut signature_requests = Vec::new();
            loop {
                match self.signature_request_receiver.try_recv() {
                    Ok(request) => {
                        signature_requests.push(request);
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        return;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        break;
                    }
                }
            }

            for signature_request in &signature_requests {
                let mut contract = contract.lock().await;
                let signature_id = signature_request.signature_id;
                contract
                    .pending_signatures
                    .insert(signature_request.request.payload.clone(), signature_id);
            }

            let mut block_update = ChainBlockUpdate {
                block: block.to_block_view(),
                signature_requests,
                completed_signatures: Vec::new(),
            };
            contract.lock().await.env.set_block_height(block.height());
            for (txn, account_id) in transactions_to_process {
                match txn {
                    ChainSendTransactionRequest::VotePk(vote_pk) => {
                        let mut contract = contract.lock().await;
                        contract.vote_pk(account_id, vote_pk.key_event_id, vote_pk.public_key);
                    }
                    ChainSendTransactionRequest::Respond(respond) => {
                        let mut contract = contract.lock().await;
                        let signature_id =
                            contract.pending_signatures.remove(&respond.request.payload);
                        if let Some(signature_id) = signature_id {
                            self.sign_response_sender.send(respond.clone()).unwrap();
                            block_update.completed_signatures.push(signature_id);
                        } else {
                            tracing::warn!(
                                "Ignoring respond transaction for unknown (possibly already-responded-to) signature: {:?}",
                                respond.request.payload
                            );
                        }
                    }
                    ChainSendTransactionRequest::VoteReshared(reshared) => {
                        let mut contract = contract.lock().await;
                        contract.vote_reshared(account_id, reshared.key_event_id);
                    }
                    ChainSendTransactionRequest::StartKeygen(start) => {
                        // todo: timeout logic in fake indexer?
                        let mut contract = contract.lock().await;
                        contract.vote_start_keygen(account_id, start.key_event_id);
                    }
                    ChainSendTransactionRequest::StartReshare(start) => {
                        let mut contract = contract.lock().await;
                        contract.vote_start_reshare(account_id, start.key_event_id);
                    }
                    ChainSendTransactionRequest::VoteAbortKeyEvent(abort) => {
                        let mut contract = contract.lock().await;
                        contract.vote_abort_key_event(account_id, abort.key_event_id);
                    }
                }
            }
            self.block_update_sender.send(block_update).ok();
            current_block = block;
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}

/// User-facing object for using the fake indexer for testing.
/// Create one of these for each test, and call `add_indexer_node` for each node.
pub struct FakeIndexerManager {
    /// Sends transactions to the core for processing. This is cloned to each node,
    /// so each node can send transactions (with its AccountId) to the core.
    core_txn_sender: mpsc::UnboundedSender<(ChainSendTransactionRequest, AccountId)>,
    /// Used to call .subscribe() so that each node can receive changes to the
    /// contract state.
    core_state_change_sender: broadcast::Sender<ContractState>,
    /// Used to call .subscribe() so that each node can receive block updates.
    core_block_update_sender: broadcast::Sender<ChainBlockUpdate>,
    /// Task that runs the core logic.
    _core_task: AutoAbortTask<()>,

    /// Collects signature responses from the core. When the core processes signature
    /// response transactions, it sends them to this receiver. See `next_response()`.
    response_receiver: mpsc::UnboundedReceiver<ChainRespondArgs>,
    /// Used to send signature requests to the core.
    signature_request_sender: mpsc::UnboundedSender<SignatureRequestFromChain>,

    /// Allows nodes to be disabled during tests. See `disable()`.
    node_disabler: HashMap<AccountId, NodeDisabler>,
    /// Allows modification of the contract.
    contract: Arc<tokio::sync::Mutex<FakeMpcContractState>>,
}

/// Allows a node to be disabled during tests.
struct NodeDisabler {
    disable: Arc<AtomicBool>,
    /// For querying whether the node is running the Invalid job,
    /// indicating it has been disabled.
    currently_running_job_name: Arc<std::sync::Mutex<String>>,
}

/// While holding this, the node remains disabled.
pub struct DisabledNode {
    disable: Arc<AtomicBool>,
    currently_running_job_name: Arc<std::sync::Mutex<String>>,
}

impl DisabledNode {
    pub async fn reenable_and_wait_till_running(self) {
        self.disable
            .store(false, std::sync::atomic::Ordering::Relaxed);
        loop {
            {
                let name = self.currently_running_job_name.lock().unwrap();
                if &*name == "Running" {
                    break;
                }
                tracing::info!(
                    "Waiting for node to be reenabled and running; currently running job: {}",
                    *name
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

impl Drop for DisabledNode {
    fn drop(&mut self) {
        self.disable
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Runs the fake indexer logic for one node.
struct FakeIndexerOneNode {
    /// Account under which transactions by this node are originated.
    account_id: AccountId,

    // The following are counterparts of the core channels.
    core_txn_sender: mpsc::UnboundedSender<(ChainSendTransactionRequest, AccountId)>,
    core_state_change_receiver: broadcast::Receiver<ContractState>,
    block_update_receiver: broadcast::Receiver<ChainBlockUpdate>,

    /// Whether the node should yield ContractState::Invalid to artificially simulate bringing the
    /// node down.
    disable: Arc<AtomicBool>,

    // The following are counterparts of the API channels.
    api_state_sender: watch::Sender<ContractState>,
    api_block_update_sender: mpsc::UnboundedSender<ChainBlockUpdate>,
    api_txn_receiver: mpsc::Receiver<ChainSendTransactionRequest>,
}

impl FakeIndexerOneNode {
    async fn run(self) {
        let FakeIndexerOneNode {
            account_id,
            core_txn_sender,
            mut core_state_change_receiver,
            mut block_update_receiver,
            disable: shutdown,
            api_state_sender,
            api_block_update_sender,
            mut api_txn_receiver,
            ..
        } = self;
        let monitor_state_changes = AutoAbortTask::from(tokio::spawn(async move {
            let mut last_state = ContractState::WaitingForSync;
            loop {
                let state = core_state_change_receiver.recv().await.unwrap();
                let state = if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    ContractState::Invalid
                } else {
                    state
                };
                if state != last_state {
                    tracing::info!("State changed: {:?}", state);
                    api_state_sender.send(state.clone()).unwrap();
                    last_state = state;
                }
            }
        }));
        let monitor_signature_requests = AutoAbortTask::from(tokio::spawn(async move {
            loop {
                let request = block_update_receiver.recv().await.unwrap();
                api_block_update_sender.send(request).unwrap();
            }
        }));
        let forward_txn_requests = AutoAbortTask::from(tokio::spawn(async move {
            while let Some(txn) = api_txn_receiver.recv().await {
                core_txn_sender.send((txn, account_id.clone())).unwrap();
            }
        }));
        monitor_state_changes.await.unwrap();
        monitor_signature_requests.await.unwrap();
        forward_txn_requests.await.unwrap();
    }
}

impl FakeIndexerManager {
    /// Creates a new fake indexer whose contract state begins with WaitingForSync.
    pub fn new(clock: Clock, txn_delay_blocks: u64) -> Self {
        let (txn_sender, txn_receiver) = mpsc::unbounded_channel();
        let (state_change_sender, _) = broadcast::channel(1000);
        let (block_update_sender, _) = broadcast::channel(1000);
        let (signature_request_sender, signature_request_receiver) = mpsc::unbounded_channel();
        let (sign_response_sender, response_receiver) = mpsc::unbounded_channel();
        let contract = Arc::new(tokio::sync::Mutex::new(FakeMpcContractState::new()));
        let core = FakeIndexerCore {
            clock: clock.clone(),
            txn_delay_blocks,
            signature_request_receiver,
            contract: contract.clone(),
            txn_receiver,
            state_change_sender: state_change_sender.clone(),
            block_update_sender: block_update_sender.clone(),
            sign_response_sender,
        };
        let core_task = AutoAbortTask::from(tokio::spawn(async move { core.run().await }));
        Self {
            core_txn_sender: txn_sender,
            core_state_change_sender: state_change_sender,
            core_block_update_sender: block_update_sender,
            _core_task: core_task,
            response_receiver,
            signature_request_sender,
            node_disabler: HashMap::new(),
            contract,
        }
    }

    /// Waits for the next signature response submitted by any node.
    pub async fn next_response(&mut self) -> ChainRespondArgs {
        self.response_receiver.recv().await.unwrap()
    }

    /// Sends a signature request to the fake blockchain.
    pub fn request_signature(&self, request: SignatureRequestFromChain) {
        self.signature_request_sender.send(request).unwrap();
    }

    /// Adds a new node to the fake indexer. Returns the API for the node, a task that
    /// runs the node's logic, and the running job name to passed to the coordinator.
    pub fn add_indexer_node(
        &mut self,
        account_id: AccountId,
    ) -> (IndexerAPI, AutoAbortTask<()>, Arc<std::sync::Mutex<String>>) {
        let (api_state_sender, api_state_receiver) = watch::channel(ContractState::WaitingForSync);
        let (api_signature_request_sender, api_signature_request_receiver) =
            mpsc::unbounded_channel();
        let (api_txn_sender, api_txn_receiver) = mpsc::channel(1000);
        let indexer = IndexerAPI {
            contract_state_receiver: api_state_receiver,
            block_update_receiver: Arc::new(tokio::sync::Mutex::new(
                api_signature_request_receiver,
            )),
            txn_sender: api_txn_sender,
        };
        let currently_running_job_name = Arc::new(std::sync::Mutex::new("".to_string()));
        let disabler = NodeDisabler {
            disable: Arc::new(AtomicBool::new(false)),
            currently_running_job_name: currently_running_job_name.clone(),
        };
        let one_node = FakeIndexerOneNode {
            account_id: account_id.clone(),
            core_txn_sender: self.core_txn_sender.clone(),
            core_state_change_receiver: self.core_state_change_sender.subscribe(),
            block_update_receiver: self.core_block_update_sender.subscribe(),
            disable: disabler.disable.clone(),
            api_state_sender,
            api_block_update_sender: api_signature_request_sender,
            api_txn_receiver,
        };
        self.node_disabler.insert(account_id, disabler);
        (
            indexer,
            AutoAbortTask::from(tokio::spawn(one_node.run())),
            currently_running_job_name,
        )
    }

    /// Waits for the contract state to satisfy the given predicate.
    pub async fn wait_for_contract_state(&mut self, f: impl Fn(&ContractState) -> bool) {
        let mut state_change_receiver = self.core_state_change_sender.subscribe();
        loop {
            let state = state_change_receiver.recv().await.unwrap();
            if f(&state) {
                break;
            }
        }
    }

    /// Disables a node, in order to test resilience to node failures.
    pub async fn disable(&self, account_id: AccountId) -> DisabledNode {
        let NodeDisabler {
            disable,
            currently_running_job_name,
        } = self.node_disabler.get(&account_id).unwrap();
        disable.store(true, std::sync::atomic::Ordering::Relaxed);
        loop {
            {
                let name = currently_running_job_name.lock().unwrap();
                if &*name == "Invalid" {
                    break;
                }
                tracing::info!(
                    "Waiting for node to be disabled; currently running job: {}",
                    *name
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        DisabledNode {
            disable: disable.clone(),
            currently_running_job_name: currently_running_job_name.clone(),
        }
    }

    pub async fn contract_mut(&self) -> tokio::sync::MutexGuard<'_, FakeMpcContractState> {
        self.contract.lock().await
    }
}
