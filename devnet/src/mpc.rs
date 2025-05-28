#![allow(clippy::expect_fun_call)] // to reduce verbosity of expect calls
use crate::account::{OperatingAccount, OperatingAccounts};
use crate::cli::{
    MpcDeployContractCmd, MpcDescribeCmd, MpcProposeUpdateContractCmd, MpcViewContractCmd,
    MpcVoteAddDomainsCmd, MpcVoteNewParametersCmd, MpcVoteUpdateCmd, NewMpcNetworkCmd,
    RemoveContractCmd, UpdateMpcNetworkCmd,
};
use crate::constants::{ONE_NEAR, TESTNET_CONTRACT_ACCOUNT_ID};
use crate::devnet::OperatingDevnetSetup;
use crate::funding::{fund_accounts, AccountToFund};
use crate::queries;
use crate::tx::IntoReturnValueExt;
use crate::types::{MpcNetworkSetup, MpcParticipantSetup, NearAccount, ParsedConfig};
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_contract::{
    config::InitConfig,
    primitives::{
        domain::{DomainConfig, DomainId, SignatureScheme},
        key_state::EpochId,
        participants::{ParticipantInfo, Participants},
        thresholds::{Threshold, ThresholdParameters},
    },
};
use mpc_contract::{state::ProtocolContractState, utils::protocol_state_to_string};
use near_crypto::SecretKey;
use near_sdk::{borsh, AccountId};
use serde::Serialize;
use std::str::FromStr;
use serde_json::json;

/// Bring the MPC network up to the desired parameterization.
async fn update_mpc_network(
    name: &str,
    accounts: &mut OperatingAccounts,
    mpc_setup: &mut MpcNetworkSetup,
    desired_num_participants: usize,
    funding_account: Option<NearAccount>,
) {
    if desired_num_participants < mpc_setup.participants.len() {
        panic!(
            "Cannot reduce number of participants from {} to {}",
            mpc_setup.participants.len(),
            desired_num_participants
        );
    }

    // Create new participants as needed and refill existing participants' balances.
    // For each participant we maintain two accounts: the MPC account, and the responding account.
    let mut accounts_to_fund = Vec::new();
    for i in 0..desired_num_participants {
        if let Some(account_id) = mpc_setup.participants.get(i) {
            accounts_to_fund.push(AccountToFund::from_existing(
                account_id.clone(),
                mpc_setup.desired_balance_per_account,
            ));
            let participant = accounts
                .account(account_id)
                .get_mpc_participant()
                // We could recover from this, but that's too much work.
                .expect("Participant account is not marked as MPC participant");
            accounts_to_fund.push(AccountToFund::from_existing(
                participant.responding_account_id.clone(),
                mpc_setup.desired_balance_per_responding_account,
            ));
        } else {
            accounts_to_fund.push(AccountToFund::from_new(
                mpc_setup.desired_balance_per_account,
                format!("mpc-{}-{}-", i, name),
            ));
            accounts_to_fund.push(AccountToFund::from_new(
                mpc_setup.desired_balance_per_responding_account,
                format!("mpc-responder-{}-{}-", i, name),
            ));
        }
    }
    let funded_accounts = fund_accounts(accounts, accounts_to_fund, funding_account).await;

    for i in mpc_setup.participants.len()..desired_num_participants {
        let account_id = funded_accounts[i * 2].clone();
        accounts
            .account_mut(&account_id)
            .set_mpc_participant(MpcParticipantSetup {
                p2p_private_key: SecretKey::from_random(near_crypto::KeyType::ED25519),
                responding_account_id: funded_accounts[i * 2 + 1].clone(),
            });
        mpc_setup.participants.push(account_id);
    }

    let responding_accounts = mpc_setup
        .participants
        .iter()
        .map(|participant| {
            accounts
                .account(participant)
                .get_mpc_participant()
                .unwrap()
                .responding_account_id
                .clone()
        })
        .collect::<Vec<_>>();

    // Ensure that the responding accounts have enough access keys.
    let futs = accounts
        .accounts_mut(&responding_accounts)
        .into_values()
        .map(|account| account.ensure_have_n_access_keys(mpc_setup.num_responding_access_keys))
        .collect::<Vec<_>>();
    futures::future::join_all(futs).await;
}

impl NewMpcNetworkCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!("Going to create MPC network {} with {} maximum participants, {} NEAR per account, and {} additional access keys per participant for responding",
            name,
            self.num_participants,
            self.near_per_account,
            self.num_responding_access_keys,
        );

        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        if setup.mpc_setups.contains_key(name) {
            panic!("MPC network {} already exists", name);
        }
        let mpc_setup = setup
            .mpc_setups
            .entry(name.to_string())
            .or_insert(MpcNetworkSetup {
                participants: Vec::new(),
                contract: None,
                desired_balance_per_account: self.near_per_account * ONE_NEAR,
                num_responding_access_keys: self.num_responding_access_keys,
                desired_balance_per_responding_account: self.near_per_responding_account * ONE_NEAR,
                nomad_server_url: None,
            });
        update_mpc_network(
            name,
            &mut setup.accounts,
            mpc_setup,
            self.num_participants,
            config.funding_account,
        )
        .await;
    }
}

impl UpdateMpcNetworkCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!("Going to update MPC network {}", name);

        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));

        let num_participants = self
            .num_participants
            .unwrap_or(mpc_setup.participants.len());

        if let Some(near_per_account) = self.near_per_account {
            mpc_setup.desired_balance_per_account = near_per_account * ONE_NEAR;
        }

        if let Some(num_responding_access_keys) = self.num_responding_access_keys {
            mpc_setup.num_responding_access_keys = num_responding_access_keys;
        }

        if let Some(near_per_responding_account) = self.near_per_responding_account {
            mpc_setup.desired_balance_per_responding_account =
                near_per_responding_account * ONE_NEAR;
        }

        update_mpc_network(
            name,
            &mut setup.accounts,
            mpc_setup,
            num_participants,
            config.funding_account,
        )
        .await;
    }
}

impl MpcDeployContractCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        let (contract_data, contract_path) = match &self.path {
            Some(contract_path) => (std::fs::read(contract_path).unwrap(), contract_path.clone()),
            None => {
                println!(
                    "fetching and deploying contract from testnet account {}",
                    TESTNET_CONTRACT_ACCOUNT_ID
                );
                (
                    queries::get_contract_code(
                        &config.rpc,
                        TESTNET_CONTRACT_ACCOUNT_ID.parse().unwrap(),
                    )
                    .await
                    .unwrap()
                    .code,
                    TESTNET_CONTRACT_ACCOUNT_ID.to_string(),
                )
            }
        };
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        if let Some(old_contract) = &mpc_setup.contract {
            let old_contract = setup
                .accounts
                .account(old_contract)
                .get_contract_code()
                .await
                .unwrap();
            if old_contract == contract_data {
                println!("Contract code is the same, not deploying");
                return;
            }
            println!("Contract code is different, going to redeploy");
        }

        let contract_account_to_fund = if let Some(contract) = &mpc_setup.contract {
            AccountToFund::ExistingAccount {
                account_id: contract.clone(),
                desired_balance: self.deposit_near * ONE_NEAR,
                do_not_refill_above: 0,
            }
        } else {
            AccountToFund::from_new(
                self.deposit_near * ONE_NEAR,
                format!("mpc-contract-{}-", name),
            )
        };
        let contract_account = fund_accounts(
            &mut setup.accounts,
            vec![contract_account_to_fund],
            config.funding_account,
        )
        .await
        .into_iter()
        .next()
        .unwrap();
        mpc_setup.contract = Some(contract_account.clone());

        setup
            .accounts
            .account_mut(&contract_account)
            .deploy_contract(contract_data, &contract_path)
            .await;

        let mut access_key = setup
            .accounts
            .account(&contract_account)
            .any_access_key()
            .await;

        let mut participants = Participants::new();
        for (i, account_id) in mpc_setup
            .participants
            .iter()
            .enumerate()
            .take(self.init_participants)
        {
            participants
                .insert(
                    account_id.clone(),
                    mpc_account_to_participant_info(setup.accounts.account(account_id), i),
                )
                .unwrap();
        }
        let parameters =
            ThresholdParameters::new(participants, Threshold::new(self.threshold)).unwrap();
        let args = serde_json::to_vec(&InitV2Args {
            parameters,
            init_config: None,
        })
        .unwrap();

        access_key
            .submit_tx_to_call_function(
                &contract_account,
                "init",
                &args,
                300,
                0,
                near_primitives::views::TxExecutionStatus::Final,
                true,
            )
            .await
            .into_return_value()
            .unwrap();
    }
}

#[derive(Serialize)]
struct InitV2Args {
    parameters: ThresholdParameters,
    init_config: Option<InitConfig>,
}

fn mpc_account_to_participant_info(account: &OperatingAccount, index: usize) -> ParticipantInfo {
    let mpc_setup = account.get_mpc_participant().unwrap();
    let quote_collateral = json!({"tcb_info_issuer_chain":"-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNTAxMFoXDTI1MDUyMTEwNTAxMFowbDEeMBwG\nA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw\nb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD\nVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv\nP+mAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh/zN3C4xvpoouGlirMba+W2lju\nypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f\nBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz\nLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK\nQEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG\nSM49BAMCA0cAMEQCIB9C8wOAN/ImxDtGACV246KcqjagZOR0kyctyBrsGGJVAiAj\nftbrNGsGU8YH211dRiYNoPPu19Zp/ze8JmhujB0oBw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\nAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n","tcb_info":"{\"id\":\"TDX\",\"version\":3,\"issueDate\":\"2025-03-11T00:36:15Z\",\"nextUpdate\":\"2025-04-10T00:36:15Z\",\"fmspc\":\"20a06f000000\",\"pceId\":\"0000\",\"tcbType\":0,\"tcbEvaluationDataNumber\":17,\"tdxModule\":{\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\"},\"tdxModuleIdentities\":[{\"id\":\"TDX_03\",\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\",\"tcbLevels\":[{\"tcb\":{\"isvsvn\":3},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"}]},{\"id\":\"TDX_01\",\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\",\"tcbLevels\":[{\"tcb\":{\"isvsvn\":4},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"},{\"tcb\":{\"isvsvn\":2},\"tcbDate\":\"2023-08-09T00:00:00Z\",\"tcbStatus\":\"OutOfDate\"}]}],\"tcbLevels\":[{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":2,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":255,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":13,\"tdxtcbcomponents\":[{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":2,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":255,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":5,\"tdxtcbcomponents\":[{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2018-01-04T00:00:00Z\",\"tcbStatus\":\"OutOfDate\"}]}","tcb_info_signature":"dff1380a12d533bff4ad7f69fd0355ad97ff034b42c8269e26e40e3d585dffff3e55bf21f8cda481d3c163fafcd4eab11c8818ba6aa7553ba6866bce06b56a95","qe_identity_issuer_chain":"-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNTAxMFoXDTI1MDUyMTEwNTAxMFowbDEeMBwG\nA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw\nb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD\nVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv\nP+mAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh/zN3C4xvpoouGlirMba+W2lju\nypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f\nBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz\nLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK\nQEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG\nSM49BAMCA0cAMEQCIB9C8wOAN/ImxDtGACV246KcqjagZOR0kyctyBrsGGJVAiAj\nftbrNGsGU8YH211dRiYNoPPu19Zp/ze8JmhujB0oBw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\nAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n","qe_identity":"{\"id\":\"TD_QE\",\"version\":2,\"issueDate\":\"2025-03-10T23:38:16Z\",\"nextUpdate\":\"2025-04-09T23:38:16Z\",\"tcbEvaluationDataNumber\":17,\"miscselect\":\"00000000\",\"miscselectMask\":\"FFFFFFFF\",\"attributes\":\"11000000000000000000000000000000\",\"attributesMask\":\"FBFFFFFFFFFFFFFF0000000000000000\",\"mrsigner\":\"DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5\",\"isvprodid\":2,\"tcbLevels\":[{\"tcb\":{\"isvsvn\":4},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"}]}","qe_identity_signature":"920d5f18df6da142a667caf71844d45dfd4de3e3b14f846bae92a3e52a9c765d855b9a8b4b54307dd3feae30f28f09888a3200c29584d7c50d42f85275afe6cc"});
    let quote_collateral = quote_collateral.to_string();
    let quote_hex = "040002008100000000000000939a7233f79c4ca9940a0db3957f0607ac666ed993e70e31ff5f5a8a2c743b220000000007010300000000000000000000000000c51e5cb16c461fe29b60394984755325ecd05a9a7a8fb3a116f1c3cf0aca4b0eb9edefb9b404deeaee4b7d454372d17a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000702000000000000c68518a0ebb42136c12b2275164f8c72f25fa9a34392228687ed6e9caeb9c0f1dbd895e9cf475121c029dc47e70e91fd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000085e0855a6384fa1c8a6ab36d0dcbfaa11a5753e5a070c08218ae5fe872fcb86967fd2449c29e22e59dc9fec998cb65474a7db64a609c77e85f603c23e9a9fd03bfd9e6b52ce527f774a598e66d58386026cea79b2aea13b81a0b70cfacdec0ca8a4fe048fea22663152ef128853caa5c033cbe66baf32ba1ff7f6b1afc1624c279f50a4cbc522a735ca6f69551e61ef2561c1b02351cd6f7c803dd36bc95ba25463aa025ce7761156260c9131a5d7c03aeccc10e12160ec3205bb2876a203a7fb81447910d62fd92897d68b1f51d54fb75dfe2aeba3a97a879cba59a771fc522d88046cc26b407d723f726fae17c3e5a50529d0b6c2b991d027f06a9b430d43ecc1000003bdd12b68ee3cfc93a1758479840b6f8734c2439106d8f0faa50ac919d86ea101c002c41d262670ad84afb8f9ee35c7abbb72dcc01bbc3e3a3773672d665005ee6bcb0c5f4b03f0563c797747f7ddd25d92d4f120bee4a829daca986bbc03c155b3d158f6a386bca7ee49ceb3ec31494b792e0cf22fc4e561ddc57156da1b77a0600461000000303070704ff00020000000000000000000000000000000000000000000000000000000000000000000000000000000015000000000000000700000000000000e5a3a7b5d830c2953b98534c6c59a3a34fdc34e933f7f5898f0a85cf08846bca0000000000000000000000000000000000000000000000000000000000000000dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005d2eb8ae211693884eadaea0be0392c5532c7ff55429e4696c84954444d62ed600000000000000000000000000000000000000000000000000000000000000004f1cd2dde7dd5d4a9a495815f3ac76c56a77a9e06a5279a8c8550b54cf2d7287a630c3b9aefb94b1b6e8491eba4b43baa811c8f44167eb7d9ca933678ea64f5b2000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f05005e0e00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49494538544343424a656741774942416749554439426b736e734170713045567861464a59785a56794f6774664d77436759494b6f5a497a6a3045417749770a634445694d434147413155454177775a535735305a577767553064594946424453794251624746305a6d397962534244515445614d42674741315545436777520a535735305a577767513239796347397959585270623234784644415342674e564241634d43314e68626e526849454e7359584a684d51737743515944565151490a44414a445154454c4d416b474131554542684d4356564d774868634e4d6a55774d6a41334d5463774f4441325768634e4d7a49774d6a41334d5463774f4441320a576a42774d534977494159445651514444426c4a626e526c624342545231676755454e4c49454e6c636e52705a6d6c6a5958526c4d526f77474159445651514b0a4442464a626e526c6243424462334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e560a4241674d416b4e424d517377435159445651514745774a56557a425a4d424d4742797147534d34394167454743437147534d34394177454841304941424853770a3977506a72554532734f4a644c5653415434686565414a572b31796c6473615556696b5a4c485832506235777374326a79697539414f5865576a7a6a6d585a4c0a4343742b457858716f53394e45476c6b52724b6a67674d4e4d4949444354416642674e5648534d4547444157674253566231334e765276683655424a796454300a4d383442567776655644427242674e56485238455a4442694d47436758714263686c706f64485277637a6f764c32467761533530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c334e6e6543396a5a584a3061575a7059324630615739754c3359304c33426a61324e796244396a595431770a624746305a6d397962535a6c626d4e765a476c755a7a316b5a584977485159445652304f42425945464d6a464e59626f7464634b636859487258467966774b460a774e534d4d41344741315564447745422f775145417749477744414d42674e5648524d4241663845416a41414d4949434f67594a4b6f5a496876684e415130420a424949434b7a4343416963774867594b4b6f5a496876684e41513042415151514134346b35686a336951797044574873756f5a474144434341575147436971470a534962345451454e41514977676746554d42414743797147534962345451454e41514942416745434d42414743797147534962345451454e41514943416745430a4d42414743797147534962345451454e41514944416745434d42414743797147534962345451454e41514945416745434d42414743797147534962345451454e0a41514946416745434d42454743797147534962345451454e41514947416749412f7a415142677371686b69472b453042445145434277494241444151426773710a686b69472b4530424451454343414942416a415142677371686b69472b45304244514543435149424144415142677371686b69472b45304244514543436749420a4144415142677371686b69472b45304244514543437749424144415142677371686b69472b45304244514543444149424144415142677371686b69472b4530420a44514543445149424144415142677371686b69472b45304244514543446749424144415142677371686b69472b453042445145434477494241444151426773710a686b69472b45304244514543454149424144415142677371686b69472b45304244514543455149424454416642677371686b69472b45304244514543456751510a4167494341674c2f4141494141414141414141414144415142676f71686b69472b45304244514544424149414144415542676f71686b69472b453042445145450a424159676f473841414141774477594b4b6f5a496876684e4151304242516f424154416542676f71686b69472b453042445145474242414b496f456755387a650a486d2b49596f7a686c337a314d45514743697147534962345451454e415163774e6a415142677371686b69472b45304244514548415145422f7a4151426773710a686b69472b45304244514548416745422f7a415142677371686b69472b45304244514548417745422f7a414b42676771686b6a4f5051514441674e49414442460a4169417362735a44796d2f72455a30476c454c62442f6e64755061536a485341746e5871567453313047486255774968414d585666784b334b666f4b675131660a4578397478765331314362363662323467424344523963477942562b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436c6a4343416a32674177494241674956414a567658633239472b487051456e4a3150517a7a674658433935554d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484178496a41670a42674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d45556c75644756730a49454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b474131554543417743513045780a437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741454e53422f377432316c58534f0a3243757a7078773734654a423732457944476757357258437478327456544c7136684b6b367a2b5569525a436e71523770734f766771466553786c6d546c4a6c0a65546d693257597a33714f42757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f536347724442530a42674e5648523845537a424a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e5648513445466751556c5739640a7a62306234656c4153636e553944504f4156634c336c517744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159420a4166384341514177436759494b6f5a497a6a30454177494452774177524149675873566b6930772b6936565947573355462f32327561586530594a446a3155650a6e412b546a44316169356343494359623153416d4435786b66545670766f34556f79695359787244574c6d5552344349394e4b7966504e2b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    ParticipantInfo {
        sign_pk: near_sdk::PublicKey::from_str(&mpc_setup.p2p_private_key.public_key().to_string())
            .unwrap(),
        url: format!("http://mpc-node-{}.service.mpc.consul:3000", index),
        tee_quote: hex::decode(quote_hex).unwrap(),
        quote_collateral: quote_collateral.clone(),
    }
}

impl RemoveContractCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        if mpc_setup.contract.is_some() {
            mpc_setup.contract = None;
            println!("Contract removed (not deleted; just removed from local view)");
        } else {
            println!("Contract is not deployed, nothing to do");
        }
    }
}

impl MpcViewContractCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        let setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get(name)
            .expect(&format!("MPC network {} does not exist", name));
        let Some(contract) = mpc_setup.contract.as_ref() else {
            println!("Contract is not deployed");
            return;
        };
        let contract_state = setup
            .accounts
            .account(contract)
            .query_contract("state", b"{}".to_vec())
            .await
            .expect("state() call failed");
        println!(
            "Contract state: {}",
            String::from_utf8_lossy(&contract_state.result)
        );
    }
}

/// Gets a list of voters who would send the vote txn, based on the cmdline flag (empty list means
/// all participants; otherwise it's the precise list of participant indices).
fn get_voter_account_ids<'a>(
    mpc_setup: &'a MpcNetworkSetup,
    voters: &[usize],
) -> Vec<&'a AccountId> {
    mpc_setup
        .participants
        .iter()
        .enumerate()
        .filter(|(i, _)| voters.is_empty() || voters.contains(i))
        .map(|(_, account_id)| account_id)
        .collect::<Vec<_>>()
}

impl MpcProposeUpdateContractCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!("Going to propose update contract for MPC network {}", name);
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        let contract = mpc_setup
            .contract
            .clone()
            .expect("Contract is not deployed");
        let contract_code = std::fs::read(&self.path).unwrap();
        let proposer_account_id = &mpc_setup.participants[self.proposer_index];

        // Fund the proposer account with additional tokens first to cover the additional deposit.
        let account_to_fund = AccountToFund::from_existing(
            proposer_account_id.clone(),
            mpc_setup.desired_balance_per_account + self.deposit_near * ONE_NEAR,
        );
        fund_accounts(
            &mut setup.accounts,
            vec![account_to_fund],
            config.funding_account,
        )
        .await;
        let proposer = setup.accounts.account(proposer_account_id);

        let result = proposer
            .any_access_key()
            .await
            .submit_tx_to_call_function(
                &contract,
                "propose_update",
                &borsh::to_vec(&ProposeUpdateArgs {
                    contract: Some(contract_code),
                    config: None,
                })
                .unwrap(),
                300,
                self.deposit_near * ONE_NEAR,
                near_primitives::views::TxExecutionStatus::Final,
                false,
            )
            .await
            .into_return_value()
            .expect("Failed to propose update");
        let update_id: u64 = serde_json::from_slice(&result).expect(&format!(
            "Failed to deserialize result: {}",
            String::from_utf8_lossy(&result)
        ));
        println!("Proposed update with ID {}", update_id);
        println!("Run the following command to vote for the update:");
        let self_exe = std::env::current_exe()
            .expect("Failed to get current executable path")
            .to_str()
            .expect("Failed to convert path to string")
            .to_string();
        println!(
            "{} mpc {} vote-update --update-id={}",
            self_exe, name, update_id
        );
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ProposeUpdateArgs {
    pub contract: Option<Vec<u8>>,
    pub config: Option<()>, // unsupported
}

impl MpcVoteUpdateCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to vote update contract for MPC network {} with update ID {}",
            name, self.update_id
        );
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        let contract = mpc_setup
            .contract
            .clone()
            .expect("Contract is not deployed");
        let from_accounts = get_voter_account_ids(mpc_setup, &self.voters);

        let mut futs = Vec::new();
        for account_id in from_accounts {
            let account = setup.accounts.account(account_id);
            let mut key = account.any_access_key().await;
            let contract = contract.clone();
            futs.push(async move {
                key.submit_tx_to_call_function(
                    &contract,
                    "vote_update",
                    &serde_json::to_vec(&VoteUpdateArgs { id: self.update_id }).unwrap(),
                    300,
                    0,
                    near_primitives::views::TxExecutionStatus::Final,
                    true,
                )
                .await
            });
        }
        let results = futures::future::join_all(futs).await;
        for (i, result) in results.into_iter().enumerate() {
            match result.into_return_value() {
                Ok(_) => {
                    println!("Participant {} vote_update({}) succeed", i, self.update_id);
                }
                Err(err) => {
                    println!(
                        "Participant {} vote_update({}) failed: {:?}",
                        i, self.update_id, err
                    );
                }
            }
        }
    }
}

#[derive(Serialize)]
struct VoteUpdateArgs {
    id: u64,
}

impl MpcVoteAddDomainsCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to vote_add_domains MPC network {} for signature schemes {:?}",
            name, self.signature_schemes
        );
        let signature_schemes: Vec<SignatureScheme> = self
            .signature_schemes
            .iter()
            .map(|scheme| {
                serde_json::from_str(&format!("\"{}\"", scheme))
                    .expect(&format!("Failed to parse signature scheme {}", scheme))
            })
            .collect::<Vec<_>>();
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        let contract = mpc_setup
            .contract
            .clone()
            .expect("Contract is not deployed");

        // Query the contract state and use the next_domain_id to construct the domain IDs we should
        // use for the proposal.
        let contract_state = read_contract_state_v2(&setup.accounts, &contract).await;
        let domains = match contract_state {
            ProtocolContractState::Running(running_contract_state) => {
                running_contract_state.domains
            }
            _ => {
                panic!(
                    "Cannot add domains when not in the running state: {:?}",
                    contract_state
                );
            }
        };
        let mut proposal = Vec::new();
        let mut next_domain = domains.next_domain_id();
        for signature_scheme in &signature_schemes {
            proposal.push(DomainConfig {
                id: DomainId(next_domain),
                scheme: *signature_scheme,
            });
            next_domain += 1;
        }

        let from_accounts = get_voter_account_ids(mpc_setup, &self.voters);

        let mut futs = Vec::new();
        for account_id in from_accounts {
            let account = setup.accounts.account(account_id);
            let mut key = account.any_access_key().await;
            let contract = contract.clone();
            let proposal = proposal.clone();
            futs.push(async move {
                key.submit_tx_to_call_function(
                    &contract,
                    "vote_add_domains",
                    &serde_json::to_vec(&VoteAddDomainsArgs { domains: proposal }).unwrap(),
                    300,
                    0,
                    near_primitives::views::TxExecutionStatus::Final,
                    true,
                )
                .await
            });
        }
        let results = futures::future::join_all(futs).await;
        for (i, result) in results.into_iter().enumerate() {
            match result.into_return_value() {
                Ok(_) => {
                    println!("Participant {} vote_add_domains succeed", i);
                }
                Err(err) => {
                    println!("Participant {} vote_add_domains failed: {:?}", i, err);
                }
            }
        }
    }
}

#[derive(Serialize)]
struct VoteAddDomainsArgs {
    domains: Vec<DomainConfig>,
}

impl MpcVoteNewParametersCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to vote_new_parameters for MPC network {}, adding participants {:?}, removing participants {:?}, and overriding threshold with {:?}",
            name, self.add, self.remove, self.set_threshold
        );
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        let contract = mpc_setup
            .contract
            .clone()
            .expect("Contract is not deployed");

        // Query the contract state so we can incrementally construct the new parameters. This is
        // because the existing participants must have the same participant IDs, and the new
        // participants must have contiguous participant IDs.
        let contract_state = read_contract_state_v2(&setup.accounts, &contract).await;
        let prospective_epoch_id = match &contract_state {
            ProtocolContractState::Running(state) => state.keyset.epoch_id.next(),
            ProtocolContractState::Resharing(state) => state.prospective_epoch_id().next(),
            _ => panic!(),
        };
        let parameters = match contract_state {
            ProtocolContractState::Running(state) => state.parameters,
            ProtocolContractState::Resharing(state) => state.previous_running_state.parameters,
            _ => {
                panic!(
                    "Cannot vote for new parameters when not in the running or resharing state: {:?}",
                    contract_state
                );
            }
        };

        let mut participants = parameters.participants().clone();
        for participant_index in &self.remove {
            let account_id = mpc_setup.participants[*participant_index].clone();
            assert!(
                participants.is_participant(&account_id),
                "Participant {} is not in the network",
                account_id
            );
            participants.remove(&account_id);
        }
        for participant_index in &self.add {
            let account_id = mpc_setup.participants[*participant_index].clone();
            assert!(
                !participants.is_participant(&account_id),
                "Participant {} is already in the network",
                account_id
            );
            participants
                .insert(
                    account_id.clone(),
                    mpc_account_to_participant_info(
                        setup.accounts.account(&account_id),
                        *participant_index,
                    ),
                )
                .unwrap();
        }
        let threshold = if let Some(threshold) = self.set_threshold {
            Threshold::new(threshold)
        } else {
            parameters.threshold()
        };
        let proposal =
            ThresholdParameters::new(participants, threshold).expect("New parameters invalid");

        let from_accounts = get_voter_account_ids(mpc_setup, &self.voters);

        let mut futs = Vec::new();
        for account_id in from_accounts {
            let account = setup.accounts.account(account_id);
            let mut key = account.any_access_key().await;
            let contract = contract.clone();
            let proposal = proposal.clone();
            futs.push(async move {
                key.submit_tx_to_call_function(
                    &contract,
                    "vote_new_parameters",
                    &serde_json::to_vec(&VoteNewParametersArgs {
                        prospective_epoch_id,
                        proposal,
                    })
                    .unwrap(),
                    300,
                    0,
                    near_primitives::views::TxExecutionStatus::Final,
                    true,
                )
                .await
            });
        }
        let results = futures::future::join_all(futs).await;
        for (i, result) in results.into_iter().enumerate() {
            match result.into_return_value() {
                Ok(_) => {
                    println!("Participant {} vote_new_parameters succeed", i);
                }
                Err(err) => {
                    println!("Participant {} vote_new_parameters failed: {:?}", i, err);
                }
            }
        }
    }
}

/// Read the contract state from the contract and deserialize it into the V2 state format.
pub async fn read_contract_state_v2(
    accounts: &OperatingAccounts,
    contract: &AccountId,
) -> ProtocolContractState {
    let contract_state = accounts
        .account(contract)
        .query_contract("state", b"{}".to_vec())
        .await
        .expect("state() call failed");
    serde_json::from_slice(&contract_state.result).expect(&format!(
        "Failed to deserialize contract state: {}",
        String::from_utf8_lossy(&contract_state.result)
    ))
}

#[derive(Serialize)]
struct VoteNewParametersArgs {
    prospective_epoch_id: EpochId,
    proposal: ThresholdParameters,
}

impl MpcDescribeCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        let setup = OperatingDevnetSetup::load(config.rpc.clone()).await;
        let mpc_setup = setup
            .mpc_setups
            .get(name)
            .expect(&format!("MPC network {} does not exist", name));
        if let Some(contract) = &mpc_setup.contract {
            println!("MPC contract deployed at: {}", contract);
            let contract_state = read_contract_state_v2(&setup.accounts, contract).await;
            print!("{}", protocol_state_to_string(&contract_state));
        } else {
            println!("MPC contract is not deployed");
        }
        println!();

        self.describe_terraform(name, &config).await;
    }
}
