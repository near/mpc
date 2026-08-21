use std::collections::BTreeMap;

use near_contract_transport::{CallContract, FunctionCallArgs, NearGas};
use near_mpc_contract_interface::types::{
    AccountId, CKDRequestArgs, DomainConfig, Protocol, SignRequestArgs,
};
use serde::Serialize;

use crate::method_names::{
    MAKE_DUPLICATE_CKD_CALLS, MAKE_DUPLICATE_SIGN_CALLS, MAKE_PARALLEL_SIGN_CALLS,
};

const FAN_OUT_GAS: NearGas = NearGas::from_tgas(300);

pub struct ParallelContractInterface<C> {
    caller: C,
    contract_id: AccountId,
}

impl<C> ParallelContractInterface<C> {
    pub fn new(caller: C, contract_id: AccountId) -> Self {
        Self {
            caller,
            contract_id,
        }
    }
}

impl<C: CallContract> ParallelContractInterface<C> {
    pub async fn make_parallel_sign_calls(
        &self,
        target_contract: AccountId,
        calls_by_domain: impl IntoIterator<Item = (DomainConfig, u64)>,
        seed: u64,
    ) -> Result<C::Output, C::Error> {
        let args = MakeParallelSignCallsArgs::new(target_contract, calls_by_domain, seed);
        self.call(MAKE_PARALLEL_SIGN_CALLS, &args).await
    }

    pub async fn make_duplicate_sign_calls(
        &self,
        target_contract: AccountId,
        request: SignRequestArgs,
        count: u64,
    ) -> Result<C::Output, C::Error> {
        let args = MakeDuplicateSignCallsArgs {
            target_contract,
            request,
            count,
        };
        self.call(MAKE_DUPLICATE_SIGN_CALLS, &args).await
    }

    pub async fn make_duplicate_ckd_calls(
        &self,
        target_contract: AccountId,
        request: CKDRequestArgs,
        count: u64,
    ) -> Result<C::Output, C::Error> {
        let args = MakeDuplicateCkdCallsArgs {
            target_contract,
            request,
            count,
        };
        self.call(MAKE_DUPLICATE_CKD_CALLS, &args).await
    }

    async fn call(&self, method_name: &str, args: &impl Serialize) -> Result<C::Output, C::Error> {
        let args = serde_json::to_vec(args).expect("arg structs are infallibly serializable");
        self.caller
            .call_contract(
                &self.contract_id,
                FunctionCallArgs::no_deposit(method_name, args, FAN_OUT_GAS),
            )
            .await
    }
}

#[derive(Serialize)]
struct MakeParallelSignCallsArgs {
    target_contract: AccountId,
    ecdsa_calls_by_domain: BTreeMap<u64, u64>,
    robust_ecdsa_calls_by_domain: BTreeMap<u64, u64>,
    eddsa_calls_by_domain: BTreeMap<u64, u64>,
    ckd_calls_by_domain: BTreeMap<u64, u64>,
    seed: u64,
}

impl MakeParallelSignCallsArgs {
    /// Buckets `calls_by_domain` into the four per-scheme maps the contract takes,
    /// keyed by each domain's [`Protocol`].
    fn new(
        target_contract: AccountId,
        calls_by_domain: impl IntoIterator<Item = (DomainConfig, u64)>,
        seed: u64,
    ) -> Self {
        let mut ecdsa_calls_by_domain = BTreeMap::new();
        let mut robust_ecdsa_calls_by_domain = BTreeMap::new();
        let mut eddsa_calls_by_domain = BTreeMap::new();
        let mut ckd_calls_by_domain = BTreeMap::new();
        for (domain, calls) in calls_by_domain {
            let bucket = match domain.protocol {
                Protocol::CaitSith => &mut ecdsa_calls_by_domain,
                Protocol::DamgardEtAl => &mut robust_ecdsa_calls_by_domain,
                Protocol::Frost => &mut eddsa_calls_by_domain,
                Protocol::ConfidentialKeyDerivation => &mut ckd_calls_by_domain,
            };
            *bucket.entry(domain.id.0).or_default() += calls;
        }
        Self {
            target_contract,
            ecdsa_calls_by_domain,
            robust_ecdsa_calls_by_domain,
            eddsa_calls_by_domain,
            ckd_calls_by_domain,
            seed,
        }
    }
}

#[derive(Serialize)]
struct MakeDuplicateSignCallsArgs {
    target_contract: AccountId,
    request: SignRequestArgs,
    count: u64,
}

#[derive(Serialize)]
struct MakeDuplicateCkdCallsArgs {
    target_contract: AccountId,
    request: CKDRequestArgs,
    count: u64,
}
