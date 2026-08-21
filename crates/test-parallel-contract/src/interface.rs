//! Host-side typed interface to the test parallel contract.
//!
//! [`ParallelContractInterface`] is the single source of each method's wire format
//! (method name, argument struct, gas, deposit), generic over a transport backend
//! implementing [`CallContract`].

use std::collections::BTreeMap;

use near_contract_transport::{CallContract, FunctionCallArgs, NearGas};
use near_mpc_contract_interface::types::{
    AccountId, CKDRequestArgs, DomainConfig, Protocol, SignRequestArgs,
};
use serde::Serialize;

use crate::method_names::{
    MAKE_DUPLICATE_CKD_CALLS, MAKE_DUPLICATE_SIGN_CALLS, MAKE_PARALLEL_SIGN_CALLS,
};

/// Every entry point fans the request out into up to ~10 child calls on the MPC
/// contract, each reserving its own share of the parent receipt's budget, so all of
/// them are called with the full per-receipt maximum.
pub const FAN_OUT_GAS: NearGas = NearGas::from_tgas(300);

/// Typed interface to a deployed test parallel contract at a fixed account, generic
/// over the transport backend `C`.
///
/// The child `sign` / `request_app_private_key` calls each carry the 1 yoctoNEAR
/// deposit the MPC contract requires, but the contract pays those from its own
/// balance rather than forwarding an attached deposit — so no method here attaches
/// one, and a deployed helper needs a funded account.
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
    /// Fans out one `sign` (or `request_app_private_key`) call per requested count in
    /// `calls_by_domain`, dispatching each domain to the payload kind its
    /// [`Protocol`] implies. `seed` derives the payloads, so distinct seeds produce
    /// distinct requests.
    pub async fn make_parallel_sign_calls(
        &self,
        target_contract: AccountId,
        calls_by_domain: impl IntoIterator<Item = (DomainConfig, u64)>,
        seed: u64,
    ) -> Result<C::Output, ParallelContractInterfaceError<C::Error>> {
        let args = MakeParallelSignCallsArgs::new(target_contract, calls_by_domain, seed);
        self.call(MAKE_PARALLEL_SIGN_CALLS, &args).await
    }

    /// Fans `request` out `count` times, exercising the contract's duplicate-request
    /// path. The caller picks the payload so it knows which response to produce.
    pub async fn make_duplicate_sign_calls(
        &self,
        target_contract: AccountId,
        request: SignRequestArgs,
        count: u64,
    ) -> Result<C::Output, ParallelContractInterfaceError<C::Error>> {
        let args = MakeDuplicateSignCallsArgs {
            target_contract,
            request,
            count,
        };
        self.call(MAKE_DUPLICATE_SIGN_CALLS, &args).await
    }

    /// CKD counterpart to [`Self::make_duplicate_sign_calls`].
    pub async fn make_duplicate_ckd_calls(
        &self,
        target_contract: AccountId,
        request: CKDRequestArgs,
        count: u64,
    ) -> Result<C::Output, ParallelContractInterfaceError<C::Error>> {
        let args = MakeDuplicateCkdCallsArgs {
            target_contract,
            request,
            count,
        };
        self.call(MAKE_DUPLICATE_CKD_CALLS, &args).await
    }

    async fn call(
        &self,
        method_name: &str,
        args: &impl Serialize,
    ) -> Result<C::Output, ParallelContractInterfaceError<C::Error>> {
        let args = serde_json::to_vec(args)?;
        self.caller
            .call_contract(
                &self.contract_id,
                FunctionCallArgs::no_deposit(method_name, args, FAN_OUT_GAS),
            )
            .await
            .map_err(ParallelContractInterfaceError::Call)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParallelContractInterfaceError<E> {
    #[error("failed to serialize call arguments: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("contract call failed: {0}")]
    Call(E),
}

#[derive(Serialize)]
pub struct MakeParallelSignCallsArgs {
    pub target_contract: AccountId,
    pub ecdsa_calls_by_domain: BTreeMap<u64, u64>,
    pub robust_ecdsa_calls_by_domain: BTreeMap<u64, u64>,
    pub eddsa_calls_by_domain: BTreeMap<u64, u64>,
    pub ckd_calls_by_domain: BTreeMap<u64, u64>,
    pub seed: u64,
}

impl MakeParallelSignCallsArgs {
    /// Buckets `calls_by_domain` into the four per-scheme maps the contract takes,
    /// keyed by each domain's [`Protocol`].
    pub fn new(
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
pub struct MakeDuplicateSignCallsArgs {
    pub target_contract: AccountId,
    pub request: SignRequestArgs,
    pub count: u64,
}

#[derive(Serialize)]
pub struct MakeDuplicateCkdCallsArgs {
    pub target_contract: AccountId,
    pub request: CKDRequestArgs,
    pub count: u64,
}
