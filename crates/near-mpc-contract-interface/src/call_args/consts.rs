//! Gas and deposit constants for the contract-call factories.

use mpc_call_args::{NearGas, NearToken};

pub(crate) const SIGN_GAS: NearGas = NearGas::from_tgas(15);

// todo: this is too much, we should benchmark and reduce it
pub(crate) const MAX_GAS: NearGas = NearGas::from_tgas(300);

// AppPublicKeyPV does an on-chain bls12381_pairing_check (2 pairs) before yielding,
// which costs significantly more than a plain CKD or sign request.
pub(crate) const CKD_PV_GAS: NearGas = NearGas::from_tgas(100);

pub(crate) const SIGN_DEPOSIT: NearToken = NearToken::from_yoctonear(1);
