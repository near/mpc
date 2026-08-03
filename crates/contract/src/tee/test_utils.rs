//! Test utilities for TEE and contract tests.
//!
//! This module provides helper functions and types for testing TEE state,
//! attestation behavior, and general contract state management.

use crate::primitives::test_utils::{gen_account_id, gen_seed};
use crate::tee::{measurements::ContractExpectedMeasurements, tee_state::TeeState};
use mpc_attestation::attestation::default_measurements;
use mpc_primitives::hash::{LauncherImageHash, NodeImageHash};
use near_account_id::AccountId;
use near_sdk::{BlockHeight, NearToken, PublicKey, test_utils::VMContextBuilder, testing_env};
use rand::Rng;
use std::time::Duration;

/// Test environment for managing VM context state.
///
/// Provides convenient methods for setting up and manipulating the NEAR VM testing
/// environment, including signer, block height, random seed, and attached deposit.
pub struct Environment {
    pub signer: AccountId,
    pub block_height: BlockHeight,
    pub seed: [u8; 32],
    pub deposit: NearToken,
}

impl Environment {
    /// Creates a new test environment with optional overrides.
    ///
    /// If parameters are `None`, random/default values are generated. The attached deposit
    /// defaults to zero; use [`Environment::set_deposit`] to change it.
    /// Automatically sets up the VM context with [`testing_env!`].
    pub fn new(
        block_height: Option<BlockHeight>,
        signer: Option<AccountId>,
        seed: Option<[u8; 32]>,
    ) -> Self {
        let seed = seed.unwrap_or(gen_seed());
        let block_height = block_height.unwrap_or(rand::thread_rng().r#gen());
        let signer = signer.unwrap_or(gen_account_id());
        let env = Environment {
            signer,
            block_height,
            seed,
            deposit: NearToken::from_yoctonear(0),
        };
        env.set();
        env
    }

    /// Sets the signer's public key in the VM context.
    pub fn set_pk(&mut self, pk: PublicKey) {
        let mut ctx = VMContextBuilder::new();
        ctx.signer_account_pk(pk);
        ctx.block_height(self.block_height);
        ctx.random_seed(self.seed);
        ctx.signer_account_id(self.signer.clone());
        ctx.predecessor_account_id(self.signer.clone());
        ctx.attached_deposit(self.deposit);
        testing_env!(ctx.build());
    }

    /// Changes the signer account and applies the new context.
    pub fn set_signer(&mut self, signer: &AccountId) {
        self.signer = signer.clone();
        self.set();
    }

    /// Sets the attached deposit and applies the new context.
    pub fn set_deposit(&mut self, deposit: NearToken) {
        self.deposit = deposit;
        self.set();
    }

    /// Applies the current environment state to the VM context.
    pub fn set(&self) {
        let mut ctx = VMContextBuilder::new();
        ctx.block_height(self.block_height);
        ctx.random_seed(self.seed);
        ctx.signer_account_id(self.signer.clone());
        ctx.predecessor_account_id(self.signer.clone());
        ctx.attached_deposit(self.deposit);
        testing_env!(ctx.build());
    }

    /// Sets a specific block height and applies the context.
    pub fn set_block_height(&mut self, block_height: BlockHeight) {
        self.block_height = block_height;
        self.set();
    }

    /// Advances the block height by a delta and applies the context.
    pub fn advance_block_height(&mut self, delta: BlockHeight) {
        self.block_height += delta;
        self.set();
    }
}

/// Sets the blockchain timestamp for testing time-dependent behavior.
pub fn set_block_timestamp(timestamp_nanos: u64) {
    testing_env!(
        VMContextBuilder::new()
            .block_timestamp(timestamp_nanos)
            .build()
    );
}

pub fn whitelist_dstack_measurements(
    tee_state: &mut TeeState,
    image: NodeImageHash,
    launcher: LauncherImageHash,
) {
    tee_state.whitelist_tee_proposal(image, Duration::MAX);
    tee_state.add_launcher_image(launcher, Duration::MAX);
    for &measurements in default_measurements() {
        tee_state.add_measurement(ContractExpectedMeasurements::from(measurements));
    }
}
