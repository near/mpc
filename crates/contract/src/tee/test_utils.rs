//! Test utilities for TEE and contract tests.
//!
//! This module provides helper functions and types for testing TEE state,
//! attestation behavior, and general contract state management.
//!
//! Note: The `Environment` struct and related utilities require the NEAR SDK's
//! unit-testing features which are only available on non-WASM targets.

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use crate::primitives::test_utils::{gen_account_id, gen_seed};
    use near_account_id::AccountId;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, BlockHeight, PublicKey};
    use rand::Rng;
    use utilities::AccountIdExtV2;

    /// Test environment for managing VM context state.
    ///
    /// Provides convenient methods for setting up and manipulating the NEAR VM testing
    /// environment, including signer, block height, and random seed.
    pub struct Environment {
        pub signer: AccountId,
        pub block_height: BlockHeight,
        pub seed: [u8; 32],
    }

    impl Environment {
        /// Creates a new test environment with optional overrides.
        ///
        /// If parameters are `None`, random/default values are generated.
        /// Automatically sets up the VM context with [`testing_env!`].
        pub fn new(
            block_height: Option<BlockHeight>,
            signer: Option<AccountId>,
            seed: Option<[u8; 32]>,
        ) -> Self {
            let seed = seed.unwrap_or(gen_seed());
            let mut ctx = VMContextBuilder::new();
            let block_height = block_height.unwrap_or(rand::thread_rng().gen());
            ctx.block_height(block_height);
            ctx.random_seed(seed);
            let signer = signer.unwrap_or(gen_account_id());
            ctx.signer_account_id(signer.clone().as_v1_account_id());
            ctx.predecessor_account_id(signer.clone().as_v1_account_id());
            testing_env!(ctx.build());
            Environment {
                signer,
                block_height,
                seed,
            }
        }

        /// Sets the signer's public key in the VM context.
        pub fn set_pk(&mut self, pk: PublicKey) {
            let mut ctx = VMContextBuilder::new();
            ctx.signer_account_pk(pk);
            ctx.block_height(self.block_height);
            ctx.random_seed(self.seed);
            ctx.signer_account_id(self.signer.clone().as_v1_account_id());
            ctx.predecessor_account_id(self.signer.clone().as_v1_account_id());
            testing_env!(ctx.build());
        }

        /// Changes the signer account and applies the new context.
        pub fn set_signer(&mut self, signer: &AccountId) {
            self.signer = signer.clone();
            self.set();
        }

        /// Applies the current environment state to the VM context.
        pub fn set(&self) {
            let mut ctx = VMContextBuilder::new();
            ctx.block_height(self.block_height);
            ctx.random_seed(self.seed);
            ctx.signer_account_id(self.signer.clone().as_v1_account_id());
            ctx.predecessor_account_id(self.signer.clone().as_v1_account_id());
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
        testing_env!(VMContextBuilder::new()
            .block_timestamp(timestamp_nanos)
            .build());
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::*;
