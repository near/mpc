//! Signer and voter authentication shared by the governance entrypoints.

use crate::MpcContract;
use crate::api::common::tls_keys_in_use;
use crate::errors::{Error, InvalidParameters};
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_sdk::{AccountId, env};

impl MpcContract {
    /// Get our own account id as a voter. Returns an error if we are not a participant.
    fn voter_account(&self) -> Result<AccountId, Error> {
        if !Self::caller_is_signer() {
            return Err(InvalidParameters::CallerNotSigner.into());
        }
        let voter = env::signer_account_id();
        self.protocol_state.authenticate_update_vote()?;
        Ok(voter)
    }

    /// Returns true if the caller is the signer account.
    fn caller_is_signer() -> bool {
        let signer = env::signer_account_id();
        let predecessor = env::predecessor_account_id();
        signer == predecessor
    }

    /// Get our own account id as a voter. If we are not a participant, panic.
    /// also ensures that the caller is the signer account.
    pub(crate) fn voter_or_panic(&self) -> AccountId {
        Self::assert_caller_is_signer();
        match self.voter_account() {
            Ok(voter) => voter,
            Err(err) => env::panic_str(&format!("not a voter, {:?}", err)),
        }
    }

    /// Ensures that the caller is an attested participant
    /// in the currently active protocol phase.
    ///
    /// The participant's current node must have signed the transaction. Its attestation is not
    /// re-verified here: [`Self::verify_tee`] reshares out participants whose attestation no
    /// longer passes, or stops accepting requests if too few valid participants would remain.
    ///
    /// Active phases:
    /// - [`Initializing`](crate::state::ProtocolContractState::Initializing) → uses proposed participants from generating_key
    /// - [`Running`](crate::state::ProtocolContractState::Running) → uses current active participants
    /// - [`Resharing`](crate::state::ProtocolContractState::Resharing) → uses new participants from resharing proposal
    ///
    /// Panics if:
    /// - The protocol is not active (e.g., NotInitialized)
    /// - The caller is not attested or not in the relevant participants set
    /// - The caller is not the signer account
    pub(crate) fn assert_caller_is_attested_participant_and_protocol_active(&self) {
        let participants = self.protocol_state.active_participants();

        let signer_id = Self::assert_caller_is_signer();

        let is_attested = participants.info(&signer_id).is_some_and(|info| {
            self.tee_state
                .node_signed_by(&signer_id, &info.tls_public_key, &env::signer_account_pk())
                .is_some()
        });

        assert!(is_attested, "Caller must be an attested participant");
    }

    /// Ensures the current call originates from the signer account itself.
    /// Panics if `signer_account_id` and `predecessor_account_id` differ.
    ///
    /// This can be used to enforce the policy that **all governance methods must be called
    /// directly from the participant's own NEAR account**, never forwarded through another
    /// contract such as a multisig.
    pub(crate) fn assert_caller_is_signer() -> AccountId {
        let signer_id = env::signer_account_id();
        let predecessor_id = env::predecessor_account_id();

        assert_eq!(
            signer_id, predecessor_id,
            "Caller must be the signer account (signer: {}, predecessor: {})",
            signer_id, predecessor_id
        );

        signer_id
    }

    /// TLS key of the node that signed the current transaction, among the nodes the account uses
    /// (see [`tls_keys_in_use`]).
    ///
    /// A node counts as the signer when its attestation was submitted under the transaction's
    /// signer key.
    pub(crate) fn signer_node_tls_key(
        &self,
        signer_account_id: &AccountId,
    ) -> Option<Ed25519PublicKey> {
        let signer_pk = env::signer_account_pk();
        tls_keys_in_use(
            self.protocol_state.active_participants(),
            &self.node_migrations,
            signer_account_id,
        )
        .find(|tls_key| {
            self.tee_state
                .node_signed_by(signer_account_id, tls_key, &signer_pk)
                .is_some()
        })
        .cloned()
    }
}
