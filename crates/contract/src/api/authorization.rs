//! Signer and voter authentication shared by the governance entrypoints.

use crate::MpcContract;
use crate::errors::{Error, InvalidParameters};
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

        Self::assert_caller_is_signer();

        let attestation_check = self
            .tee_state
            .is_caller_an_attested_participant(participants);

        assert_matches::assert_matches!(
            attestation_check,
            Ok(()),
            "Caller must be an attested participant"
        );
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
}
