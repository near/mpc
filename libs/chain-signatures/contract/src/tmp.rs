
    fn state_read<T: borsh::BorshDeserialize>() -> Option<T> {
        env::storage_read(b"STATE").and_then(|data| T::try_from_slice(&data).ok())
    }
    /// This will be called internally by the contract to migrate the state when a new contract
    /// is deployed. This function should be changed every time state is changed to do the proper
    /// migrate flow.
    ///
    /// If nothing is changed, then this function will just return the current state. If it fails
    /// to read the state, then it will return an error.
    #[private]
    #[init(ignore_state)]
    #[handle_result]
    pub fn migrate() -> Result<Self, Error> {
        if let Some(legacy_contract_state::VersionedMpcContract::V1(state)) =
            Self::state_read::<legacy_contract_state::VersionedMpcContract>()
        {
