#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use borsh::BorshDeserialize;
use near_sdk::collections::LookupMap;
use near_sdk::{env, AccountId};

use crate::config::Config;
use crate::errors::{InitError, MpcContractError};
use crate::primitives::{SignatureRequest, YieldIndex};
use crate::{update, MpcContract, ProtocolContractState, VersionedMpcContract};

// NOTE: All the custom `BorshDeserialize` implementations are necessary for debugging purposes
// in case the migration fails. This way we can log the error and get details about what went wrong
// during the deserialization step.

#[derive(BorshDeserialize)]
pub struct OldConfig {
    pub triple_timeout: u64,
    pub presignature_timeout: u64,
    pub signature_timeout: u64,
}

#[derive(BorshDeserialize)]
enum OldUpdate {
    Config(OldConfig),
    Contract(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OldUpdateId(pub(crate) u64);

impl BorshDeserialize for OldUpdateId {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let id = deserialize_or_log(reader, "OldUpdateId.u64")?;
        Ok(OldUpdateId(id))
    }
}

pub struct OldProposedUpdates {
    updates: HashMap<OldUpdateId, Vec<OldUpdate>>,
    votes: HashMap<OldUpdateId, HashSet<AccountId>>,
    next_id: u64,
}

impl BorshDeserialize for OldProposedUpdates {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let updates = deserialize_or_log(reader, "OldProposedUpdates.updates")?;
        let votes = deserialize_or_log(reader, "OldProposedUpdates.votes")?;
        let next_id = deserialize_or_log(reader, "OldProposedUpdates.next_id")?;
        Ok(OldProposedUpdates {
            updates,
            votes,
            next_id,
        })
    }
}

pub struct OldContract {
    protocol_state: ProtocolContractState,
    pending_requests: LookupMap<SignatureRequest, YieldIndex>,
    request_counter: u32,
    proposed_updates: OldProposedUpdates,
    config: OldConfig,
}

impl BorshDeserialize for OldContract {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let protocol_state = deserialize_or_log(reader, "OldContract.protocol_state")?;
        let pending_requests = deserialize_or_log(reader, "OldContract.pending_requests")?;
        let request_counter = deserialize_or_log(reader, "OldContract.request_counter")?;
        let proposed_updates = deserialize_or_log(reader, "OldContract.proposed_updates")?;
        let config = deserialize_or_log(reader, "OldContract.config")?;
        Ok(OldContract {
            protocol_state,
            pending_requests,
            request_counter,
            proposed_updates,
            config,
        })
    }
}

#[derive(BorshDeserialize)]
enum OldVersionedMpcContract {
    V0(OldContract),
}

pub fn migrate_testnet_dev() -> Result<VersionedMpcContract, MpcContractError> {
    // try to load state, if it doesn't work, then we need to do migration for dev.
    // NOTE: that since we're in dev, there will be many changes. If state was able
    // to be loaded successfully, then that means a migration was not necessary and
    // the developer did not change the contract state.
    let data = env::storage_read(b"STATE").ok_or(MpcContractError::InitError(
        InitError::ContractStateIsMissing,
    ))?;

    if let Ok(loaded) = MpcContract::try_from_slice(&data) {
        return Ok(VersionedMpcContract::V0(loaded));
    };

    // NOTE: for any PRs that have this error, change the code in this block so we can keep
    // our dev environment not broken.

    let old = OldVersionedMpcContract::try_from_slice(&data).unwrap();
    let OldVersionedMpcContract::V0(mut old) = old;

    // Migrate old proposed updates to new proposed updates.
    let mut new_updates = update::ProposedUpdates::default();
    for (id, updates) in old.proposed_updates.updates {
        let updates: Vec<_> = updates
            .into_iter()
            .map(|update| match update {
                OldUpdate::Config(_) => update::Update::Config(Config::default()),
                OldUpdate::Contract(contract) => update::Update::Contract(contract),
            })
            .collect();

        let entry = update::UpdateEntry {
            bytes_used: update::bytes_used_updates(&updates),
            updates,
            votes: old.proposed_updates.votes.remove(&id).unwrap(),
        };
        new_updates.entries.insert(update::UpdateId(id.0), entry);
    }
    new_updates.id = update::UpdateId(old.proposed_updates.next_id);

    let migrated = VersionedMpcContract::V0(MpcContract {
        protocol_state: old.protocol_state,
        pending_requests: old.pending_requests,
        request_counter: old.request_counter,
        proposed_updates: new_updates,
        config: Config::default(),
    });
    Ok(migrated)
}

fn deserialize_or_log<T: BorshDeserialize, R: borsh::io::Read>(
    reader: &mut R,
    which_state: &str,
) -> borsh::io::Result<T> {
    match T::deserialize_reader(reader) {
        Ok(state) => Ok(state),
        Err(err) => {
            env::log_str(&format!("Error deserializing {which_state} state: {err:?}"));
            Err(err)
        }
    }
}
