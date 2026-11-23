use std::time::Duration;

use near_mpc_contract_interface::types::{EpochId, Keyset};

/// Long enough that no passing test can hit it
pub const TEST_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const KEYSET_FIXTURE: &str = include_str!("../assets/current_keyset.json");

pub fn fixture_keyset() -> Keyset {
    serde_json::from_str(KEYSET_FIXTURE).expect("keyset fixture must deserialize")
}

pub fn keyset_with_epoch(epoch_id: u64) -> Keyset {
    Keyset {
        epoch_id: EpochId::new(epoch_id),
        ..fixture_keyset()
    }
}

/// What contract initialization leaves behind: a keyset without any key yet.
pub fn keyset_without_domains() -> Keyset {
    Keyset::new(EpochId::new(0), Vec::new())
}
