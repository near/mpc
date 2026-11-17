use near_mpc_contract_interface::types::{EpochId, Keyset};

const KEYSET_FIXTURE: &str = include_str!("../assets/current_keyset.json");

pub fn keyset_with_epoch(epoch_id: u64) -> Keyset {
    let mut keyset: Keyset =
        serde_json::from_str(KEYSET_FIXTURE).expect("keyset fixture must deserialize");
    keyset.epoch_id = EpochId::new(epoch_id);
    keyset
}

/// What contract initialization leaves behind: a keyset without any key yet.
pub fn keyset_without_domains() -> Keyset {
    Keyset::new(EpochId::new(0), Vec::new())
}
