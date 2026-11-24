use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use mpc_node::keyshare::{Keyshare, test_utils::generate_dummy_keyshare};
use near_account_id::AccountId;
use near_mpc_contract_interface::{
    client::MpcContractHandle,
    types::{DestinationNodeInfo, Ed25519PublicKey, EpochId, Keyset, ParticipantInfo},
};
use rand::{SeedableRng as _, rngs::StdRng};
use tokio::sync::{Mutex, Notify};

use crate::ports::{KeyShareRepository, P2PClient};

/// Long enough that no passing test can hit it
pub const TEST_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Waited out only under a paused clock
pub const TEST_RETRY_DELAY: Duration = Duration::from_mins(1);

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

pub fn mpc_contract<V>(viewer: V) -> MpcContractHandle<V> {
    MpcContractHandle::new(viewer, "v1.signer".parse().unwrap())
}

pub fn operator_account_id() -> AccountId {
    "operator.near".parse().unwrap()
}

pub fn participant_info(tls_public_key: Ed25519PublicKey) -> ParticipantInfo {
    ParticipantInfo {
        url: "http://127.0.0.1:3000".try_into().unwrap(),
        tls_public_key,
    }
}

pub fn migration_destination(tls_public_key: Ed25519PublicKey) -> DestinationNodeInfo {
    DestinationNodeInfo {
        signer_account_pk: Ed25519PublicKey::from([1; 32]),
        destination_node_info: participant_info(tls_public_key),
    }
}

pub struct FakeP2PClient {
    get_keyshares_calls: AtomicUsize,
    put_keyshares_calls: AtomicUsize,
    pub fetched: Arc<Notify>,
    /// Domains the node holds, or all domains of the requested keyset when `None`.
    held_domain_ids: Option<Vec<u64>>,
    fail: bool,
    hang: bool,
}

impl FakeP2PClient {
    pub fn new() -> Self {
        Self {
            get_keyshares_calls: AtomicUsize::new(0),
            put_keyshares_calls: AtomicUsize::new(0),
            fetched: Arc::new(Notify::new()),
            held_domain_ids: None,
            fail: false,
            hang: false,
        }
    }

    pub fn holding_domains(domain_ids: &[u64]) -> Self {
        Self {
            held_domain_ids: Some(domain_ids.to_vec()),
            ..Self::new()
        }
    }

    pub fn failing() -> Self {
        Self {
            fail: true,
            ..Self::new()
        }
    }

    /// Accepts the fetch and never answers it.
    pub fn hanging() -> Self {
        Self {
            hang: true,
            ..Self::new()
        }
    }

    pub fn get_keyshares_calls(&self) -> usize {
        self.get_keyshares_calls.load(Ordering::SeqCst)
    }

    pub fn put_keyshares_calls(&self) -> usize {
        self.put_keyshares_calls.load(Ordering::SeqCst)
    }
}

impl P2PClient for FakeP2PClient {
    type Error = anyhow::Error;

    async fn get_keyshares(&self, keyset: &Keyset) -> Result<Vec<Keyshare>, Self::Error> {
        self.get_keyshares_calls.fetch_add(1, Ordering::SeqCst);
        self.fetched.notify_one();
        if self.hang {
            std::future::pending::<()>().await;
        }
        if self.fail {
            anyhow::bail!("mpc node is unreachable");
        }
        let domain_ids = self.held_domain_ids.clone().unwrap_or_else(|| {
            keyset
                .domains
                .iter()
                .map(|domain| domain.domain_id.0)
                .collect()
        });
        Ok(keyshares_for(keyset.epoch_id.get(), &domain_ids))
    }

    async fn put_keyshares(&self, _keyshares: &[Keyshare]) -> Result<(), Self::Error> {
        self.put_keyshares_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

pub struct FakeKeyshareStorage {
    keyshares: Mutex<Vec<Keyshare>>,
    fail_load_after_store: bool,
    pub stored: Arc<AtomicUsize>,
    pub stored_notify: Arc<Notify>,
}

impl FakeKeyshareStorage {
    pub fn empty() -> Self {
        Self::with_keyshares(vec![])
    }

    pub fn with_keyshares(keyshares: Vec<Keyshare>) -> Self {
        Self {
            keyshares: Mutex::new(keyshares),
            fail_load_after_store: false,
            stored: Arc::new(AtomicUsize::new(0)),
            stored_notify: Arc::new(Notify::new()),
        }
    }

    pub fn failing_load_after_store() -> Self {
        Self {
            fail_load_after_store: true,
            ..Self::empty()
        }
    }
}

impl KeyShareRepository for FakeKeyshareStorage {
    type Error = anyhow::Error;

    async fn store_keyshares(&self, keyshares: &[Keyshare]) -> Result<(), Self::Error> {
        *self.keyshares.lock().await = keyshares.to_vec();
        self.stored.fetch_add(1, Ordering::SeqCst);
        // `notify_one` stores a permit, so a waiter that registers late still observes it.
        self.stored_notify.notify_one();
        Ok(())
    }

    async fn load_keyshares(&self) -> Result<Vec<Keyshare>, Self::Error> {
        if self.fail_load_after_store && self.stored.load(Ordering::SeqCst) > 0 {
            anyhow::bail!("storage is unreadable");
        }
        Ok(self.keyshares.lock().await.clone())
    }
}

pub fn keyshares_for(epoch_id: u64, domain_ids: &[u64]) -> Vec<Keyshare> {
    let mut rng = StdRng::seed_from_u64(42);
    domain_ids
        .iter()
        .map(|domain_id| generate_dummy_keyshare(epoch_id, *domain_id, 1, &mut rng))
        .collect()
}
