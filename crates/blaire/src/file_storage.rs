//! File-based storage backend for Blaire: one JSON file per kind of record.

use std::fs::{self, File};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use blaire_interface::NodeReport;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::traits::{StoreReports, TrackMpcNodes, WhitelistAccounts};
use crate::types::{
    AccountId, BlockHeight, MpcNode, ReportedData, Timestamp, TlsKey, UserId, WhitelistedAccount,
};

// Names of the files inside the data directory, one JSON array in each
const WHITELIST_FILE: &str = "whitelist.json";
const NODES_FILE: &str = "nodes.json";
const REPORTS_FILE: &str = "reports.json";

/// Stores Blaire's data as JSON files in one directory.
pub struct FileStore {
    dir: PathBuf,
    /// Held for the duration of every file operation.
    lock: Mutex<()>,
}

/// Things that can go wrong while reading or writing the files.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("file I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("stored data is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("store lock was poisoned by a panicking thread")]
    LockPoisoned,
}

impl FileStore {
    /// Opens the store in `dir`, creating the directory if it does not exist.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            lock: Mutex::new(()),
        })
    }

    // Full path of one of the files, e.g. <data_dir>/nodes.json
    fn path(&self, file: &str) -> PathBuf {
        self.dir.join(file)
    }

    // Waits until no other request is using the files, then holds the lock
    fn guard(&self) -> Result<MutexGuard<'_, ()>, StoreError> {
        self.lock.lock().map_err(|_| StoreError::LockPoisoned)
    }
}

impl WhitelistAccounts for FileStore {
    type Error = StoreError;

    fn add_account(
        &self,
        account_id: AccountId,
        added_by: UserId,
        added_at: Timestamp,
    ) -> Result<(), Self::Error> {
        let _guard = self.guard()?;
        let path = self.path(WHITELIST_FILE);
        let mut accounts: Vec<WhitelistedAccount> = read_json(&path)?;

        // An account is only stored once
        if accounts.iter().any(|account| account.account_id == account_id) {
            return Ok(()); // already whitelisted: keep the original entry
        }

        // Add the new account and write the updated list back
        accounts.push(WhitelistedAccount {
            account_id,
            added_by,
            added_at,
        });
        write_json_atomic(&path, &accounts)
    }

    fn remove_account(&self, account_id: &AccountId) -> Result<(), Self::Error> {
        let _guard = self.guard()?;
        let path = self.path(WHITELIST_FILE);
        let mut accounts: Vec<WhitelistedAccount> = read_json(&path)?;

        // Keep every account except the one to remove, then write the list back
        accounts.retain(|account| &account.account_id != account_id);
        write_json_atomic(&path, &accounts)
    }

    fn is_whitelisted(
        &self,
        account_id: &AccountId,
    ) -> Result<Option<WhitelistedAccount>, Self::Error> {
        let _guard = self.guard()?;
        let accounts: Vec<WhitelistedAccount> = read_json(&self.path(WHITELIST_FILE))?;
        Ok(accounts
            .into_iter()
            .find(|account| &account.account_id == account_id))
    }

    fn list_accounts(&self) -> Result<Vec<WhitelistedAccount>, Self::Error> {
        let _guard = self.guard()?;
        read_json(&self.path(WHITELIST_FILE))
    }
}

impl TrackMpcNodes for FileStore {
    type Error = StoreError;

    fn add_node(
        &self,
        account_id: AccountId,
        tls_key: TlsKey,
        block_height: BlockHeight,
        added_at: Timestamp,
    ) -> Result<(), Self::Error> {
        let _guard = self.guard()?;
        let path = self.path(NODES_FILE);
        let mut nodes: Vec<MpcNode> = read_json(&path)?;

        // A node is only stored once, so its first observed block height is kept
        if nodes.iter().any(|node| node.tls_key == tls_key) {
            return Ok(());
        }

        // Add the new node and write the updated list back
        nodes.push(MpcNode {
            account_id,
            tls_key,
            added_at,
            block_height,
        });
        write_json_atomic(&path, &nodes)
    }

    fn remove_node(&self, tls_key: &TlsKey) -> Result<(), Self::Error> {
        let _guard = self.guard()?;
        let path = self.path(NODES_FILE);
        let mut nodes: Vec<MpcNode> = read_json(&path)?;

        // Keep every node except the one to remove, then write the list back
        nodes.retain(|node| &node.tls_key != tls_key);
        write_json_atomic(&path, &nodes)
    }

    fn list_nodes(&self) -> Result<Vec<MpcNode>, Self::Error> {
        let _guard = self.guard()?;
        read_json(&self.path(NODES_FILE))
    }
}

impl StoreReports for FileStore {
    type Error = StoreError;

    fn add_report(
        &self,
        account_id: AccountId,
        tls_key: TlsKey,
        node_report: NodeReport,
        received_at: Timestamp,
    ) -> Result<(), Self::Error> {
        let _guard = self.guard()?;
        let path = self.path(REPORTS_FILE);
        let mut reports: Vec<ReportedData> = read_json(&path)?;

        // Every report is kept, so the history of a node's config is preserved
        reports.push(ReportedData {
            account_id,
            tls_key,
            node_report,
            received_at,
        });
        write_json_atomic(&path, &reports)
    }

    fn latest_report(&self, tls_key: &TlsKey) -> Result<Option<ReportedData>, Self::Error> {
        let _guard = self.guard()?;
        let reports: Vec<ReportedData> = read_json(&self.path(REPORTS_FILE))?;

        // Search from the newest end: the first match is the latest report
        Ok(reports.into_iter().rev().find(|report| &report.tls_key == tls_key))
    }

    fn list_reports(
        &self,
        account_id: &AccountId,
        limit: u32,
    ) -> Result<Vec<ReportedData>, Self::Error> {
        let _guard = self.guard()?;
        let reports: Vec<ReportedData> = read_json(&self.path(REPORTS_FILE))?;

        // Newest first, only this account's reports, at most `limit` of them
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(reports
            .into_iter()
            .rev()
            .filter(|report| &report.account_id == account_id)
            .take(limit)
            .collect())
    }
}

// Reads a JSON array file and returns its records.
// A missing file counts as empty, because nothing has been stored yet.
fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>, StoreError> {
    // Read the whole file; if it does not exist yet, there are no records
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    // Turn the JSON array back into records
    Ok(serde_json::from_slice(&bytes)?)
}

// Replaces a JSON array file with the given records.
// Writes a temporary file first and renames it, so a crash never leaves a half-written file.
fn write_json_atomic<T: Serialize>(path: &Path, records: &[T]) -> Result<(), StoreError> {
    // Turn the records into indented, readable JSON
    let mut content = serde_json::to_vec_pretty(records)?;
    content.push(b'\n');

    // Write it to a temporary file next to the real one, and wait until it is on disk
    let tmp = path.with_extension("json.tmp");
    let mut file = File::create(&tmp)?;
    file.write_all(&content)?;
    file.sync_all()?;
    drop(file);

    // Swap the temporary file in place of the old one
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(name: &str) -> AccountId {
        name.parse().expect("valid account id")
    }

    #[test]
    fn whitelisted_account_survives_restart() {
        // Given
        let dir = tempfile::tempdir().expect("temp dir is created");
        let store = FileStore::open(dir.path()).expect("store opens");
        store
            .add_account(account("alice.near"), UserId(1), Timestamp(1_700_000_000))
            .expect("account is added");

        // When
        drop(store);
        let reopened = FileStore::open(dir.path()).expect("store reopens");

        // Then
        let accounts = reopened.list_accounts().expect("accounts are listed");
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].account_id, account("alice.near"));
    }

    #[test]
    fn removed_account_is_no_longer_whitelisted() {
        // Given
        let dir = tempfile::tempdir().expect("temp dir is created");
        let store = FileStore::open(dir.path()).expect("store opens");
        store
            .add_account(account("alice.near"), UserId(1), Timestamp(1_700_000_000))
            .expect("account is added");

        // When
        store
            .remove_account(&account("alice.near"))
            .expect("account is removed");

        // Then
        let found = store
            .is_whitelisted(&account("alice.near"))
            .expect("lookup works");
        assert_eq!(found, None);
    }
}
