use std::path::Path;

use ed25519_dalek::VerifyingKey;

use crate::{
    ports::{ContractInterface, KeyShareRepository, P2PClient, SecretsRepository},
    types::{self, PersistentSecrets},
};

pub struct LocalSecretsStorage {}

impl LocalSecretsStorage {
    const SECRETS_FILE_NAME: &'static str = "secrets.json";
}

impl SecretsRepository for LocalSecretsStorage {
    type Error = String;

    async fn store_secrets(
        &self,
        home_dir: &Path,
        secrets: &types::PersistentSecrets,
    ) -> Result<(), Self::Error> {
        if !home_dir.exists() {
            std::fs::create_dir_all(home_dir)
                .map_err(|err| format!("Could not create dir: {err}"))?;
        }
        let path = home_dir.join(Self::SECRETS_FILE_NAME);
        if path.exists() {
            return Err("secrets.json already exists. Refusing to overwrite.".to_string());
        }
        std::fs::write(
            &path,
            serde_json::to_vec(&secrets)
                .map_err(|err| format!("Could not convert secrets to json: {err}"))?,
        )
        .map_err(|err| format!("Could not write secrets file: {err}"))?;
        Ok(())
    }

    async fn load_secrets(&self, home_dir: &Path) -> Result<types::PersistentSecrets, Self::Error> {
        let file_path = home_dir.join(Self::SECRETS_FILE_NAME);
        if file_path.exists() {
            let str = std::fs::read_to_string(&file_path)
                .map_err(|err| format!("Could not read file: {err}"))?;
            let secrets: PersistentSecrets = serde_json::from_str(&str)
                .map_err(|err| format!("Could not get secrets from json: {err}"))?;
            Ok(secrets)
        } else {
            Err(format!("File not found: {file_path:?}"))
        }
    }
}

pub struct DummyKeyshareStorage {}

impl KeyShareRepository for DummyKeyshareStorage {
    type Error = String;

    async fn store_key_shares(&self, _key_shares: &types::KeyShares) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn load_key_shares(&self) -> Result<types::KeyShares, Self::Error> {
        Ok(types::KeyShares {})
    }
}

pub struct DummyP2PClient {}

impl P2PClient for DummyP2PClient {
    type Error = String;

    async fn get_key_shares(&self) -> Result<types::KeyShares, Self::Error> {
        Ok(types::KeyShares {})
    }

    async fn put_key_shares(&self, _key_shares: &types::KeyShares) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct DummyContractInterface {}

impl ContractInterface for DummyContractInterface {
    type Error = String;

    async fn register_backup_data(&self, _public_key: &VerifyingKey) -> Result<(), Self::Error> {
        Ok(())
    }
}
