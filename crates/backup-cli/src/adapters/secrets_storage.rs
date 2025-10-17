use std::{path::Path, sync::Arc};

use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
};

use crate::{ports::SecretsRepository, types};

pub struct SharedJsonSecretsStorage<D>(Arc<Mutex<JsonSecretsStorage<D>>>);

const SECRETS_FILE_NAME: &str = "secrets.json";

impl SharedJsonSecretsStorage<File> {
    pub async fn open_write(storage_path: &Path) -> Self {
        if !storage_path.exists() {
            std::fs::create_dir_all(storage_path).expect("Could not create dir: {err}");
        }
        let file_path = storage_path.join(SECRETS_FILE_NAME);
        Self(Arc::new(Mutex::new(
            JsonSecretsStorage::<File>::open_write(file_path.as_path()).await,
        )))
    }

    pub async fn open_read(storage_path: &Path) -> Self {
        let file_path = storage_path.join(SECRETS_FILE_NAME);
        Self(Arc::new(Mutex::new(
            JsonSecretsStorage::<File>::open_read(file_path.as_path()).await,
        )))
    }
}

pub struct JsonSecretsStorage<D> {
    destination: D,
}

impl JsonSecretsStorage<File> {
    pub async fn open_write(storage_path: &Path) -> Self {
        let destination = File::create_new(storage_path)
            .await
            .expect("Error creating file");

        Self { destination }
    }

    pub async fn open_read(storage_path: &Path) -> Self {
        let destination = File::open(storage_path).await.expect("Error opening file");

        Self { destination }
    }
}

impl<W> JsonSecretsStorage<W>
where
    W: AsyncWrite + Unpin + AsyncSeek,
{
    pub async fn store_secrets(&mut self, secrets: &types::PersistentSecrets) {
        let encoded_secrets =
            serde_json::to_vec(&secrets).expect("Could not convert secrets to vec");
        self.destination
            .seek(std::io::SeekFrom::Start(0))
            .await
            .expect("Could not seek to start");
        self.destination
            .write_all(&encoded_secrets)
            .await
            .expect("Could not write to destination");
    }
}

impl<R> JsonSecretsStorage<R>
where
    R: AsyncRead + Unpin + AsyncSeek,
{
    pub async fn load_secrets(&mut self) -> types::PersistentSecrets {
        let mut buffer = Vec::new();
        self.destination
            .seek(std::io::SeekFrom::Start(0))
            .await
            .expect("Could not seek to start");
        self.destination
            .read_to_end(&mut buffer)
            .await
            .expect("Could not read destination");
        serde_json::from_slice(&buffer).expect("Could not read secrets from json")
    }
}

impl<D> SecretsRepository for SharedJsonSecretsStorage<D>
where
    D: AsyncRead + Unpin + AsyncSeek,
    D: AsyncWrite + Unpin + AsyncSeek,
    D: Send,
{
    type Error = String;

    async fn store_secrets(&self, secrets: &types::PersistentSecrets) -> Result<(), Self::Error> {
        self.0.lock().await.store_secrets(secrets).await;

        Ok(())
    }

    async fn load_secrets(&self) -> Result<types::PersistentSecrets, Self::Error> {
        Ok(self.0.lock().await.load_secrets().await)
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use std::io::Cursor;

    use rand::rngs::OsRng;

    use super::*;

    impl SharedJsonSecretsStorage<Cursor<Vec<u8>>> {
        pub async fn open_write(vector_storage: Vec<u8>) -> Self {
            Self(Arc::new(Mutex::new(
                JsonSecretsStorage::<Cursor<Vec<u8>>> {
                    destination: Cursor::new(vector_storage),
                },
            )))
        }

        pub async fn open_read(vector_storage: Vec<u8>) -> Self {
            Self(Arc::new(Mutex::new(
                JsonSecretsStorage::<Cursor<Vec<u8>>> {
                    destination: Cursor::new(vector_storage),
                },
            )))
        }
    }

    #[tokio::test]
    async fn json_secrets_storage__should_be_able_to_load_stored_secrets() {
        // Given
        let test_secrets = dummy_persistent_secrets();
        let secrets_storage = shared_vector_storage().await;

        // When
        secrets_storage
            .store_secrets(&test_secrets)
            .await
            .expect("should work");

        let loaded = secrets_storage.load_secrets().await.expect("should work");

        // Then
        assert_eq!(test_secrets, loaded);
    }

    async fn shared_vector_storage() -> SharedJsonSecretsStorage<Cursor<Vec<u8>>> {
        SharedJsonSecretsStorage::<Cursor<Vec<u8>>>::open_write(Vec::new()).await
    }

    fn dummy_persistent_secrets() -> types::PersistentSecrets {
        types::PersistentSecrets::generate(&mut OsRng)
    }
}
