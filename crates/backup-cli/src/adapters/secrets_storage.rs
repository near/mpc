use std::{path::Path, sync::Arc};

use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
};

use crate::{ports::SecretsRepository, types};

const SECRETS_FILE_NAME: &str = "secrets.json";

pub struct SharedJsonSecretsStorage<D>(Arc<Mutex<JsonSecretsStorage<D>>>);

pub struct JsonSecretsStorage<D> {
    destination: D,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to open file: {0}")]
    OpenFile(tokio::io::Error),

    #[error("could not seek from start: {0}")]
    SeekFromStart(tokio::io::Error),

    #[error("could not write to file: {0}")]
    Write(tokio::io::Error),

    #[error("could not read from file: {0}")]
    Read(tokio::io::Error),

    #[error("failed to serialize secrets")]
    JsonSerialization(serde_json::Error),

    #[error("failed to deserialize secrets")]
    JsonDeserialization(serde_json::Error),
}

impl SharedJsonSecretsStorage<File> {
    pub async fn open_write(storage_path: &Path) -> Result<Self, Error> {
        Ok(Self(Arc::new(Mutex::new(
            JsonSecretsStorage::<File>::open_write(storage_path).await?,
        ))))
    }

    pub async fn open_read(storage_path: &Path) -> Result<Self, Error> {
        Ok(Self(Arc::new(Mutex::new(
            JsonSecretsStorage::<File>::open_read(storage_path).await?,
        ))))
    }
}

impl JsonSecretsStorage<File> {
    pub async fn open_write(storage_path: impl AsRef<Path>) -> Result<Self, Error> {
        let file_path = storage_path.as_ref().join(SECRETS_FILE_NAME);
        let destination = File::options()
            .create(true)
            .write(true)
            .open(file_path)
            .await
            .map_err(Error::OpenFile)?;

        Ok(Self { destination })
    }

    pub async fn open_read(storage_path: impl AsRef<Path>) -> Result<Self, Error> {
        let file_path = storage_path.as_ref().join(SECRETS_FILE_NAME);
        let destination = File::open(file_path).await.map_err(Error::OpenFile)?;

        Ok(Self { destination })
    }
}

impl<W> JsonSecretsStorage<W>
where
    W: AsyncWrite + Unpin + AsyncSeek,
{
    pub async fn store_secrets(&mut self, secrets: &types::PersistentSecrets) -> Result<(), Error> {
        let encoded_secrets = serde_json::to_vec(&secrets).map_err(Error::JsonSerialization)?;

        self.destination
            .seek(std::io::SeekFrom::Start(0))
            .await
            .map_err(Error::SeekFromStart)?;
        self.destination
            .write_all(&encoded_secrets)
            .await
            .map_err(Error::Write)?;

        Ok(())
    }
}

impl<R> JsonSecretsStorage<R>
where
    R: AsyncRead + Unpin + AsyncSeek,
{
    pub async fn load_secrets(&mut self) -> Result<types::PersistentSecrets, Error> {
        let mut buffer = Vec::new();
        self.destination
            .seek(std::io::SeekFrom::Start(0))
            .await
            .map_err(Error::SeekFromStart)?;
        self.destination
            .read_to_end(&mut buffer)
            .await
            .map_err(Error::Read)?;

        serde_json::from_slice(&buffer).map_err(Error::JsonDeserialization)
    }
}

impl<D> SecretsRepository for SharedJsonSecretsStorage<D>
where
    D: AsyncRead + Unpin + AsyncSeek,
    D: AsyncWrite + Unpin + AsyncSeek,
    D: Send,
{
    type Error = Error;

    async fn store_secrets(&self, secrets: &types::PersistentSecrets) -> Result<(), Self::Error> {
        self.0.lock().await.store_secrets(secrets).await
    }

    async fn load_secrets(&self) -> Result<types::PersistentSecrets, Self::Error> {
        self.0.lock().await.load_secrets().await
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use std::io::Cursor;

    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    impl SharedJsonSecretsStorage<Cursor<Vec<u8>>> {
        pub async fn new(vector_storage: Vec<u8>) -> Self {
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
        let mut rng = StdRng::seed_from_u64(123);
        let test_secrets = types::PersistentSecrets::generate(&mut rng);
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
        SharedJsonSecretsStorage::<Cursor<Vec<u8>>>::new(Vec::new()).await
    }
}
